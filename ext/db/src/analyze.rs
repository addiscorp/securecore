//! What one SQL text does, independent of who sends it: its statement type, the tables it reads
//! and writes, the protected columns it names, and the option names / meta keys its WHERE (or
//! its VALUES) pins it to. Computed once per distinct query text and cached ([`crate::Cache`]);
//! the per-component decision ([`crate::policy`]) is then a few set lookups.
//!
//! The checks that must hold however the parser reads the text run first, on the tokens:
//! MySQL executes `/*! … */` comments the parser skips, and a few refused statements
//! (PREPARE … FROM, HANDLER, DO, INTO OUTFILE) are not in sqlparser's MySQL grammar, so they are
//! refused by their leading keyword or tokens rather than left to "unparseable".

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, FromTable, ObjectName, ObjectType, OnInsert, Query, SelectItem, Set, SetExpr,
    Statement, TableFactor, TableObject, TableWithJoins, Value, Visit, Visitor, visit_expressions, visit_relations,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

/// The statement classes the allowlist knows. Anything else is [`Shape::Refused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// SELECT (no CTE, no INTO).
    Select,
    /// INSERT / REPLACE / UPDATE / DELETE.
    Write,
    /// SHOW / DESCRIBE / EXPLAIN: schema and plans, no row data.
    Meta,
    /// A session SET WordPress uses (NAMES, sql_mode, autocommit, …), never a variable.
    SessionSet,
    /// START TRANSACTION / BEGIN / COMMIT / ROLLBACK / SAVEPOINT / RELEASE SAVEPOINT.
    Transaction,
    /// CREATE / ALTER / DROP / TRUNCATE / RENAME TABLE, CREATE / DROP INDEX: allowed on tables the
    /// caller may write, never on core's for a component.
    Ddl,
    /// Refused for everyone, with the rule naming why.
    Refused(&'static str),
    /// Not parseable: refused for a component, allowed and logged for core.
    Unparseable,
}

/// A literal a WHERE (or VALUES / SET) pins a column to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pin {
    Exact(String),
    /// `LIKE 'prefix%'`: every name starting with this.
    Prefix(String),
}

/// The pins of one column (`option_name`, `meta_key`) in a statement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    /// The names the statement is limited to. Empty with `pinned == false` means unlimited.
    pub names: BTreeSet<Pin>,
    /// The statement is provably limited to `names` (a top-level AND of an `=`, `IN` or
    /// `LIKE 'x%'` on the column, or every VALUES row's literal). False when the column is
    /// unconstrained, OR-ed, or set from something that is not a literal.
    pub pinned: bool,
    /// The column is assigned (UPDATE … SET option_name = …, a renamed row): those names are in
    /// `names` too, and a non-literal assignment clears `pinned`.
    pub assigned: bool,
}

/// One statement, analysed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub shape: Shape,
    /// The leading keyword, lowercase (`select`, `insert`, `replace`, `prepare`, …): the audit
    /// line's statement type.
    pub keyword: String,
    /// Tables written (INSERT/UPDATE/DELETE targets, DDL names), as `[schema.]name`, lowercase.
    pub writes: BTreeSet<TableName>,
    /// Tables only read.
    pub reads: BTreeSet<TableName>,
    /// Column identifiers read anywhere in the statement (expressions, not assignment targets or
    /// INSERT column lists), lowercase, last part only.
    pub columns: BTreeSet<String>,
    /// A `*` (or `t.*`, or `TABLE t`) projection over these tables, read directly.
    pub wildcard: BTreeSet<TableName>,
    /// `option_name` pins.
    pub option_names: Pins,
    /// `meta_key` pins.
    pub meta_keys: Pins,
    /// How many statements the text holds (more than one is refused for a component).
    pub statements: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableName {
    pub schema: Option<String>,
    pub name: String,
}

impl std::fmt::Display for TableName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.schema {
            Some(s) => write!(f, "{s}.{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

impl Analysis {
    fn refused(keyword: String, rule: &'static str) -> Analysis {
        Analysis { shape: Shape::Refused(rule), ..Analysis::empty(keyword) }
    }

    fn empty(keyword: String) -> Analysis {
        Analysis {
            shape: Shape::Unparseable,
            keyword,
            writes: BTreeSet::new(),
            reads: BTreeSet::new(),
            columns: BTreeSet::new(),
            wildcard: BTreeSet::new(),
            option_names: Pins::default(),
            meta_keys: Pins::default(),
            statements: 1,
        }
    }

    /// Every table the statement names, written or read.
    pub fn tables(&self) -> impl Iterator<Item = &TableName> {
        self.writes.iter().chain(self.reads.iter())
    }
}

/// Statements refused by their leading keyword, whatever follows (several are not in the
/// parser's MySQL grammar, so they must not fall through to "unparseable", which core is allowed).
const REFUSED_LEADING: &[(&str, &str)] = &[
    ("PREPARE", "prepare"),
    ("EXECUTE", "prepare"),
    ("DEALLOCATE", "prepare"),
    ("HANDLER", "statement"),
    ("DO", "statement"),
    ("USE", "statement"),
    ("CALL", "statement"),
    ("LOAD", "server-file"),
    ("LOCK", "statement"),
    ("UNLOCK", "statement"),
    ("GRANT", "statement"),
    ("REVOKE", "statement"),
    ("KILL", "statement"),
    ("FLUSH", "statement"),
    ("PURGE", "statement"),
    ("RESET", "statement"),
    ("INSTALL", "statement"),
    ("UNINSTALL", "statement"),
    ("SHUTDOWN", "statement"),
    ("CHANGE", "statement"),
    ("XA", "statement"),
    ("SIGNAL", "statement"),
    ("RESIGNAL", "statement"),
    ("BINLOG", "statement"),
    ("CACHE", "statement"),
    ("CHECKSUM", "statement"),
    ("ANALYZE", "statement"),
    ("CHECK", "statement"),
    ("OPTIMIZE", "statement"),
    ("REPAIR", "statement"),
    ("WITH", "cte"),
];

/// Charsets whose bytes the parser (UTF-8) and MySQL read the same way. A multi-byte charset such
/// as GBK or SJIS can swallow a backslash and so move where a string ends.
const SAFE_CHARSETS: &[&str] = &["utf8mb4", "utf8", "utf8mb3", "latin1", "ascii", "binary"];

/// `sql_mode` flags that change how MySQL tokenizes (so the parser would read the text
/// differently from the server): `"…"` as an identifier, `\` not an escape.
const UNSAFE_SQL_MODES: &[&str] = &["ANSI_QUOTES", "ANSI", "NO_BACKSLASH_ESCAPES"];

pub fn safe_charset(name: &str) -> bool {
    let n = name.trim().trim_matches(['\'', '"', '`']).to_ascii_lowercase();
    SAFE_CHARSETS.contains(&n.as_str())
}

/// Analyses one query text.
pub fn analyze(sql: &str) -> Analysis {
    let dialect = MySqlDialect {};
    // MySQL runs `/*! … */`; sqlparser's MySQL tokenizer expands some of them and not others
    // (`/*!99999 …*/`, which the server may skip). Neither reading can be trusted to match the
    // server, so any executable comment is refused, read off the raw text.
    if executable_comment(sql) {
        return Analysis::refused(String::new(), "executable-comment");
    }
    let tokens = match Tokenizer::new(&dialect, sql).tokenize() {
        Ok(t) => t,
        Err(_) => return Analysis::empty(String::new()),
    };
    let keyword = tokens
        .iter()
        .find_map(|t| match t {
            Token::Word(w) => Some(w.value.to_ascii_lowercase()),
            Token::Whitespace(_) | Token::LParen => None,
            _ => Some(String::new()),
        })
        .unwrap_or_default();
    if let Some(rule) = token_rule(&tokens) {
        return Analysis::refused(keyword, rule);
    }
    if let Some((_, rule)) = REFUSED_LEADING.iter().find(|(k, _)| k.eq_ignore_ascii_case(&keyword)) {
        return Analysis::refused(keyword, rule);
    }
    if matches!(keyword.as_str(), "create" | "alter" | "drop") && stored_object(&tokens) {
        return Analysis::refused(keyword, "routine");
    }
    let statements = match Parser::new(&dialect).with_tokens(tokens).parse_statements() {
        Ok(s) => s,
        // A SET changes how the server reads every later query (charset, sql_mode); one the
        // parser can't read is refused for everyone, core's unparseable allowance included.
        Err(_) if keyword == "set" => return Analysis::refused(keyword, "statement"),
        Err(_) => return Analysis::empty(keyword),
    };
    if statements.is_empty() {
        return Analysis::empty(keyword);
    }
    // Each statement must pass on its own; the analysis is their union, the first refusal wins.
    let mut out = Analysis::empty(keyword.clone());
    out.statements = statements.len();
    let mut first = true;
    for stmt in &statements {
        let one = statement(stmt, &keyword);
        if first {
            out.shape = one.shape;
            first = false;
        } else if !matches!(out.shape, Shape::Refused(_)) && matches!(one.shape, Shape::Refused(_) | Shape::Unparseable) {
            out.shape = one.shape;
        }
        out.writes.extend(one.writes);
        out.reads.extend(one.reads);
        out.columns.extend(one.columns);
        out.wildcard.extend(one.wildcard);
        merge_pins(&mut out.option_names, one.option_names);
        merge_pins(&mut out.meta_keys, one.meta_keys);
    }
    out.reads.retain(|t| !out.writes.contains(t));
    out
}

fn merge_pins(into: &mut Pins, from: Pins) {
    if into.names.is_empty() && !into.pinned && !into.assigned {
        *into = from;
        return;
    }
    into.pinned = into.pinned && from.pinned;
    into.assigned |= from.assigned;
    into.names.extend(from.names);
}

/// Refusals read off the tokens, before (and whatever) the parser makes of them.
fn token_rule(tokens: &[Token]) -> Option<&'static str> {
    let words: Vec<(usize, String)> = tokens
        .iter()
        .enumerate()
        .filter_map(|(i, t)| match t {
            Token::Word(w) if w.quote_style.is_none() => Some((i, w.value.to_ascii_uppercase())),
            _ => None,
        })
        .collect();
    for t in tokens {
        // MySQL runs the text of `/*! … */` and `/*!50000 … */`; the parser drops it as a comment.
        if let Token::Whitespace(Whitespace::MultiLineComment(c)) = t
            && c.starts_with('!')
        {
            return Some("executable-comment");
        }
    }
    for (n, (i, w)) in words.iter().enumerate() {
        match w.as_str() {
            "LOAD_FILE" if matches!(next_significant(tokens, *i), Some(Token::LParen)) => return Some("server-file"),
            "INTO" if words.get(n + 1).is_some_and(|(_, x)| x == "OUTFILE" || x == "DUMPFILE") => return Some("server-file"),
            _ => {}
        }
    }
    None
}

/// Whether `sql` holds a `/*!` comment outside a quoted string or identifier, read the way MySQL
/// reads it: `'…'` and `"…"` with backslash escapes and doubled quotes, `` `…` `` with doubled
/// backticks, and `-- ` / `#` line comments (which hide what follows to the end of the line).
pub fn executable_comment(sql: &str) -> bool {
    let b = sql.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < b.len() {
                    if q != b'`' && b[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if b[i] == q {
                        if b.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'-' if b.get(i + 1) == Some(&b'-') && b.get(i + 2).is_none_or(|c| c.is_ascii_whitespace()) => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                if b.get(i + 2) == Some(&b'!') {
                    return true;
                }
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    false
}

/// CREATE / ALTER / DROP of a stored object rather than a table or index: the object keyword
/// comes before the name (after OR REPLACE, ALGORITHM=, DEFINER=, SQL SECURITY, AGGREGATE, …).
fn stored_object(tokens: &[Token]) -> bool {
    const OBJECTS: &[&str] = &["VIEW", "FUNCTION", "PROCEDURE", "TRIGGER", "EVENT", "SERVER", "USER", "ROLE", "DATABASE", "SCHEMA", "TABLESPACE", "LOGFILE"];
    tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) if w.quote_style.is_none() => Some(w.value.to_ascii_uppercase()),
            _ => None,
        })
        .take_while(|w| w != "TABLE" && w != "INDEX" && w != "AS")
        .take(12)
        .any(|w| OBJECTS.contains(&w.as_str()))
}

fn next_significant(tokens: &[Token], i: usize) -> Option<&Token> {
    tokens[i + 1..].iter().find(|t| !matches!(t, Token::Whitespace(_)))
}

fn table_name(name: &ObjectName) -> Option<TableName> {
    let parts: Vec<String> = name.0.iter().map(|p| p.as_ident().map(|i| i.value.to_ascii_lowercase())).collect::<Option<_>>()?;
    match parts.as_slice() {
        [t] => Some(TableName { schema: None, name: t.clone() }),
        [s, t] => Some(TableName { schema: Some(s.clone()), name: t.clone() }),
        _ => None,
    }
}

/// Every relation under a node, by name (`None` for a name the policy can't read: refuse).
fn relations<V: Visit>(v: &V) -> Vec<Option<TableName>> {
    let mut out = Vec::new();
    let _ = visit_relations(v, |r| {
        out.push(table_name(r));
        ControlFlow::<()>::Continue(())
    });
    out
}

fn statement(stmt: &Statement, keyword: &str) -> Analysis {
    let mut a = Analysis::empty(keyword.to_owned());
    let mut writes: Vec<Option<TableName>> = Vec::new();
    a.shape = match stmt {
        Statement::Query(q) => query_shape(q),
        Statement::Insert(ins) => {
            if let TableObject::TableName(n) = &ins.table {
                writes.push(table_name(n));
            } else {
                return Analysis::refused(keyword.to_owned(), "statement");
            }
            a.option_names = insert_pins(ins, "option_name");
            a.meta_keys = insert_pins(ins, "meta_key");
            Shape::Write
        }
        Statement::Update(up) => {
            writes.extend(relations(&up.table));
            a.option_names = where_pins(up.selection.as_ref(), "option_name");
            a.meta_keys = where_pins(up.selection.as_ref(), "meta_key");
            assigned(&mut a.option_names, &up.assignments, "option_name", false);
            assigned(&mut a.meta_keys, &up.assignments, "meta_key", false);
            Shape::Write
        }
        Statement::Delete(del) => {
            if del.tables.is_empty() {
                let from = match &del.from {
                    FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
                };
                writes.extend(from.iter().flat_map(relations));
            } else {
                writes.extend(del.tables.iter().map(table_name));
            }
            a.option_names = where_pins(del.selection.as_ref(), "option_name");
            a.meta_keys = where_pins(del.selection.as_ref(), "meta_key");
            Shape::Write
        }
        Statement::ShowColumns { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowCollation { .. }
        | Statement::ShowCharset(_)
        | Statement::ExplainTable { .. } => Shape::Meta,
        Statement::Explain { statement, analyze, .. } => {
            // EXPLAIN ANALYZE runs the statement: hold it to what the inner statement may do.
            if *analyze {
                let inner = self::statement(statement, keyword);
                return Analysis { keyword: keyword.to_owned(), ..inner };
            }
            Shape::Meta
        }
        Statement::Set(set) => set_shape(set),
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => Shape::Transaction,
        Statement::CreateTable(ct) => {
            writes.push(table_name(&ct.name));
            Shape::Ddl
        }
        Statement::AlterTable(at) => {
            writes.push(table_name(&at.name));
            Shape::Ddl
        }
        Statement::CreateIndex(ci) => {
            writes.push(table_name(&ci.table_name));
            Shape::Ddl
        }
        Statement::Drop { object_type: ObjectType::Table, names, .. } => {
            writes.extend(names.iter().map(table_name));
            Shape::Ddl
        }
        Statement::Truncate(t) => {
            writes.extend(t.table_names.iter().map(|n| table_name(&n.name)));
            Shape::Ddl
        }
        Statement::RenameTable(rs) => {
            for r in rs {
                writes.push(table_name(&r.old_name));
                writes.push(table_name(&r.new_name));
            }
            Shape::Ddl
        }
        Statement::CreateView { .. }
        | Statement::CreateFunction(_)
        | Statement::CreateProcedure { .. }
        | Statement::CreateTrigger(_) => Shape::Refused("routine"),
        _ => Shape::Refused("statement"),
    };
    if writes.iter().any(Option::is_none) {
        return Analysis::refused(keyword.to_owned(), "table-name");
    }
    a.writes = writes.into_iter().flatten().collect();
    let all = relations(stmt);
    if all.iter().any(Option::is_none) {
        return Analysis::refused(keyword.to_owned(), "table-name");
    }
    a.reads = all.into_iter().flatten().filter(|t| !a.writes.contains(t)).collect();
    let _ = visit_expressions(stmt, |e| {
        match e {
            Expr::Identifier(i) => {
                a.columns.insert(i.value.to_ascii_lowercase());
            }
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last() {
                    a.columns.insert(last.value.to_ascii_lowercase());
                }
            }
            _ => {}
        }
        ControlFlow::<()>::Continue(())
    });
    // JOIN … USING (col) and NATURAL JOIN compare columns by name without an expression.
    let mut natural = false;
    let _ = stmt.visit(&mut JoinColumns { columns: &mut a.columns, natural: &mut natural });
    if natural {
        a.columns.insert("*natural".into());
    }
    let mut w = Wildcards { out: &mut a.wildcard, opaque: false };
    let _ = stmt.visit(&mut w);
    if w.opaque {
        return Analysis::refused(keyword.to_owned(), "table-name");
    }
    // A SELECT pins options through its outermost WHERE.
    if let Statement::Query(q) = stmt
        && let SetExpr::Select(s) = q.body.as_ref()
    {
        a.option_names = where_pins(s.selection.as_ref(), "option_name");
        a.meta_keys = where_pins(s.selection.as_ref(), "meta_key");
    }
    a
}

fn query_shape(q: &Query) -> Shape {
    if q.with.is_some() {
        return Shape::Refused("cte");
    }
    let mut into = false;
    let _ = q.visit(&mut SelectInto { found: &mut into });
    if into { Shape::Refused("select-into") } else { Shape::Select }
}

struct SelectInto<'a> {
    found: &'a mut bool,
}

impl Visitor for SelectInto<'_> {
    type Break = ();
    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        if let SetExpr::Select(s) = q.body.as_ref()
            && s.into.is_some()
        {
            *self.found = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// `*` / `t.*` / `TABLE t` projections, by the tables they read directly.
struct Wildcards<'a> {
    out: &'a mut BTreeSet<TableName>,
    opaque: bool,
}

impl Wildcards<'_> {
    fn body(&mut self, body: &SetExpr) {
        match body {
            SetExpr::Select(s) => {
                let star = s.projection.iter().any(|p| matches!(p, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)));
                if star {
                    for twj in &s.from {
                        self.direct(twj);
                    }
                }
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.body(left);
                self.body(right);
            }
            SetExpr::Table(t) => match &t.table_name {
                Some(n) => {
                    self.out.insert(TableName { schema: t.schema_name.as_ref().map(|s| s.to_ascii_lowercase()), name: n.to_ascii_lowercase() });
                }
                None => self.opaque = true,
            },
            _ => {}
        }
    }

    fn direct(&mut self, twj: &TableWithJoins) {
        for f in std::iter::once(&twj.relation).chain(twj.joins.iter().map(|j| &j.relation)) {
            if let TableFactor::Table { name, .. } = f {
                match table_name(name) {
                    Some(t) => {
                        self.out.insert(t);
                    }
                    None => self.opaque = true,
                }
            }
        }
    }
}

impl Visitor for Wildcards<'_> {
    type Break = ();
    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        self.body(&q.body);
        ControlFlow::Continue(())
    }
}

struct JoinColumns<'a> {
    columns: &'a mut BTreeSet<String>,
    natural: &'a mut bool,
}

impl Visitor for JoinColumns<'_> {
    type Break = ();
    fn pre_visit_table_factor(&mut self, _f: &TableFactor) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        if let SetExpr::Select(s) = q.body.as_ref() {
            for twj in &s.from {
                for j in &twj.joins {
                    let text = j.to_string().to_ascii_uppercase();
                    if text.contains("NATURAL") {
                        *self.natural = true;
                    }
                    if let Some(rest) = text.split("USING").nth(1) {
                        for c in rest.split(|ch: char| !(ch.is_alphanumeric() || ch == '_')).filter(|c| !c.is_empty()) {
                            self.columns.insert(c.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
        ControlFlow::Continue(())
    }
}

fn set_shape(set: &Set) -> Shape {
    // The text decides, so a variable can't hide behind a form the AST names differently.
    let text = set.to_string();
    if text.contains('@') {
        return Shape::Refused("user-variable");
    }
    let upper = text.to_ascii_uppercase();
    let mut words = upper.split_whitespace().skip(1);
    let first = words.next().unwrap_or("");
    match first {
        "GLOBAL" | "PERSIST" | "PERSIST_ONLY" | "PASSWORD" | "ROLE" | "DEFAULT" => return Shape::Refused("statement"),
        _ => {}
    }
    if let Set::SetNames { charset_name, .. } = set
        && !safe_charset(&charset_name.to_string())
    {
        return Shape::Refused("charset");
    }
    if let Set::SetNamesDefault {} = set {
        return Shape::Refused("charset");
    }
    if upper.contains("CHARACTER SET") || upper.contains("CHARSET") || upper.contains("CHARACTER_SET") || upper.contains("COLLATION") {
        let value = upper.rsplit(['=', ' ']).next().unwrap_or("");
        if !safe_charset(value) && !upper.starts_with("SET NAMES") {
            return Shape::Refused("charset");
        }
    }
    if upper.contains("SQL_MODE") {
        let Some((_, value)) = upper.split_once('=') else { return Shape::Refused("sql-mode") };
        let value = value.trim();
        let literal = (value.starts_with('\'') && value.ends_with('\'')) || (value.starts_with('"') && value.ends_with('"'));
        if !literal {
            return Shape::Refused("sql-mode");
        }
        let flags = value.trim_matches(['\'', '"']);
        if flags.split(',').map(str::trim).any(|f| UNSAFE_SQL_MODES.contains(&f)) {
            return Shape::Refused("sql-mode");
        }
    }
    Shape::SessionSet
}

fn column_is(e: &Expr, col: &str) -> bool {
    match e {
        Expr::Identifier(i) => i.value.eq_ignore_ascii_case(col),
        Expr::CompoundIdentifier(p) => p.last().is_some_and(|i| i.value.eq_ignore_ascii_case(col)),
        Expr::Nested(inner) => column_is(inner, col),
        _ => false,
    }
}

fn string_literal(e: &Expr) -> Option<String> {
    match e {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) => Some(s.clone()),
            _ => None,
        },
        Expr::Nested(inner) => string_literal(inner),
        _ => None,
    }
}

/// `LIKE 'abc%'` (an unescaped literal prefix then one trailing `%`), MySQL's `\_` and `\%` read
/// as the literal characters.
fn like_prefix(pattern: &str) -> Option<String> {
    let body = pattern.strip_suffix('%')?;
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '%' | '_' => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// The pins on `col` in a WHERE: only through a chain of top-level ANDs, so an OR can't widen it.
fn where_pins(selection: Option<&Expr>, col: &str) -> Pins {
    let mut pins = Pins::default();
    let Some(sel) = selection else { return pins };
    let mut conjuncts = Vec::new();
    flatten_and(sel, &mut conjuncts);
    for c in conjuncts {
        let mut found = BTreeSet::new();
        let ok = match c {
            Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
                let (l, r) = (left.as_ref(), right.as_ref());
                match (column_is(l, col), column_is(r, col)) {
                    (true, _) => string_literal(r).map(|s| found.insert(Pin::Exact(s))).is_some(),
                    (_, true) => string_literal(l).map(|s| found.insert(Pin::Exact(s))).is_some(),
                    _ => false,
                }
            }
            Expr::InList { expr, list, negated: false } if column_is(expr, col) => list
                .iter()
                .map(string_literal)
                .collect::<Option<Vec<_>>>()
                .map(|v| v.into_iter().for_each(|s| {
                    found.insert(Pin::Exact(s));
                }))
                .is_some(),
            Expr::Like { negated: false, any: false, expr, pattern, .. } if column_is(expr, col) => {
                string_literal(pattern).and_then(|p| like_prefix(&p)).map(|p| found.insert(Pin::Prefix(p))).is_some()
            }
            _ => false,
        };
        if ok && !found.is_empty() {
            // Several pins ANDed: the intersection is within any one of them; keep the first.
            if !pins.pinned {
                pins.names = found;
                pins.pinned = true;
            }
        }
    }
    pins
}

fn flatten_and<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::BinaryOp { left, op: BinaryOperator::And, right } => {
            flatten_and(left, out);
            flatten_and(right, out);
        }
        Expr::Nested(inner) => flatten_and(inner, out),
        other => out.push(other),
    }
}

/// UPDATE … SET <col> = …: the assigned value joins the names; anything but a literal (or, in
/// ON DUPLICATE KEY UPDATE, `VALUES(<col>)`) unpins the statement.
fn assigned(pins: &mut Pins, assignments: &[sqlparser::ast::Assignment], col: &str, upsert: bool) {
    for a in assignments {
        let targets: Vec<&ObjectName> = match &a.target {
            AssignmentTarget::ColumnName(n) => vec![n],
            AssignmentTarget::Tuple(ns) => ns.iter().collect(),
        };
        let hits = targets.iter().any(|n| n.0.last().and_then(|p| p.as_ident()).is_some_and(|i| i.value.eq_ignore_ascii_case(col)));
        if !hits {
            continue;
        }
        pins.assigned = true;
        if upsert && is_values_of(&a.value, col) {
            continue;
        }
        match string_literal(&a.value) {
            Some(s) => {
                pins.names.insert(Pin::Exact(s));
            }
            None => pins.pinned = false,
        }
    }
}

fn is_values_of(e: &Expr, col: &str) -> bool {
    let Expr::Function(f) = e else { return false };
    if !f.name.to_string().eq_ignore_ascii_case("values") {
        return false;
    }
    let text = f.args.to_string();
    text.trim_matches(['(', ')', '`', ' ']).eq_ignore_ascii_case(col)
}

/// INSERT (cols) VALUES (…), (…) / INSERT … SET col = …: every row's literal for `col`.
fn insert_pins(ins: &sqlparser::ast::Insert, col: &str) -> Pins {
    let mut pins = Pins::default();
    if let Some(i) = ins.columns.iter().position(|c| c.0.last().and_then(|p| p.as_ident()).is_some_and(|id| id.value.eq_ignore_ascii_case(col))) {
        let rows = ins.source.as_ref().and_then(|q| match q.body.as_ref() {
            SetExpr::Values(v) => Some(&v.rows),
            _ => None,
        });
        match rows {
            Some(rows) => {
                pins.pinned = true;
                for row in rows {
                    match row.get(i).and_then(string_literal) {
                        Some(s) => {
                            pins.names.insert(Pin::Exact(s));
                        }
                        None => pins.pinned = false,
                    }
                }
            }
            None => pins.pinned = false,
        }
        pins.assigned = true;
    } else if !ins.assignments.is_empty() {
        assigned(&mut pins, &ins.assignments, col, false);
        if pins.assigned && pins.names.is_empty() {
            pins.pinned = false;
        } else if pins.assigned {
            pins.pinned = true;
        }
    }
    if let Some(OnInsert::DuplicateKeyUpdate(up)) = &ins.on {
        let was = pins.pinned;
        assigned(&mut pins, up, col, true);
        pins.pinned &= was || !pins.assigned;
    }
    pins
}
