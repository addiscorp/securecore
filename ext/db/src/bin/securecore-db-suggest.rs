//! Suggests the `layer2.components` database entries a site's components need, from the
//! extension's audit lines in `log` mode (E4). Run the site in `log` mode, use it, then:
//!
//!   securecore-db-suggest --prefix wp_ php-fpm.log... > suggested.json
//!
//! For each component it proposes `tables` (the other tables it used, without the prefix),
//! `options` (the options it read or wrote by name) and `grants` (core's tables, `read` or
//! `write` by the statement). What the policy never opens (protected options written, protected
//! columns, the statement allowlist) is listed under `"refusedAlways"` instead: a suggestion is
//! for a person to approve, and those can't be approved.

use std::io::{BufRead, BufReader};

use securecore_db::suggest::{Suggestions, parse_line};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut prefix = String::from("wp_");
    let mut files = Vec::new();
    while let Some(a) = args.next() {
        if a == "--prefix" {
            prefix = args.next().unwrap_or_default();
        } else {
            files.push(a);
        }
    }
    let mut s = Suggestions::new(&prefix);
    let mut read = |r: Box<dyn BufRead>| {
        for line in r.lines().map_while(Result::ok) {
            if let Some(l) = parse_line(&line) {
                s.add(&l);
            }
        }
    };
    if files.is_empty() {
        read(Box::new(BufReader::new(std::io::stdin())));
    }
    for f in &files {
        match std::fs::File::open(f) {
            Ok(file) => read(Box::new(BufReader::new(file))),
            Err(e) => {
                eprintln!("securecore-db-suggest: {f}: {e}");
                std::process::exit(2);
            }
        }
    }
    println!("{}", s.to_json());
}
