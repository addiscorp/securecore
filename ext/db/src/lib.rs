//! The layer-2 database policy (addiscorp/securecore#53, phase E4): every query PHP sends is
//! parsed with a real MySQL-dialect parser ([sqlparser-rs](https://crates.io/crates/sqlparser),
//! Apache DataFusion's) and decided for the component that sent it. A port of #49's PHP policy
//! (`plugin/sql-policy.php`, phpmyadmin/sql-parser) to Rust, with E4's per-component tables,
//! options and grants. Plain Rust, no PHP: the extension (`securecore-php`) supplies who is
//! calling and the site facts, and carries out the decision.
//!
//! [`analyze`] works out what a query text does (cached by text, [`Cache`]); [`policy`] decides
//! it for a caller.

pub mod analyze;
pub mod caller;
pub mod policy;
pub mod suggest;

use std::collections::HashMap;
use std::sync::Arc;

pub use analyze::{Analysis, Shape, analyze};
pub use policy::{Decision, Rules4, Site, Who, decide};

/// A bounded cache of analyses by query text, for one php-fpm worker. A front page repeats the
/// same few dozen query shapes, so nearly every lookup is a hit; a miss parses. Least recently
/// used entries go first. Texts longer than [`Cache::MAX_KEY`] are analysed but not kept (large
/// INSERTs are rarely repeated and would crowd the cache out).
#[derive(Debug)]
pub struct Cache {
    map: HashMap<String, (Arc<Analysis>, u64)>,
    capacity: usize,
    tick: u64,
    pub hits: u64,
    pub misses: u64,
}

impl Cache {
    pub const MAX_KEY: usize = 8192;

    pub fn new(capacity: usize) -> Cache {
        Cache { map: HashMap::with_capacity(capacity), capacity: capacity.max(1), tick: 0, hits: 0, misses: 0 }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&mut self, sql: &str) -> Arc<Analysis> {
        self.tick += 1;
        if let Some((a, used)) = self.map.get_mut(sql) {
            *used = self.tick;
            self.hits += 1;
            return Arc::clone(a);
        }
        self.misses += 1;
        let a = Arc::new(analyze(sql));
        if sql.len() <= Self::MAX_KEY {
            if self.map.len() >= self.capacity {
                self.evict();
            }
            self.map.insert(sql.to_owned(), (Arc::clone(&a), self.tick));
        }
        a
    }

    /// Drop the least recently used quarter (at least one), so eviction is amortised.
    fn evict(&mut self) {
        let mut ticks: Vec<u64> = self.map.values().map(|(_, t)| *t).collect();
        ticks.sort_unstable();
        let cut = ticks[(ticks.len() / 4).min(ticks.len() - 1)];
        self.map.retain(|_, (_, t)| *t > cut);
    }
}

#[cfg(test)]
mod tests;
