//! Layer 3 of SecureCore (addiscorp/securecore#53, E7): a plugin listed in `layer3.isolate` runs
//! in a clean child process, never in the php-fpm worker. This crate is the plain-Rust part,
//! unit-tested without PHP; the extension (`securecore-php`, `layer3.rs`) is the wiring.
//!
//! - [`options`]: which options the helper boots WordPress from (core's own, never a plugin's,
//!   never a secret; #47).
//! - [`wire`] (Linux): the control socket, the per-request socket and their messages.
//! - [`child`] (Linux): the child's sandbox (gelada) and rlimits.

pub mod options;

#[cfg(target_os = "linux")]
pub mod child;
#[cfg(target_os = "linux")]
pub mod wire;
