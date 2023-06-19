//! Webassembly bindings for the web platform.
#![deny(missing_docs)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod bindings;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use bindings::*;
