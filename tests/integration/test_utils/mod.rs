pub(crate) mod peer_channel;

#[cfg(
    not(all(target_arch = "wasm32", target_os = "unknown")),
)]
pub(crate) mod native;

#[cfg(
    all(target_arch = "wasm32", target_os = "unknown"),
)]
pub(crate) mod web;

#[cfg(
    not(all(target_arch = "wasm32", target_os = "unknown")),
)]
pub use native::*;

#[cfg(
    all(target_arch = "wasm32", target_os = "unknown"),
)]
pub use web::*;
