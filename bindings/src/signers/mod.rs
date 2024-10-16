#[cfg(all(
    feature = "ecdsa",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod ecdsa;

#[cfg(all(
    feature = "eddsa",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod eddsa;

#[cfg(all(
    feature = "schnorr",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod schnorr;
