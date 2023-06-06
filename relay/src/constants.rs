/// Noise protocol pattern.
pub const PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// Tag for PEM encoding of private key.
pub const PEM_PRIVATE: &str = "NOISE PRIVATE KEY";

/// Tag for PEM encoding of public key.
pub const PEM_PUBLIC: &str = "NOISE PUBLIC KEY";

pub(crate) const TAGLEN: usize = 16;
