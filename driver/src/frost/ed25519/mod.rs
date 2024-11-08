//! Driver for the FROST Ed25519 protocol.\

mod key_gen;

pub use key_gen::KeyGenDriver;

type MessageOut = ();
