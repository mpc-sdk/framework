//! Compression helpers using zlib.

use crate::Result;
use flate2::{
    write::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use std::io::prelude::*;

/// Compress bytes.
pub fn deflate(packet: &[u8]) -> Result<Vec<u8>> {
    let mut encoder =
        ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(packet)?;
    Ok(encoder.finish()?)
}

/// Decompress bytes.
pub fn inflate(packet: &[u8]) -> Result<Vec<u8>> {
    let mut z = ZlibDecoder::new(Vec::new());
    z.write_all(packet)?;
    Ok(z.finish()?)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn compress_decompress() -> Result<()> {
        let packet = "Some message that we send out over the wire.";
        let compressed = deflate(packet.as_bytes())?;
        let decompressed = inflate(&compressed)?;
        assert_eq!(packet.as_bytes(), &decompressed);
        Ok(())
    }
}
