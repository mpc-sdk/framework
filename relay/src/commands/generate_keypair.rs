//! Generate a new keypair.
use anyhow::{bail, Result};
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};

use mpc_protocol::{encode_keypair, generate_keypair, hex};

/// Generate keypair and write to file.
pub async fn run(
    path: PathBuf,
    force: bool,
    public_key: Option<PathBuf>,
) -> Result<()> {
    if fs::try_exists(&path).await? && !force {
        bail!(
            "file {} already exists, use --force to overwrite",
            path.display()
        );
    }

    let keypair = generate_keypair()?;
    let pem = encode_keypair(&keypair);

    let mut file = fs::File::create(&path).await?;
    file.write_all(pem.as_bytes()).await?;
    file.flush().await?;

    println!("{}", hex::encode(keypair.public_key()));

    if let Some(public_key) = public_key {
        let public_key_hex = hex::encode(keypair.public_key());
        fs::write(public_key, public_key_hex.as_bytes()).await?;
    }

    Ok(())
}
