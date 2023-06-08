use anyhow::{bail, Result};
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};

use mpc_relay_protocol::{generate_keypair, encode_keypair};

/// Generate keypair and write to file.
pub async fn run(path: PathBuf, force: bool) -> Result<()> {
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

    Ok(())
}
