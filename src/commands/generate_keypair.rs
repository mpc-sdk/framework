use anyhow::{bail, Result};
use mpc_relay_server::keypair;
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};

/// Generate keypair and write to file.
pub async fn run(path: PathBuf, force: bool) -> Result<()> {
    if fs::try_exists(&path).await? && !force {
        bail!(
            "file {} already exists, use --force to overwrite",
            path.display()
        );
    }

    let keypair = keypair::generate_keypair()?;
    let pem = keypair::encode_keypair(&keypair);

    let mut file = fs::File::create(&path).await?;
    file.write_all(pem.as_bytes()).await?;
    file.flush().await?;

    Ok(())
}
