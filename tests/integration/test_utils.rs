use anyhow::Result;
use axum_server::Handle;

use std::{net::SocketAddr, thread};
use tokio::{fs, sync::oneshot};

use mpc_relay_protocol::{
    decode_keypair, generate_keypair, snow::Keypair,
};

use mpc_relay_client::{ClientOptions, EventLoop, NativeClient};

use mpc_relay_server::{RelayServer, ServerConfig};

const ADDR: &str = "127.0.0.1:7337";
const SERVER: &str = "ws://localhost:7337";

/// Get the public key for the test server.
pub async fn server_public_key() -> Result<Vec<u8>> {
    let contents = fs::read_to_string("tests/test.pem").await?;
    let keypair = decode_keypair(&contents)?;
    Ok(keypair.public)
}

pub fn init_tracing() {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .try_init();
}

/// Create new client connected to the mock server.
pub async fn new_client() -> Result<(NativeClient, EventLoop, Keypair)>
{
    let server_public_key = server_public_key().await?;
    let keypair = generate_keypair()?;
    let url = format!(
        "{}/?public_key={}",
        SERVER,
        hex::encode(&keypair.public)
    );
    let copy = Keypair {
        public: keypair.public.clone(),
        private: keypair.public.clone(),
    };
    let options = ClientOptions {
        keypair,
        server_public_key,
    };
    let (client, event_loop) =
        NativeClient::new(url, options).await?;
    Ok((client, event_loop, copy))
}

struct MockServer {
    handle: Handle,
}

impl MockServer {
    fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new(),
        })
    }

    async fn start(&self) -> Result<()> {
        let addr: SocketAddr = ADDR.parse::<SocketAddr>()?;
        tracing::info!("start mock server {:#?}", addr);
        let (config, keypair) =
            ServerConfig::load("tests/config.toml").await?;
        let server = RelayServer::new(config, keypair);
        server.start(addr, self.handle.clone()).await?;
        Ok(())
    }

    /// Run the mock server in a separate thread.
    fn spawn(
        tx: oneshot::Sender<SocketAddr>,
    ) -> Result<ShutdownHandle> {
        let server = MockServer::new()?;
        let listen_handle = server.handle.clone();
        let user_handle = server.handle.clone();

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                loop {
                    if let Some(addr) =
                        listen_handle.listening().await
                    {
                        tracing::info!(
                            "server has started {:#?}",
                            addr
                        );
                        tx.send(addr).expect(
                            "failed to send listening notification",
                        );
                        break;
                    }
                }
            });
        });

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                server.start().await.expect("failed to start server");
            });
        });

        Ok(ShutdownHandle(user_handle))
    }
}

/// Ensure the server is shutdown when the handle is dropped.
pub struct ShutdownHandle(Handle);

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        tracing::info!("shutdown mock server");
        self.0.shutdown();
    }
}

pub fn spawn(
) -> Result<(oneshot::Receiver<SocketAddr>, ShutdownHandle)> {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockServer::spawn(tx)?;
    Ok((rx, handle))
}
