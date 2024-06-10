use anyhow::Result;
use futures::{Stream, StreamExt};
use mpc_client::Transport;
use mpc_driver::k256::ecdsa::{SigningKey, VerifyingKey};
use mpc_driver::{SessionEventHandler, SessionHandler};
use mpc_protocol::SessionState;
use rand::rngs::OsRng;
use std::pin::Pin;

mod keygen;
mod threshold_sign;

pub use keygen::run_keygen;
pub use threshold_sign::run_threshold_sign;

pub fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| *signer.verifying_key())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

type SessionStream = Pin<
    Box<
        dyn Stream<
                Item = Result<mpc_client::Event, mpc_client::Error>,
            > + Send,
    >,
>;

/// Drive streams to prepare sessions.
pub async fn drive_stream_sessions(
    streams: Vec<SessionStream>,
    sessions: Vec<SessionHandler>,
) -> Result<Vec<(Transport, SessionState, SessionStream)>> {
    let mut jhs = Vec::new();
    for (mut stream, mut session) in streams.into_iter().zip(sessions)
    {
        let jh = tokio::task::spawn(async move {
            let mut state: Option<(
                Transport,
                SessionState,
                SessionStream,
            )> = None;
            while let Some(event) = stream.next().await {
                let event = event?;
                if let Some(session_state) =
                    session.handle_event(event).await?
                {
                    let transport = session.into_transport();
                    state = Some((transport, session_state, stream));
                    break;
                }
            }

            Ok::<_, anyhow::Error>(state)
        });

        jhs.push(jh);
    }

    let results = futures::future::try_join_all(jhs).await.unwrap();

    let mut states = Vec::new();
    for result in results {
        let result = result?;
        states.push(result.unwrap());
    }

    Ok(states)
}
