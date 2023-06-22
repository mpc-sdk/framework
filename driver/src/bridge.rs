use futures::{select, FutureExt, StreamExt};
use mpc_client::{Event, EventStream, NetworkTransport, Transport};
use mpc_protocol::{SessionId, SessionState};

use crate::{Driver, Error, ProtocolDriver, Round, RoundBuffer};

/// Connects a network transport with a protocol driver.
pub(crate) struct Bridge<D: ProtocolDriver> {
    pub(crate) transport: Transport,
    pub(crate) buffer: RoundBuffer<D::Incoming>,
    pub(crate) driver: Option<D>,
    pub(crate) session: SessionState,
}

impl<D: ProtocolDriver> Bridge<D> {
    /// Handle event from the client event loop stream.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<D::Output>, D::Error> {
        if let Event::JsonMessage {
            message,
            session_id,
            ..
        } = event
        {
            if let Some(session_id) = &session_id {
                if session_id != &self.session.session_id {
                    return Err(
                        Box::new(Error::SessionIdMismatch).into()
                    );
                }
            } else {
                return Err(Box::new(Error::SessionIdRequired).into());
            }

            let message: D::Outgoing = message.deserialize()?;
            let round_number = message.round_number();
            let incoming: D::Incoming = message.into();
            self.buffer.add_message(round_number, incoming);

            if self.buffer.is_ready(round_number) {
                let messages = self.buffer.take(round_number);
                for message in messages {
                    self.driver
                        .as_mut()
                        .unwrap()
                        .handle_incoming(message)?;
                }

                // For single round drivers we mustn't call proceed again
                if self.buffer.len() == 1 {
                    let result =
                        self.driver.take().unwrap().finish()?;
                    return Ok(Some(result));
                }

                let messages =
                    self.driver.as_mut().unwrap().proceed()?;
                self.dispatch_round_messages(messages).await?;

                if round_number.get() as usize == self.buffer.len() {
                    let result =
                        self.driver.take().unwrap().finish()?;
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<(), D::Error> {
        let messages = self.driver.as_mut().unwrap().proceed()?;
        self.dispatch_round_messages(messages).await?;
        Ok(())
    }

    async fn dispatch_round_messages(
        &mut self,
        mut messages: Vec<D::Outgoing>,
    ) -> Result<(), D::Error> {
        let is_broadcast = messages.len() == 1
            && messages.get(0).as_ref().unwrap().is_broadcast();

        if is_broadcast {
            let message = messages.remove(0);
            let recipients =
                self.session.recipients(self.transport.public_key());

            self.transport
                .broadcast_json(
                    &self.session.session_id,
                    recipients.as_slice(),
                    &message,
                )
                .await?;
        } else {
            for message in messages {
                let party_number = message.receiver().unwrap();
                let peer_key =
                    self.session.peer_key(*party_number).unwrap();
                self.transport
                    .send_json(
                        peer_key,
                        &message,
                        Some(self.session.session_id),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

/// Wait for a driver to complete.
pub async fn wait_for_driver<D>(
    stream: &mut EventStream,
    mut driver: D,
) -> Result<(Transport, D::Output), D::Error>
where
    D: Driver + Into<Transport>,
{
    driver.execute().await?;

    #[allow(unused_assignments)]
    let mut output: Option<D::Output> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(result) =
                            driver.handle_event(event).await? {
                            output = Some(result);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((driver.into(), output.take().unwrap()))
}

/// Wait for a close event.
///
/// Calling close() on a transport internally sends
/// the message view the event loop so we still need
/// to drive the event loop after calling close.
pub async fn wait_for_close(
    stream: &mut EventStream,
) -> crate::Result<()> {
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Event::Close = event {
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok(())
}

/// Wait for a session finish event.
pub async fn wait_for_session_finish(
    stream: &mut EventStream,
    session_id: SessionId,
) -> crate::Result<()> {
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Event::SessionFinished(id)= event {
                            if session_id == id {
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok(())
}
