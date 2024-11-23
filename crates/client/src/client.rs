#[doc(hidden)]
macro_rules! client_impl {
    () => {
        /// Relay a buffer to a peer over the noise protocol channel.
        ///
        /// The peers must have already performed the noise protocol
        /// handshake.
        async fn relay(
            &mut self,
            public_key: impl AsRef<[u8]>,
            payload: &[u8],
            encoding: Encoding,
            broadcast: bool,
            session_id: Option<SessionId>,
        ) -> Result<()> {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(public_key.as_ref()) {
                let request = encrypt_peer_channel(
                    public_key, peer, payload, encoding, broadcast,
                    session_id,
                )
                .await?;

                self.outbound_tx
                    .send(InternalMessage::Request(request))?;
                Ok(())
            } else {
                Err(Error::PeerNotFound(hex::encode(
                    public_key.as_ref().to_vec(),
                )))
            }
        }

        /// Encrypt a request message and send over the encrypted
        /// server channel.
        async fn request(
            &mut self,
            message: ServerMessage,
        ) -> Result<()> {
            let envelope = {
                let mut server = self.server.write().await;
                if let Some(server) = server.as_mut() {
                    let payload = encode(&message).await?;
                    let inner = encrypt_server_channel(
                        server, &payload, false,
                    )
                    .await?;
                    Some(inner)
                } else {
                    None
                }
            };

            if let Some(envelope) = envelope {
                let request = RequestMessage::Opaque(
                    OpaqueMessage::ServerMessage(envelope),
                );
                self.outbound_tx
                    .send(InternalMessage::Request(request))?;
                Ok(())
            } else {
                unreachable!()
            }
        }

        /// Send a buffer.
        async fn send(&mut self, buffer: Vec<u8>) -> Result<()> {
            Ok(self
                .outbound_tx
                .send(InternalMessage::Buffer(buffer))?)
        }
    };
}

#[doc(hidden)]
macro_rules! client_transport_impl {
    ($kind:ty) => {

        #[async_trait::async_trait]
        impl crate::NetworkTransport for $kind {

            /// Public key for this client.
            fn public_key(&self) -> &[u8] {
                self.options.keypair.as_ref().unwrap().public_key()
            }

            /// Perform initial handshake with the server.
            async fn connect(&mut self) -> Result<()> {
                if self.options.is_encrypted() {
                    let request = {
                        let mut state = self.server.write().await;

                        let (len, payload) = match &mut *state {
                            Some(ProtocolState::Handshake(initiator)) => {
                                let mut request = vec![0u8; 1024];
                                let len =
                                    initiator.write_message(&[], &mut request)?;
                                (len, request)
                            }
                            _ => return Err(Error::NotHandshakeState),
                        };

                        RequestMessage::Transparent(
                            TransparentMessage::ServerHandshake(
                                HandshakeMessage::Initiator(len, payload),
                            ),
                        )
                    };

                    self.outbound_tx.send(InternalMessage::Request(request))?;
                }
                Ok(())
            }

            async fn is_connected(&self) -> bool {
                let state = self.server.read().await;
                matches!(&*state, Some(ProtocolState::Transport(_)))
            }

            /// Handshake with a peer.
            ///
            /// Peer already exists error is returned if this
            /// client is already connecting to the peer.
            async fn connect_peer(
                &mut self,
                public_key: &[u8],
            ) -> Result<()> {
                let mut peers = self.peers.write().await;

                if peers.get(public_key.as_ref()).is_some() {
                    return Err(Error::PeerAlreadyExists);
                    //return Ok(())
                }

                tracing::debug!(
                    to = ?hex::encode(public_key.as_ref()),
                    "peer handshake initiator"
                );

                let builder = Builder::new(self.options.params()?);
                let handshake = builder
                    .local_private_key(self.options.keypair.as_ref().unwrap().private_key())
                    .remote_public_key(public_key.as_ref())
                    .build_initiator()?;
                let peer_state =
                    ProtocolState::Handshake(Box::new(handshake));

                let state = peers
                    .entry(public_key.as_ref().to_vec())
                    .or_insert(peer_state);

                let (len, payload) = match state {
                    ProtocolState::Handshake(initiator) => {
                        let mut request = vec![0u8; 1024];
                        let len =
                            initiator.write_message(&[], &mut request)?;
                        (len, request)
                    }
                    _ => return Err(Error::NotHandshakeState),
                };
                drop(peers);

                let request = RequestMessage::Transparent(
                    TransparentMessage::PeerHandshake {
                        public_key: public_key.as_ref().to_vec(),
                        message: HandshakeMessage::Initiator(len, payload),
                    },
                );

                self.outbound_tx.send(InternalMessage::Request(request))?;

                Ok(())
            }

            /// Send a JSON message to a peer via the relay service.
            async fn send_json<S>(
                &mut self,
                public_key: &[u8],
                payload: &S,
                session_id: Option<SessionId>,
            ) -> Result<()>
            where
                S: Serialize + Send + Sync,
            {
                self.relay(
                    public_key,
                    &JsonMessage::serialize(payload)?,
                    Encoding::Json,
                    false,
                    session_id,
                )
                .await
            }

            /// Send a binary message to a peer via the relay service.
            async fn send_blob(
                &mut self,
                public_key: &[u8],
                payload: Vec<u8>,
                session_id: Option<SessionId>,
            ) -> Result<()> {
                self.relay(
                    public_key,
                    &payload,
                    Encoding::Blob,
                    false,
                    session_id,
                )
                .await
            }

            /// Create a new meeting point.
            async fn new_meeting(
                &mut self,
                owner_id: UserId,
                slots: HashSet<UserId>,
            ) -> Result<()> {
                let message = MeetingRequest::NewRoom {
                    owner_id,
                    slots,
                };
                let buffer = serde_json::to_vec(&message)?;
                self.send(buffer).await
            }

            /// Join a meeting point.
            async fn join_meeting(
                &mut self,
                meeting_id: MeetingId,
                user_id: UserId,
                data: PublicKeys,
            ) -> Result<()> {
                let message = MeetingRequest::JoinRoom {
                    meeting_id,
                    user_id,
                    data,
                };
                let buffer = serde_json::to_vec(&message)?;
                self.send(buffer).await
            }

            /// Create a new session.
            async fn new_session(
                &mut self,
                participant_keys: Vec<Vec<u8>>,
            ) -> Result<()> {
                let session = SessionRequest { participant_keys };
                let message = ServerMessage::NewSession(session);
                self.request(message).await
            }

            /// Register a peer connection in a session.
            async fn register_connection(
                &mut self,
                session_id: &SessionId,
                peer_key: &[u8],
            ) -> Result<()> {
                let message = ServerMessage::SessionConnection {
                    session_id: *session_id,
                    peer_key: peer_key.to_vec(),
                };
                self.request(message).await
            }

            /// Close a session.
            async fn close_session(
                &mut self,
                session_id: SessionId,
            ) -> Result<()> {
                let message = ServerMessage::CloseSession(session_id);
                self.request(message).await
            }

            #[cfg(not(target_arch="wasm32"))]
            async fn close(&self) -> Result<()> {
                self.outbound_tx.send(InternalMessage::Close)?;
                Ok(())
            }

            #[cfg(target_arch="wasm32")]
            async fn close(&self) -> Result<()> {
                // Remove event listener closures
                self.ws.set_onopen(None);
                self.ws.set_onmessage(None);
                self.ws.set_onerror(None);

                // Close the socket connection
                self.ws.close()?;

                // Must also dispatch the close event for the driver
                self.outbound_tx.send(InternalMessage::Close)?;

                Ok(())
            }
        }
    }
}

pub(crate) use client_impl;
pub(crate) use client_transport_impl;
