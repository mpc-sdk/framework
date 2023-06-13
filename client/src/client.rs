#[doc(hidden)]
macro_rules! client_impl {
    () => {
        /// The public key for this client.
        pub fn public_key(&self) -> &[u8] {
            &self.options.keypair.public
        }

        /// Perform initial handshake with the server.
        pub async fn connect(&mut self) -> Result<()> {
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

            self.outbound_tx.send(request).await?;

            Ok(())
        }

        /// Handshake with a peer.
        ///
        /// Peer already exists error is returned if this
        /// client is already connecting to the peer.
        pub async fn connect_peer(
            &mut self,
            public_key: impl AsRef<[u8]>,
        ) -> Result<()> {
            let mut peers = self.peers.write().await;

            if peers.get(public_key.as_ref()).is_some() {
                return Err(Error::PeerAlreadyExists);
            }

            tracing::debug!(
                to = ?hex::encode(public_key.as_ref()),
                "peer handshake initiator"
            );

            let builder = Builder::new(PATTERN.parse()?);
            let handshake = builder
                .local_private_key(&self.options.keypair.private)
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

            self.outbound_tx.send(request).await?;

            Ok(())
        }

        /// Send a JSON message to a peer via the relay service.
        pub async fn send<S>(
            &mut self,
            public_key: impl AsRef<[u8]>,
            payload: &S,
            session_id: Option<SessionId>,
        ) -> Result<()>
        where
            S: Serialize + ?Sized,
        {
            self.relay(
                public_key,
                &serde_json::to_vec(payload)?,
                Encoding::Json,
                false,
                session_id,
            )
            .await
        }

        /// Send a binary message to a peer via the relay service.
        pub async fn send_blob(
            &mut self,
            public_key: impl AsRef<[u8]>,
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
                self.outbound_tx.send(request).await?;
                Ok(())
            } else {
                Err(Error::PeerNotFound(hex::encode(
                    public_key.as_ref().to_vec(),
                )))
            }
        }

        /// Create a new session.
        pub async fn new_session(
            &mut self,
            participant_keys: Vec<Vec<u8>>,
        ) -> Result<()> {
            let session = SessionRequest { participant_keys };
            let message = ServerMessage::NewSession(session);
            self.request(message).await
        }

        /// Register a peer connection in a session.
        pub async fn register_session_connection(
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
        pub async fn close_session(
            &mut self,
            session_id: SessionId,
        ) -> Result<()> {
            let message = ServerMessage::CloseSession(session_id);
            self.request(message).await
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
                    let inner =
                        encrypt_server_channel(server, payload, false)
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
                self.outbound_tx.send(request).await?;
                Ok(())
            } else {
                unreachable!()
            }
        }

        /// Broadcast a JSON message in the context of a session.
        pub async fn broadcast<S>(
            &mut self,
            session_id: &SessionId,
            recipient_public_keys: &[Vec<u8>],
            payload: &S,
        ) -> Result<()>
        where
            S: Serialize + ?Sized,
        {
            self.relay_broadcast(
                session_id,
                recipient_public_keys,
                &serde_json::to_vec(payload)?,
                Encoding::Json,
            )
            .await
        }

        /// Broadcast a binary message in the context of a session.
        pub async fn broadcast_blob(
            &mut self,
            session_id: &SessionId,
            recipient_public_keys: &[Vec<u8>],
            payload: Vec<u8>,
        ) -> Result<()> {
            self.relay_broadcast(
                session_id,
                recipient_public_keys,
                &payload,
                Encoding::Blob,
            )
            .await
        }

        async fn relay_broadcast(
            &mut self,
            session_id: &SessionId,
            recipient_public_keys: &[Vec<u8>],
            payload: &[u8],
            encoding: Encoding,
        ) -> Result<()> {
            for key in recipient_public_keys {
                self.relay(
                    key,
                    payload,
                    encoding,
                    true,
                    Some(*session_id),
                )
                .await?;
            }
            Ok(())
        }
    }
}

pub(crate) use client_impl;
