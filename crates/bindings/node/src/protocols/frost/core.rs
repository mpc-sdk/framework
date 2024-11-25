macro_rules! frost_impl {
    ($name:ident) => {
        /// FROST protocol.
        #[napi]
        pub struct $name {
            options: polysig_client::SessionOptions,
            key_share: ThresholdKeyShare,
        }

        #[napi]
        impl $name {
            /// Create a FROST protocol.
            #[napi(constructor)]
            pub fn new(
                options: SessionOptions,
                key_share: KeyShare,
            ) -> Result<$name> {
                let options: polysig_client::SessionOptions =
                    options.try_into().map_err(Error::new)?;
                let key_share: ThresholdKeyShare =
                    key_share.try_into().map_err(Error::new)?;
                Ok(Self { options, key_share })
            }

            /// Distributed key generation.
            #[napi]
            pub async fn dkg(
                options: SessionOptions,
                party: PartyOptions,
                signer: Vec<u8>,
            ) -> Result<KeyShare> {
                let options: polysig_client::SessionOptions =
                    options.try_into().map_err(Error::new)?;

                let party: ProtocolPartyOptions =
                    party.try_into().map_err(Error::new)?;

                let signer: SigningKey = signer
                    .as_slice()
                    .try_into()
                    .map_err(Error::new)?;
                let verifier = signer.verifying_key().clone();

                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(Error::new)?;
                let key_share = dkg(options, participant)
                    .await
                    .map_err(Error::new)?;

                let key_share: KeyShare =
                    key_share.try_into().map_err(Error::new)?;
                Ok(key_share)
            }

            /// Sign a message.
            #[napi]
            pub async fn sign(
                &self,
                party: PartyOptions,
                signer: Vec<u8>,
                identifiers: Vec<Identifier>,
                message: String,
            ) -> Result<Signature> {
                let options = self.options.clone();
                let party: ProtocolPartyOptions =
                    party.try_into().map_err(Error::new)?;
                let signer: SigningKey = signer
                    .as_slice()
                    .try_into()
                    .map_err(Error::new)?;
                let verifier = signer.verifying_key().clone();
                let participant =
                    Participant::new(signer, verifier, party)
                        .map_err(Error::new)?;

                let mut ids = Vec::with_capacity(identifiers.len());
                for id in identifiers {
                    ids.push(id.try_into()?);
                }

                let signature = sign(
                    options,
                    participant,
                    ids,
                    self.key_share.clone(),
                    message.as_bytes().to_vec(),
                )
                .await
                .map_err(Error::new)?;

                Ok(signature.try_into()?)
            }
        }
    };
}

pub(crate) use frost_impl;
