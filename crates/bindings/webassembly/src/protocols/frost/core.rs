macro_rules! frost_impl {
    ($name:ident) => {
        /// FROST protocol.
        #[wasm_bindgen]
        pub struct $name {
            options: polysig_client::SessionOptions,
            key_share: ThresholdKeyShare,
        }

        #[wasm_bindgen]
        impl $name {
            /// Create a FROST protocol.
            #[wasm_bindgen(constructor)]
            pub fn new(
                options: JsValue,
                key_share: JsValue,
            ) -> Result<$name, JsError> {
                let options: SessionOptions =
                    serde_wasm_bindgen::from_value(options)?;
                let key_share: KeyShare =
                    serde_wasm_bindgen::from_value(key_share)?;
                let key_share: ThresholdKeyShare =
                    (&key_share).try_into().map_err(JsError::from)?;
                Ok(Self { options, key_share })
            }

            /*
                /// Distributed key generation.
                pub async fn dkg(
                    options: SessionOptions,
                    party: PartyOptions,
                    signer: SigningKey,
                    identifiers: Vec<Identifier>,
                ) -> Result<KeyShare> {
                    let options: polysig_client::SessionOptions =
                        options.try_into().map_err(Error::new)?;

                    let party: ProtocolPartyOptions =
                        party.try_into().map_err(Error::new)?;

                    let signer: ProtocolSigningKey = signer.try_into()?;
                    let verifier = signer.verifying_key().clone();

                    let participant =
                        Participant::new(signer, verifier, party)
                            .map_err(Error::new)?;

                    let mut ids = Vec::with_capacity(identifiers.len());
                    for id in identifiers {
                        ids.push(id.try_into()?);
                    }

                    let key_share = dkg(options, participant, ids)
                        .await
                        .map_err(Error::new)?;

                    let key_share: KeyShare =
                        key_share.try_into().map_err(Error::new)?;
                    Ok(key_share)
                }

                /// Sign a message.
                pub async fn sign(
                    &self,
                    party: PartyOptions,
                    signer: SigningKey,
                    identifiers: Vec<Identifier>,
                    message: String,
                ) -> Result<Signature> {
                    let options = self.options.clone();
                    let party: ProtocolPartyOptions =
                        party.try_into().map_err(Error::new)?;
                    let signer: ProtocolSigningKey = signer.try_into()?;
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

            */
        }
    };
}

pub(crate) use frost_impl;
