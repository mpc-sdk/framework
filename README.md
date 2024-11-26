# Polysig

Polysig is a library for single-party and multisig use cases for ECDSA, Schnorr and Ed25519 signature schemes.

We refer to single-party implementations as *signers* and multisig as *protocols*; all of the multisig *protocols* are threshold signature schemes. Supported protocols are [FROST][] and [CGGMP21][].

Protocols communicate via an end-to-end encrypted relay server using the [noise protocol][] and websockets for the transport layer or if you already have a transport you can use the [driver][] crate directly.

The library includes bindings for Webassembly to be used in the browser and for Nodejs; for multisig protocols the client implementation uses [web-sys][] for webassembly and [tokio-tungstenite][] for other platforms.

| Signer or Protocol | Curve     | Feature              | Library                | WASM | Node |
|:-------------------|:----------|:---------------------|:-----------------------|:-----|:-----|
| ECDSA              | Secp256k1 | `ecdsa`              | [k256][]               | Yes  | Yes  |
| EdDSA              | Ed25519   | `eddsa`              | [ed25519-dalek][]      | Yes  | Yes  |
| Schnorr            | Secp256k1 | `schnorr`            | [k256][]               | Yes  | Yes  |
| CGGMP              | Secp256k1 | `cggmp`              | [synedrion][]          | Yes  | Yes  |
| FROST              | Ed25519   | `frost-ed25519`      | [frost-ed25519][]      | Yes  | Yes  |
| FROST Taproot      | Secp256k1 | `frost-secp256k1-tr` | [frost-secp256k1-tr][] | Yes  | Yes  |

Other feature flags are `full` to enable all features or all `protocols` and `signers`.

## Meeting Rooms

For protocols to be executed the participants need to exchange public key information. To facilitate this we provide the [meeting-server][] which allows for meeting rooms to be created and all participants to be notified once all public keys are available. The client library provides [high-level functions](https://docs.rs/polysig-client/latest/polysig_client/meeting/index.html) for creating and joining rooms; these functions are also exposed in the bindings.

The [meeting-server][] is intentionally distinct from the [relay-server][] so the relay server has no knowledge of the public key exchange.

There are two identifiers for meeting rooms the `MeetingId` and a `UserId` for each participant. The `UserId` is a 32-byte identifier which is typically generated using a hash (such as SHA256) of some unique information. The information could be the participant's email address or other unique identifier.

The creator of the meeting room submits all the user identifiers (including their own) and the server will assign slots and return a `MeetingId`.

The meeting room creator then needs to share the `MeetingId` and each participant's assigned `UserId` with each of the participants; typically this would be done in the form of a URL.

All participants must then join the meeting room using their assigned slot (usually via a URL link) and publish their public keys to the server. Each participant must share both the `public_key` which is the public key for the noise protocol and the `verifying_key` which is used to verify authenticity when exchanging protocol round messages.

Once all participants have joined the room the server will send a broadcast notification including all the participant identifiers and public keys.

Now the participants are ready to begin create and join a session context.

## Session Context

After exchanging public keys via a meeting room it's required to create a session context on the relay server for protocol execution. If you are using the high-level functions in [polysig-client](https://docs.rs/polysig-client) then sessions are automatically created and destroyed.

A session context groups participants in a protocol so that we can ensure only participants with access to the session identifier are communicating and also so that peers can negotiate their noise protocol encrypted channels. We distinguish between an ***initiator*** that starts a session and a ***participant*** who registers their connection in a session. The initiator is responsible for closing a session once the protocol completes; if a session is not closed, perhaps due to a network error the server will eventually delete the session once it has expired.

The session initiator creates a session by sending all the ***noise transport public keys*** (including their own) to the server and then each participant submits their ***noise transport public key*** to the server to register as a participant in the session. Once all participants have registered their public keys then the server will send a `SessionReady` event, once the `SessionReady` event has been received each party attempts to create the encrypted peer to peer channel. Once all the peers are connected on secure channels a `SessionActive` event is emitted and then the protocol can begin execution.

## Documentation

* [protocol][] Message types and encoding
* [driver][] Signers and protocol drivers
* [client][] Websocket client library
* [meeting-server][] Websocket meeting room server library
* [relay-server][] Websocket relay server library
* [cli][] Command line interface for the server

See [BUILD](/BUILD.md) for information on installing, building and testing the source.

## License

The server code is licensed under AGPL-3.0 and the client code is licensed as either MIT or Apache-2.0 except when the `cggmp` feature is enabled which triggers the AGPL-3.0 license via the [synedrion][] library.

[CGGMP21]: https://eprint.iacr.org/2021/060
[FROST]: https://datatracker.ietf.org/doc/rfc9591/
[noise protocol]: https://noiseprotocol.org/
[rust]: https://www.rust-lang.org/
[playwright]: https://playwright.dev
[web-sys]: https://docs.rs/web-sys
[tokio-tungstenite]: https://docs.rs/tokio-tungstenite
[protocol]: https://docs.rs/polysig-protocol
[driver]: https://docs.rs/polysig-driver
[client]: https://docs.rs/polysig-client
[relay-server]: https://docs.rs/polysig-relay-server
[meeting-server]: https://docs.rs/polysig-meeting-server
[cli]: https://docs.rs/polysig-server
[synedrion]: https://docs.rs/synedrion/
[k256]: https://docs.rs/k256/latest/k256/
[ed25519-dalek]: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/
[frost-ed25519]: https://docs.rs/frost-ed25519/
[frost-secp256k1-tr]: https://docs.rs/frost-secp256k1-tr/
