# Polysig

Polysig is a library for single-party and multisig use cases for ECDSA, Schnorr and Ed25519 signature schemes.

We refer to single-party implementations as *signers* and multisig as *protocols*; all of the multisig *protocols* are threshold signature schemes.

Protocols communicate via an end-to-end encrypted relay server using the [noise protocol][] and websockets for the transport layer or if you already have a transport you can use the [driver](/driver) crate directly.

The library includes bindings for Webassembly to be used in the browser and for Nodejs; for multisig protocols the client implementation uses [web-sys][] for webassembly and [tokio-tungstenite][] for other platforms.

## Features

### Protocols

* `cggmp`: Enable the CGGMP21 protocol using [synedrion](https://docs.rs/synedrion/).
* `frost-ed25519`: Enable the FROST Ed25519 protocol using  [frost-ed25519](https://docs.rs/frost-ed25519/).

### Signers

* `ecdsa`: Signer compatible with Ethereum using [k256](https://docs.rs/k256/latest/k256/).
* `eddsa`: Signer compatible with Solana using [ed25519](https://docs.rs/ed25519/latest/ed25519/) and [ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/).
* `schnorr`: Signer compatible with Bitcoin Taproot (BIP-340) using [k256](https://docs.rs/k256/latest/k256/).

## Bindings

### Webassembly

* [x] CGGMP
* [x] ECDSA
* [x] EdDSA
* [ ] FROST
* [x] Schnorr

### Node

* [x] CGGMP
* [x] ECDSA
* [x] EdDSA
* [ ] FROST
* [x] Schnorr

## Server Installation

```
cargo install mpc-relay
```

## Documentation

* [protocol][] Message types and encoding
* [server][] Websocket server library
* [client][] Websocket client library
* [cli][] Command line interface for the server

## Development

### Getting Started

You will need the [rust][] toolchain and a few other tools:

```
cargo install cargo-hack
cargo install cargo-make
cargo install cargo-nextest
cargo install wasm-pack
```

Minimum supported rust version (MSRV) is 1.68.1.

Run the `gen-keys` task to setup keypairs for the server and test specs:

```
cargo make gen-keys
```

### Server

Start a server:

```
cargo run -- start config.toml
```

### Documentation

```
cargo make doc
```

### Tests

To run the tests using the native client:

```
cargo make test
```

For webassembly and node binding tests see the README files in the conformance directory.

## License

The bindings and driver crates are released under the GPLv3 license and all other code is either MIT or Apache-2.0.

[noise protocol]: https://noiseprotocol.org/
[rust]: https://www.rust-lang.org/
[playwright]: https://playwright.dev
[web-sys]: https://docs.rs/web-sys
[tokio-tungstenite]: https://docs.rs/tokio-tungstenite
[protocol]: https://docs.rs/mpc-protocol
[server]: https://docs.rs/mpc-relay-server
[client]: https://docs.rs/mpc-client
[cli]: https://docs.rs/mpc-relay
