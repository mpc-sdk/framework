# Multi-party computation protocol

End-to-end encrypted relay service designed for MPC/TSS applications built using the [noise protocol][] and websockets for the transport layer.

The service facilitates secure communication between peers but it does not handle public key exchange nor meeting points.

For clients to use the relay service they must know the public key of the server and the public keys of all the participants for a session.

Creating a meeting point that shares the session identifier between participants to execute an MPC/TSS protocol is left up to the application. Typically, this can be achieved by encoding the session identifier in a URL and sharing the URL with all the participants.

## Features

### Protocols

* `cggmp`: Enable the CGGMP21 protocol using [synedrion](https://github.com/entropyxyz/synedrion).

### Signers

* `ecdsa`: Single-party signer compatible with Ethereum.
* `eddsa`: Single-party signer compatible with Solana.
* `schnorr`: Single-party signer compatible with Bitcoin Taproot (BIP-340).

## Server Installation

```
cargo install mpc-relay
```

## Documentation

* [protocol][] Message types and encoding
* [server][] Websocket server library
* [client][] Websocket client library
* [cli][] Command line interface for the server

The client implementation uses [web-sys][] for webassembly and [tokio-tungstenite][] for other platforms.

## Development

### Getting Started

You will need the [rust][] toolchain and a few other tools:

```
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

#### Native Platform

To run the tests using the native client:

```
cargo nextest run
```

#### Web Platform

To test the web client using webassembly, first start a test server (port 8008):

```
cargo make test-server
```

Now you can run the webassembly tests:

```
cargo make test-wasm
```

##### End-to-end tests

The webassembly tests cannot simulate key generation and signing as it is too computationally intensive for a single-threaded context and the integration tests would hit the browser script timeout before completion.

To run end to end tests for the web platform, first compile the webassembly bindings:

```
cargo make bindings
```

Then generate the test files:

```
cargo make gen-e2e
```

Start a server for the end-to-end tests:

```
cargo make e2e-server
```

Note we don't use the `test-server` task as the e2e tests use a configuration with different timeout settings.

Then start a dev server (port 9009) used to serve the HTML and Javascript:

```
cargo make dev-server
```

Running the test specs requires [playwright][], so first install the dependencies for the end-to-end tests and then the [playwright][] browsers:

```
cd integration/tests/e2e
npm install
npx playwright install
```

Then you should be able to run the end-to-end tests:

```
npm test
```

Or run headed to see the browsers, which can be useful for debugging:

```
npm run test-headed
```

Or use the [playwright][] UI:

```
npm run test-ui
```

If you need to debug the test specs you can also just open the pages manually in a browser, first open the initiator `/cggmp/p1.html` and then open the participant pages `/cggmp/p2.html` and `/cggmp/p3.html` on the `http://localhost:9009` development server.

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
