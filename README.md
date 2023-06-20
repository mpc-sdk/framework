# Multi-party computation protocol

End-to-end encrypted relay service designed for MPC/TSS applications built using the [noise protocol][] and websockets for the transport layer.

The service facilitates secure communication between peers but it does not handle public key exchange nor meeting points.

For clients to use the relay service they must know the public key of the server and the public keys of all the participants for a session.

Creating a meeting point that shares the session identifier between participants to execute an MPC/TSS protocol is left up to the application. Typically, this can be achieved by encoding the session identifier in a URL and sharing the URL with all the participants.

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
cargo run -- server config.toml
```

### Documentation

```
cargo make doc
```

### Tests

#### Server Key

Generate a server key for the test specs and print the public key:

```
cargo run -- generate-keypair tests/test.pem
```

Copy the hex-encoded public key into the file `tests/server_public_key.txt`.

#### Native Client

To run the tests using the native client:

```
cargo make test
```

#### Web Client

To test the web client using webassembly, first start a test server (port 8008):

```
cargo make test-server
```

Now you can run the webassembly tests:

```
cargo make test-wasm
```

## License

The driver crate is GPLv3 all other code is either MIT or Apache-2.0.

[noise protocol]: https://noiseprotocol.org/
[rust]: https://www.rust-lang.org/
[web-sys]: https://docs.rs/web-sys
[tokio-tungstenite]: https://docs.rs/tokio-tungstenite
[protocol]: https://docs.rs/mpc-protocol
[server]: https://docs.rs/mpc-relay-server
[client]: https://docs.rs/mpc-client
[cli]: https://docs.rs/mpc-relay
