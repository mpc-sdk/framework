# MPC Relay

End-to-end encrypted relay service designed for MPC/TSS applications built using the [noise protocol][] and websockets for the transport layer.

The service facilitates secure communication between peers but it does not handle public key exchange nor meeting points.

For clients to use the relay service they must know the public key of the server and the public keys of all the participants for a session.

Creating a meeting point that shares the session identifier between participants to execute an MPC/TSS protocol is left up to the application. Typcially, this can be achieved by encoding the session identifier in a URL and sharing the URL with all the participants.

The client implementation uses [web-sys][] for webassembly and [tokio-tunsgtentite][] for other platforms.

## Getting Started

You will need the [rust][] toolchain and a few other tools:

```
cargo install cargo-make
cargo install wasm-pack
```

## Server

First generate a keypair:

```
cargo run -- generate-keypair server.pem
```

Then start the server:

```
cargo run -- server config.toml
```

## Documentation

```
cargo make doc
```

## Tests

Generate a server key for the test specs:

```
cargo run -- generate-keypair tests/test.pem
```

Afterwards you should be able to run the tests using the native client:

```
cargo make test
```

To test the web client using webassembly, first start a test server:

```
cargo run -- server -b 127.0.0.1:8008 tests/config.toml
```

Copy the server public key and update the `tests/wasm.rs` file with the server public key.

Now you can run the webassembly tests:

```
cargo make test-wasm
```

## License

MIT or Apache-2.0

[noise protocol]: https://noiseprotocol.org/
[rust]: https://www.rust-lang.org/
[web-sys]: https://docs.rs/web-sys/latest/web_sys/
[tokio-tungstenite]: https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/
