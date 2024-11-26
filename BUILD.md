# Build

## Server Installation

```
cargo install polysig-server
```

## Getting Started

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

## Server

Start a server:

```
cargo run -- config.toml
```

## Documentation

```
cargo make doc
```

## Tests

To run the tests using the native client:

```
cargo make test
```

For webassembly and node binding tests see the README files in the conformance directory.

[rust]: https://www.rust-lang.org/
