#!/usr/bin/env bash

cd ../../../
cargo run --bin polysig-meeting -- start -b 127.0.0.1:8008 conformance/signers/webassembly-cggmp/config.toml
