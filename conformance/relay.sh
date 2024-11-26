#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

cd "${SCRIPT_DIR}/../"
cargo run -- -b 127.0.0.1:8008 conformance/relay.toml
