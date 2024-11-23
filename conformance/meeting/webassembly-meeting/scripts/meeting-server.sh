#!/usr/bin/env bash

set -e

cd ../../../
cargo run --bin polysig-meeting -- start -b 127.0.0.1:8008 conformance/meeting.toml
