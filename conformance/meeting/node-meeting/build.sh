#!/usr/bin/env bash

set -e

mkdir -p build

cd ../../../crates/bindings/node
# meeting functionality depends on at least one protocol
# being active
npm run build:frost-ed25519-debug

cp -f build/frost-ed25519/debug/* ../../../conformance/meeting/node-meeting/build/
