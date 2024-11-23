#!/usr/bin/env bash

set -e

command -v wasm-pack "wasm-pack must be installed"

cd ../../../crates/bindings/webassembly
# meeting functionality depends on at least one protocol
# being active
wasm-pack build \
	--target web \
	--features cggmp,tracing

cp -rf ./pkg ../../../conformance/meeting/webassembly-meeting/public/
