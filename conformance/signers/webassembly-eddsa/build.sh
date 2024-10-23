#!/usr/bin/env bash

command -v wasm-pack "wasm-pack must be installed"

cd ../../../bindings/webassembly
# WARN: must use --no-opt for now otherwise we get
# WARN: a "failed to grow table" error in the wasm-bindgen bindings
wasm-pack build \
	--target web \
	--no-opt \
	--scope mpc-sdk \
	--features eddsa

cp -rf ./pkg ../../conformance/signers/webassembly-eddsa/
