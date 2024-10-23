#!/usr/bin/env bash

command -v wasm-pack "wasm-pack must be installed"

cd ../../../bindings/webassembly
wasm-pack build \
	--target web \
	--features eddsa

cp -rf ./pkg ../../conformance/signers/webassembly-eddsa/
