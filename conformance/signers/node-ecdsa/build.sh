#!/usr/bin/env bash

mkdir -p build

cd ../../../crates/bindings/node
npm run build-ecdsa

cp -f build/ecdsa/release/* ../../../conformance/signers/node-ecdsa/build
