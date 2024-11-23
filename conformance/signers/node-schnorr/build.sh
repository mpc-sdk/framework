#!/usr/bin/env bash

mkdir -p build

cd ../../../crates/bindings/node
npm run build-schnorr

cp -f build/schnorr/release/* ../../../conformance/signers/node-schnorr/build
