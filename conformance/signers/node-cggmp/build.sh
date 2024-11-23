#!/usr/bin/env bash

set -e

mkdir -p build

cd ../../../crates/bindings/node
npm run build-cggmp

cp -f build/cggmp/release/* ../../../conformance/signers/node-cggmp/build/
