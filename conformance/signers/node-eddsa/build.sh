#!/usr/bin/env bash

set -e

mkdir -p build

cd ../../../crates/bindings/node
npm run build-eddsa

cp -f build/eddsa/release/* ../../../conformance/signers/node-eddsa/build
