#!/usr/bin/env bash

mkdir -p build

cd ../../../bindings/node
npm run build-eddsa

cp -f build/eddsa/release/* ../../conformance/signers/node-eddsa/build
