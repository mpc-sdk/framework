#!/usr/bin/env bash

mkdir -p build

cd ../../../bindings/node
npm run build-cggmp

cp -f build/cggmp/release/* ../../conformance/signers/node-cggmp/build/
