#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-schnorr

cp -rf build/schnorr/release ../../conformance/signers/node-schnorr/build
