#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-ecdsa

cp -rf build/ecdsa/release ../../conformance/signers/node-ecdsa/build
