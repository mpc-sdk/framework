#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-eddsa

cp -rf build/eddsa/release ../../conformance/signers/node-eddsa/build
