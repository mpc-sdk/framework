#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-cggmp

cp -rf build/cggmp/release/* ../../conformance/signers/node-cggmp/build/
