#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-schnorr

cp -f unisign.node ../../conformance/signers/node-schnorr/
