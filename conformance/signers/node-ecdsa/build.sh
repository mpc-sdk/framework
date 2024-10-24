#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-ecdsa

cp -f unisign.node ../../conformance/signers/node-ecdsa/
