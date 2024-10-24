#!/usr/bin/env bash

cd ../../../bindings/node
npm run build-eddsa

cp -f unisign.node ../../conformance/signers/node-eddsa/
