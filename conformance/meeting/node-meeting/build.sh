#!/usr/bin/env bash

mkdir -p build

cd ../../../bindings/node
# meeting functionality depends on at least one protocol
# being active
npm run build-cggmp

cp -f build/cggmp/release/* ../../conformance/meeting/node-meeting/build/
