#!/usr/bin/env bash

set -e

mkdir -p build

cd ../../../crates/bindings/node
# meeting functionality depends on at least one protocol
# being active
npm run build-cggmp

cp -f build/cggmp/release/* ../../../conformance/meeting/node-meeting/build/
