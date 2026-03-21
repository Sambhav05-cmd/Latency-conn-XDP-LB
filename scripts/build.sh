#!/usr/bin/env bash
set -e

ROOT=$(dirname "$(realpath "$0")")/..

cd "$ROOT"

echo "==> running code generation"
./scripts/gen.sh

echo "==> creating bin directory"
mkdir -p bin

echo "==> building LC loader"
go build -o bin/lbxdpd-lc ./cmd/lbxdpd-lc

echo "==> building WLC daemon"
go build -o bin/lbxdpd-wlc ./cmd/lbxdpd-wlc

echo "==> building ctl"
go build -o bin/lbctl ./cmd/lbctl

echo "==> build complete"
ls -lh bin