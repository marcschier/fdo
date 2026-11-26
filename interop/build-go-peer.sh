#!/usr/bin/env bash
# Copyright (c) marcschier. Licensed under the MIT License.

set -euo pipefail

revision=930d18f414353903e8e9b847cb2cf3d37e0497ce
archive_sha=abac2330e1bb6ae50dc0ddab50c7f9a6ea3e00a9256eb8a1e40f30477bfc89ba
if [[ $# != 1 || "$(GOTOOLCHAIN=local go env GOVERSION)" != go1.26.10 ]]; then
    echo "Usage: build-go-peer.sh <output-binary> (Go 1.26.10 required)" >&2
    exit 2
fi

output="$(realpath -m "$1")"
work="$(mktemp -d)"
trap 'rm -f -- "$work/peer.tar.gz"; rm -rf -- "$work/source"; rmdir -- "$work"' EXIT
mkdir -p "$(dirname "$output")" "$work/source"
curl --fail --silent --show-error --location --max-time 60 \
    "https://codeload.github.com/bkgoodman/go-fdo/tar.gz/$revision" -o "$work/peer.tar.gz"
printf '%s  %s\n' "$archive_sha" "$work/peer.tar.gz" | sha256sum --check
tar --extract --gzip --file "$work/peer.tar.gz" --directory "$work/source" --strip-components=1
cd "$work/source/examples"
export GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
go mod download
go mod verify
GOPROXY=off go build -mod=readonly -trimpath -o "$output" ./cmd
