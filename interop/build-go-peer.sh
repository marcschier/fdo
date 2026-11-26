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
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -f -- "$work/peer.tar.gz"; rm -rf -- "$work/source"; rmdir -- "$work"' EXIT
mkdir -p "$(dirname "$output")" "$work/source"
curl --fail --silent --show-error --location --max-time 60 \
    "https://codeload.github.com/bkgoodman/go-fdo/tar.gz/$revision" -o "$work/peer.tar.gz"
printf '%s  %s\n' "$archive_sha" "$work/peer.tar.gz" | sha256sum --check
tar --extract --gzip --file "$work/peer.tar.gz" --directory "$work/source" --strip-components=1
cd "$work/source"
# Encode the FDO 2.0 direct fixture's null RVPref before the Owner signs the blob.
git apply "$scripts/go-peer-direct-rvpref.patch"
# Type 85 embeds the signed voucher entry, not a byte string wrapping it.
git apply "$scripts/go-peer-ov-next-entry.patch"
git apply "$scripts/go-peer-enrollment.patch"
cp "$scripts/go-peer-paired-gcm.go" cose/fdo_probe_gcm.go
gcm='RegisterEncryptAlgorithm(A256GCM, true, 256, aesGcm)'
if [[ $(grep -F -c -- "$gcm" cose/encrypt_alg.go) != 1 ]]; then
    echo "Expected exactly one A256GCM registration in the pinned Go peer." >&2
    exit 2
fi
sed 's/RegisterEncryptAlgorithm(A256GCM, true, 256, aesGcm)/RegisterEncryptAlgorithm(A256GCM, true, 256, newFixtureGcm)/' \
    cose/encrypt_alg.go >cose/encrypt_alg.go.fixture
mv cose/encrypt_alg.go.fixture cose/encrypt_alg.go
cd "$work/source/examples"
cp "$scripts/go-peer-fixture.go" cmd/fdo_probe_fixture.go
cp "$scripts/go-peer-simple-enrollment.go" cmd/fdo_probe_enrollment.go
# The example always prepends a delay-only test directive, even at the default zero delay.
delay='rvInfo = append([][]protocol.RvInstruction{{{Variable: protocol.RVDelaysec, Value: mustMarshal(rvDelay)}}}, rvInfo...)'
if [[ $(grep -F -c -- "$delay" cmd/server.go) != 1 ]]; then
    echo "Expected exactly one delay-only directive in the pinned Go example." >&2
    exit 2
fi
grep -F -v -- "$delay" cmd/server.go >cmd/server.go.fixture
mv cmd/server.go.fixture cmd/server.go

export GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
go mod download
go mod verify
GOPROXY=off go build -mod=readonly -trimpath -o "$output" ./cmd
