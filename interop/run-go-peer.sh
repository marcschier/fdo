#!/usr/bin/env bash
# Copyright (c) marcschier. Licensed under the MIT License.

set -euo pipefail

if [[ $# != 1 ]]; then
    echo "Usage: run-go-peer.sh <directory containing fdo-go-peer and probe/>" >&2
    exit 2
fi

inputs="$(realpath "$1")"
scripts="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
if [[ ! -x "$inputs/fdo-go-peer" || ! -f "$inputs/probe/Fdo.PeerProbe.dll" ]]; then
    echo "The prepared peer or .NET probe is missing." >&2
    exit 2
fi

runtime=mcr.microsoft.com/dotnet/runtime@sha256:f4ee1b92a00425ca1fabc7fb25c9819a7a5ea0f36342e37e4998b582eb57b8c7
"${CONTAINER_ENGINE:-docker}" run --rm --platform linux/amd64 --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 1g \
    --user 65534:65534 --tmpfs /scratch:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
    --mount "type=bind,source=$inputs,target=/inputs,readonly" \
    --mount "type=bind,source=$scripts/peer-exchange.sh,target=/peer-exchange.sh,readonly" \
    --entrypoint /usr/bin/timeout "$runtime" --kill-after=5s 70s /bin/bash /peer-exchange.sh
