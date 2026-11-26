#!/usr/bin/env bash
# Copyright (c) marcschier. Licensed under the MIT License.

set -euo pipefail

export HOME=/scratch TMPDIR=/scratch
cd /scratch
/inputs/fdo-go-peer server -db /scratch/peer.db -http 127.0.0.1:8080 \
    -ext-http 127.0.0.1:8080 -reuse-cred >peer.log 2>&1 &
peer=$!
trap 'kill "$peer" 2>/dev/null || true; wait "$peer" 2>/dev/null || true' EXIT
for ((attempt=0; attempt<80; attempt++)); do
    if (echo >/dev/tcp/127.0.0.1/8080) 2>/dev/null; then
        ready=true
        break
    fi
    if ! kill -0 "$peer" 2>/dev/null; then
        echo "phase=startup outcome=peer-exited" >&2
        tail -n 5 peer.log >&2
        exit 2
    fi
    sleep 0.25
done
if [[ ${ready:-false} != true ]]; then
    echo "phase=startup outcome=timeout" >&2
    exit 2
fi

timeout --kill-after=5s 45s dotnet /inputs/probe/Fdo.PeerProbe.dll http://127.0.0.1:8080/
