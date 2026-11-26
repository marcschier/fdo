# FDO interoperability probe

This probe runs the FDO .NET Device against the public Go example
Manufacturer, Rendezvous, and Owner roles. It pins the
[Go reference candidate](https://github.com/bkgoodman/go-fdo/tree/930d18f414353903e8e9b847cb2cf3d37e0497ce)
and archive SHA-256. The peer is Apache-2.0; the runner fetches it for
validation rather than copying it into the repository or package.

On Linux x64, install Go 1.26.10, the .NET 11 SDK, and Docker or Podman.
From the repository root, prepare the artifacts, then run them together
with only loopback networking:

```bash
bash interop/build-go-peer.sh "$PWD/bin/interop/fdo-go-peer"
dotnet publish interop/Fdo.PeerProbe -c Release -o bin/interop/probe
bash interop/run-go-peer.sh "$PWD/bin/interop"
```

Set `CONTAINER_ENGINE=podman` for Podman. The build downloads the pinned
peer and Go modules. The run uses a separate container with no external
network, a read-only artifact mount, and a disposable database. Do not
give the probe production credentials or enable peer debug logging.

The probe reports the last completed phase and stops at the first rejection.
It targets ECDH256/A256GCM if DI and TO1 complete. The certificate check
matches the issued key to the synthetic CSR; it is not production
certificate trust policy. A failure before the protected exchange says
nothing about its cipher behavior. Even successful execution against this
candidate would not establish FDO Base Profile conformance.

The first isolated run with this pin reached the Go HTTP server, but the
.NET Device rejected the DI exchange with `CborContentException` before
staging the credential or sending `DI.SetHMAC`. TO1 and TO2 did not run.
This result does not test the two implementations' protected IV policies.
