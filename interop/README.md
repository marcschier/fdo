# FDO interoperability probe

This probe runs the FDO .NET Device against the public Go example
Manufacturer, Rendezvous, and Owner roles. It pins the
[Go reference candidate](https://github.com/bkgoodman/go-fdo/tree/930d18f414353903e8e9b847cb2cf3d37e0497ce)
and archive SHA-256. The peer is Apache-2.0; the runner fetches it for
validation rather than copying it into the repository or package.

The build configures the example to send no vendor flags and omits its
delay-only test directive. The runner advertises `rvserver.local` for
Device Initialize, but the probe admits only that name and port and
connects to `127.0.0.1` without a DNS lookup. For the direct FDO 2.0
fixture, the Go Owner writes a fifth address field, `RVPref`, as CBOR
null before signing the redirect. This follows the non-delegated prose
in [FDO 2.0 §3.3.17][rv-address]; the CDDL lists the field as a map.
The [build-time patch](go-peer-direct-rvpref.patch) applies only to the
downloaded test peer and leaves the upstream pin unchanged. The
Rendezvous Server does not change the signed address.

For `TO2.OVNextEntry20`, the [fixture patch](go-peer-ov-next-entry.patch)
embeds the tagged voucher entry directly, as [FDO 2.0 §5.5.9][ov-next-entry]
specifies. The unpatched Go example puts an extra byte string around it.
The patch does not change the signed voucher entry.

For protected TO2, the fixture's A256GCM sender and receiver use the same
role-separated counters as the .NET paired profile. The fresh fixture
process accepts one session and at most 64 protected request/response
pairs. The upstream example uses random IVs; the .NET policy is unchanged.
The [fixture Owner module](go-peer-simple-enrollment.go) activates `fdo.csr`
and handles one P-256 simple-enrollment request using the paired Base64
text convention. It checks the CSR signature and issues a certificate
from the fixture's ephemeral CA.

On Linux x64, install Go 1.26.10, the .NET 11 SDK, Git, and Docker or Podman.
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

The probe reports each completed phase and stops at the first rejection.
A passing run prints `phase=TO2 outcome=complete` after authenticating
`DoneAck20` and installing the enrollment certificate. The Device matches
the issued key to the synthetic CSR; that check is not production
certificate trust policy.

The [unconfigured Go example](https://github.com/marcschier/fdo/actions/runs/45828125680)
sent an unsolicited vendor flag. With that flag disabled in isolation,
the Device rejected the missing `rvserver.local` directive. The configured
fixture completes DI, including credential installation, and TO1.
The .NET Device accepts the mixed `TO1.HelloRVAck` capabilities and reads
the five-field `TO1.RVRedirect` address without following it outside
loopback. With the voucher envelope, counter and enrollment fixture
changes, the isolated ECDH256/A256GCM exchange completes TO2 with
credential reuse. This qualifies the configured fixture only. It does
not demonstrate compatibility with the unmodified Go peer or establish
FDO Base Profile conformance.

[rv-address]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html#rvto2addr
[ov-next-entry]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html#MSGT2-63
