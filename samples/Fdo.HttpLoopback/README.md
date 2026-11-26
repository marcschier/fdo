# Host Device initialization over HTTP

Kestrel listens on an ephemeral IPv4 loopback port. The sample passes the raw
request target and request stream to `FdoHttpServerSession` and confirms each
response handoff only after the server writes the response. The Device uses
the public `FdoHttp` runner. The same fixture as the in-process sample verifies
that initialization installed a credential and transfer appended an Owner.

From the repository root, run:

```powershell
dotnet run --project samples/Fdo.HttpLoopback --framework net10.0
```

Look for `FDO HTTP initialization complete; transferred voucher has one Owner entry.`
Use `--framework net11.0` to run on .NET 11. The sample accepts a single
preauthorized fixture and serves plain HTTP on loopback only. It does not
provide production station authentication, durable storage, or a token router
for multiple Devices. See [Host the FDO roles](../../docs/FdoHosting.md)
for those host responsibilities and the subsequent enrollment flow.
