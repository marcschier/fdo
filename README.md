# FDO for .NET

A [FIDO Device Onboard (FDO) 2.0](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html)
library for .NET 10 and 11. Run the Device, Owner, and Rendezvous roles together
over HTTP or HTTPS, or supply your own transport.

> **Preview:** The library runs between paired roles. Full Base Profile support
> and independent interoperability are not yet established. No NuGet package
> has been published.

## 🧩 What it does

- Initialize a Device and transfer its ownership voucher.
- Register and discover an Owner, including opt-in delegated discovery and
  paging.
- Enroll the Device over protected TO2 and retain or replace its FDO credential.

Your application authorizes peers and destinations and supplies credential
storage. The library handles messages, signatures, and protocol state.

## Quick start

Use the .NET 11 SDK to build both targets. From the repository root, run the
.NET 10 loopback example:

```powershell
dotnet run --project tests\Fdo.AotSmoke\Fdo.AotSmoke.csproj --framework net10.0 -- --scenario ecdh256-a128gcm
```

The example creates temporary keys and runs initialization, voucher transfer,
Rendezvous, and protected enrollment. Look for `FDO AOT smoke passed`. This
command runs managed code; `dynamicCode` in the output distinguishes it from
a NativeAOT run.

To build the library and test project together:

```powershell
dotnet build Fdo.slnx
```

## 📚 Documentation

- [Host the roles](docs/FdoHosting.md): public APIs, callbacks, and storage.
- [Integration design](docs/FdoIntegrationDesign.md): trust boundaries and paired wire choices.
- [Qualification and support](docs/FdoQualification.md): verified paths, platform limits, and open work.
