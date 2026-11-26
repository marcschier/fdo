# FDO for .NET

A [FIDO Device Onboard (FDO) 2.0](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html)
library for .NET 10 and 11. Run the Device, Owner, and Rendezvous roles together
over HTTP or HTTPS, or supply your own transport. Licensed under the
[MIT License](LICENSE).

> **Preview:** The library runs between paired roles. Full Base Profile support
> and independent interoperability are not yet established.

## 🧩 What it does

- Initialize a Device and transfer its ownership voucher.
- Register and discover an Owner, including opt-in delegated discovery and
  paging.
- Enroll the Device over protected TO2 and retain or replace its FDO credential.

Your application authorizes peers and destinations and supplies credential
storage. The library handles messages, signatures, and protocol state.

## Quick start

Install the .NET 11 SDK and the .NET 10 runtime. From the repository root,
initialize a Device and transfer its voucher in process:

```powershell
dotnet run --project samples/Fdo.InProcess --framework net10.0
```

The sample uses ephemeral keys. Look for `FDO initialization complete`.
Try the [HTTP loopback sample](samples/Fdo.HttpLoopback/README.md) to host
the Manufacturer over HTTP.

To build the library and test project together:

```powershell
dotnet build Fdo.slnx
```

## 📚 Documentation

- [Documentation index](docs/README.md): hosting, recovery, trust, and integration.
- [Qualification and support](docs/FdoQualification.md): tested paths and limitations.
- [Changelog](CHANGELOG.md)
