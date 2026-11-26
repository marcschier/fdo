# FDO documentation

Start with the [in-process sample](../samples/Fdo.InProcess/README.md) to
initialize a Device and transfer its voucher. The
[HTTP loopback sample](../samples/Fdo.HttpLoopback/README.md) shows how to
connect the same roles through the HTTP binding.

| Topic | What it covers |
|---|---|
| [Host the FDO roles](FdoHosting.md) | Public role APIs, callbacks, message limits, and host responsibilities. |
| [Integration design](FdoIntegrationDesign.md) | Trust boundaries, state transitions, and paired wire choices. |
| [Host recovery](FdoHostRecovery.md) | Reconcile uncertain storage, installation, and delivery outcomes. |
| [Private HTTPS trust](FdoPrivateHttpsTrust.md) | Trust a private CA without changing machine trust stores. |
| [Delegated Rendezvous](FdoDelegatedRendezvous.md) | Registration authority, source admission, and paged discovery. |
| [Offline Delegate status](FdoOfflineDelegateRevocation.md) | Verify status evidence before accepting delegated authority. |
| [Voucher X5CHAIN](FdoVoucherX5Chain.md) | Encode and verify certificate-chain Owner keys. |
| [Qualification and support](FdoQualification.md) | Evidence by platform and role, including NativeAOT and peer limits. |
| [Interoperability probe](../interop/README.md) | Run the pinned Go peer against the .NET Device in isolation. |
| [Base Profile audit](FdoBaseProfileAudit.md) | Requirements and remaining support gaps. |
| [Changelog](../CHANGELOG.md) | User-visible changes by version. |
| [Build and release](FdoRelease.md) | Signed assembly identity, local package checks, and gated publication. |
