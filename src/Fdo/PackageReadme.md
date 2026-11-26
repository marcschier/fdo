# Fdo

Fdo is a .NET 10 and 11 library for paired FIDO Device Onboard (FDO) 2.0
exchanges. Your application supplies peer and destination authorization,
credential storage, and recovery policy. The library handles wire encoding,
signature verification, and protocol state.

This package is intended for local integration. The paired exchanges do not
establish full Base Profile support, independent interoperability, or FIDO
certification. Fdo is MIT-licensed; see `LICENSE` in the package.

If you have access to the source repository, start with the
[loopback example](https://github.com/marcschier/fdo#quick-start). See the
[hosting guide](https://github.com/marcschier/fdo/blob/main/docs/FdoHosting.md)
for the public role APIs and callbacks, and the
[qualification notes](https://github.com/marcschier/fdo/blob/main/docs/FdoQualification.md)
for the tested paths and platform limits.
