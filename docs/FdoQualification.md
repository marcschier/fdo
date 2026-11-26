# FDO qualification and support

Use this page to choose an FDO 2.0 role, transport, and platform for a paired
integration. Each result names the code that ran and the behavior it
verified. The library does not yet support the complete Base Profile, and
the tests do not establish interoperability with another implementation.
Your application still owns authorization, destination admission, durable
storage, and recovery.

Start with [role and transport coverage](#role-and-transport-coverage) for
the current behavior. The [requirements audit](FdoBaseProfileAudit.md)
records the gaps at `770f9d6`. Treat limits in a checkpoint row as limits
of that checkpoint, not of later rows.

## Managed test evidence

Counts are per target framework (TFM).

| Area | Verified checkpoint and scope |
|---|---|
| Verify-first delegated redirect | `770f9d6`: 407 selected Windows cases and 410 Linux cases per TFM. Device accepts one host-supplied signed blob only after chain, exact signature, separate Redirect permission and host approval. |
| Atomic Rendezvous storage | `ca457d7`: 81 selected cases per TFM on Windows and Linux. Separate direct/delegate records and expiring slots, source IP discrimination without IP-based authorization, exact mutation receipts, and stale writer rejection. Evidence is file-backed reopen and concurrent writers serialized in one process, not cross-process or power-loss durability. |
| Paired delegated TO0/TO1 | `0670d09`: 336 selected Windows cases and 339 Linux cases per target framework. Both roles opt in. The server verifies the observed source and exact signed blob, asks the host to admit it, then checks the record revision and expiry again at Device proof. This checkpoint returns one eligible blob with one address and null preferences; later rows cover multiple addresses, Error 104, and paging. |
| Multiple addresses in one delegated TO1 blob | `d0a73df`: 389 selected Windows cases and 396 Linux cases per TFM. The Device checks the host-selected origin before claiming the result, then verifies the exact signed address before host approval and enrollment. Tests reject a URI missing the signed DNS root dot or containing an IPv6 zone identifier without consuming the result. This checks the declared URI, not a resolved peer; no new NativeAOT evidence. |
| Authenticated TO0 permission rejection | `5001ceb`: 389 selected Windows cases and 396 Linux cases per TFM. The server sends Error 104 only after authenticating the delegated submission and only when Redirect permission is missing. It does not call host admission or write a record. |
| Bounded delegated TO1 batches | `82d7372`: 398 selected Windows cases and 405 Linux cases per TFM. The Device caches all pages of up to eight null-preference blobs before returning candidates. The server permits one exact repeat of the last `RVMore` request only while the snapshot is unchanged and none of its records have expired. This run does not cover non-null preferences or NativeAOT. |
| Rendezvous directive role filtering | `ff67fb2`: 103 selected cases per TFM on Windows and Linux. The parser validates directive structure before skipping instructions addressed only to the other role. It preserves applicable directive indices and the Device discovery requirement, and still rejects unsupported instructions in applicable directives. |
| Rendezvous variables in shared directives | `0ca73b1`: 109 selected cases per TFM on Windows and Linux for role-specific ports and protocol. `c78c88f`: 111 selected cases per TFM on both platforms. The Owner ignores the remaining assigned Device-only fields (tags 6–11 and 14–15) after checking their structure; the Device still rejects them. Unknown tags, delays, and Owner HTTPS behavior are unchanged. |
| Host recovery | `8ae2855`: 251 selected Windows cases and 254 Linux cases per TFM. File-backed DI reconciliation and fresh sessions, TO0 uncertain-write receipts, and separate TO2 replacement and enrollment effects. No production database, physical power-loss or exported-secret test. |
| Private-CA HTTPS | `df6f684`: 274 selected Windows cases and 281 Linux cases per TFM. Linux public runners complete matching-root TO0, TO1 and TO2 runs and reject wrong name, wrong root or an unconfigured private root. No positive Windows Schannel run; the fixture's ephemeral TLS key did not support that run. |
| Offline Delegate status | `bbd3edc`: 332 selected Windows cases and 339 Linux cases per TFM. A host-supplied authoritative result must match each verified certificate and issuer, including the bare voucher Owner hop. This tests status binding, coverage and freshness, not CRL or OCSP signature authentication. |
| ECDSA voucher X5CHAIN | `aa37791`: 417 selected Windows source tests per TFM, including multi-hop TO0/TO1/TO2 and exact manufacturer digest/final Owner bytes. Attached certificates do not establish CA trust, CA Owner support, or NOM. |
| Delegate validity while onboarding | `b047119`: deterministic clock tests cover expiry before proof receipt and expiry while collecting voucher entries. Both stop before the offline status source, host acceptance, and enrollment. |

These runs use .NET 10 and .NET 11 on Windows x64 and Linux x64; the Linux
portable managed environment uses OpenSSL 3.0.13. Clean `276947d` passed
517 selected Windows tests and 524 portable Linux tests per target, with
no failures or skips. Linux includes the seven Linux-only HTTPS cases.

Clean `dcfefb5` passed the full managed corpus on Linux (1,608 tests per
target) and all Windows-eligible cases (1,601 per target), with no failures
or skips on .NET 10 or 11. The earlier unfiltered Linux run failed one
format 281 test because the platform exported CMS with present `eContent`.
The fixture now constructs certs-only CMS with absent `eContent`, as
required by RFC 8551 §3.8. Both platforms also passed all 24 focused CMS
cases, including rejection of empty but present `eContent`. The decoder
is unchanged. These managed results do not cover NativeAOT.

Clean `c78c88f` passed all 1,616 unfiltered managed tests per target on
Linux x64 with .NET 10 and 11, with no failures or skips. This refreshes
Linux managed evidence only.

## NativeAOT test evidence

Clean `276947d` passed all ten Linux x64 NativeAOT enrollment scenarios
per target, including the two Linux DH cases and `delegated-replacement`.
Linux native runs used Debian 12 and OpenSSL 3.0.20. Windows x64 passed
eight enrollments and two expected unsupported-DH rejections per target.
Both platforms ran the native executables directly with
`--require-native-aot` on .NET 10.0.15 and 11.0.0.

The `delegated-replacement` scenario exercises X5CHAIN, delegated TO2 and offline status,
the Owner2 replacement commit and HMAC, activation after authenticated
DoneAck, and enrollment installation. It uses direct HTTP TO0/TO1 and
in-memory host callbacks. It does not exercise delegated discovery,
private TLS, or durable recovery under NativeAOT.

The first Windows publish timed out after producing a binary. The smoke
runner did not use it. The retry omitted debug symbols. After the publisher
and linker exited, only the verified Visual C++ telemetry helper left in
each job was stopped. The smoke runner used the new
executables only after both publish processes returned exit 0 and their
jobs were empty. No machine-wide settings changed.

| Native executable from `276947d` | SHA-256 |
|---|---|
| Windows x64 .NET 10 | `b55c47006cb2053d968ac259e8aaa227b8b3a3b0796316f763ddda9a23b274ec` |
| Windows x64 .NET 11 | `5e8bc8896a38a3f1137ea223de2f708723a98a0eba22b3ff4a9d252d682f3ce7` |
| Linux x64 .NET 10 | `b63dde3bff703f42c80c84de3e8e0479ded290af772547de272c1dac791a93ea` |
| Linux x64 .NET 11 | `6f941b263e24233535cd231f744ff0e208abf1d7999c5d8cbeddb8ff6966d2c0` |

Clean `3882040` ran the Linux-only `direct-rsa-combined-offers` scenario
under NativeAOT on .NET 10.0.15 and 11.0.0 (Debian 12 x64, OpenSSL 3.0.20).
It checked the ordered RSA-2048 ASYMKEX/DH and GCM/CBC offers, the accepted
Device proof selecting the non-primary DH14 and CBC-EtM, and completed
protected enrollment. This is one combined-offer case, not an expanded
platform or cipher matrix. Windows compiled the smoke but did not run it.

| Combined-offer native executable from `3882040` | SHA-256 |
|---|---|
| Linux x64 .NET 10 | `b7c69b8b2905dc82e3a6d8f0fc23ddfb8b1c422f1bf4905aae5e5d1f758f244a` |
| Linux x64 .NET 11 | `fd134e483ea65c0658686af7897c915f6719a41ae5d196c4e90c39947544b35c` |

## Role and transport coverage

| Role | Verified paired paths | Limits |
|---|---|---|
| Device | DI over HTTP; TO1 and TO2 over HTTP and HTTPS with a configured root on Linux; credential reuse and replacement; host-authorized Delegate proof and redirect. | The host provisions Device credentials and admits the selected destination. A signed `to1d` remains untrusted until TO2. The HTTP runner doesn't pin the resolved IP address, set the TLS server name independently of the URI, or follow redirects. |
| Owner | Voucher transfer, TO0 registration, TO2 authenticated Device enrollment and credential replacement. The selected `fdo.csr` exchanges include simple enrollment, re-enrollment, format 281 CA distribution, attributes and server key generation. | The host authorizes issuance, commits the voucher and enrollment separately, and reconciles uncertain effects. An Owner commit is not evidence that the Device activated a new credential. Delegated TO2 does not support ASYMKEX or disable. |
| Rendezvous | Direct and delegated TO0/TO1, with exact signed bytes, per-record expiry and host-authorized atomic updates. A delegated blob may contain up to three ordered addresses. Explicit delegated batch lookup supports up to eight blobs with null preferences. TO0 Error 104 is limited to authenticated submissions that lack Redirect permission. | Non-null `RVPref` is not implemented. HTTP hosts supply the observed TO0 submitter IP for the actual `OwnerSign` request; the library does not use forwarded headers. |

The managed Linux HTTPS runs use the client runners and the paired server
binding. The host opens the listener, terminates TLS, and decides which
proxies and destinations to trust. [Private CA trust for the HTTP runner](FdoPrivateHttpsTrust.md)
does not replace [offline Delegate status](FdoOfflineDelegateRevocation.md).
Configure each policy separately.

## Platform and interoperability limits

- ECDH-GCM primitive and KDF outputs on clean `8ae2855` matched three
  specification-aligned, vendor-authored known-answer vectors on Windows
  and Linux, on both TFMs: P-256/A128GCM, P-256/A256GCM and P-384/A256GCM.
  The published cipher-suite row selects HMAC-SHA256 for those GCM suites,
  independent of curve. The results verify both role orders and exact ShSe
  and SEVK, not message bytes or external protocol execution.
- Paired DH at the exact required exponent widths is implemented on
  Linux/OpenSSL. Do not infer Windows or macOS DH support from provider
  availability. macOS DH and CCM are unsupported; the public CommonCrypto
  CTR path has not run on macOS. The deferred manual arm64 macOS job was
  prepared and parsed locally only; it has not been installed or run. It
  requires `macos-15` arm64, the .NET 10 and 11 SDK toolchains, and public
  Apple developer tools. It selects CTR vectors and the supported-platform
  NativeAOT scenario matrix, including delegated replacement.
- Public FDO 2.0 candidate peers include
  [fido-device-onboard/go-fdo#285][go] at `930d18f414353903e8e9b847cb2cf3d37e0497ce`
  and its UEFI/Rust siblings. They share a vendor lineage and were not
  executed here. The bounded search did not verify an issued FDO 2.0
  Errata 1 or independent EtM, DH, ASYMKEX, or full message-byte vectors.
  No alternate encoding is tried after a verification failure.
- The paired roles select FDO 2.0 with bounded capability rules, not general
  version or vendor negotiation. The Rendezvous server accepts known 1.x
  capability bits alongside 2.0 in received Hello messages and selects
  only 2.0. Client ACK and OwnerSign checks still require exact paired
  flags; there is no fallback to 1.x. TO2 checks for the 2.0 bit rather
  than requiring it to be the only version bit. The profile's complete key encoding,
  attestation and cipher matrices have not been independently qualified.
  `DispDisable`, NOM, CA Owner and broader phase-specific Errors are not
  implemented. Omitted features and unresolved wire details are tracked in
  the requirements audit rather than inferred from a successful paired run.
- A TO2 Owner can configure up to nine `AdditionalCipherSuites` after its
  required `CipherSuite`. It rejects duplicates and unsupported entries
  before the run. The list preserves configuration order, but the Device
  selects its configured suite, not the first entry. Its signed proof binds
  that selection to the exact acknowledgement. Clean `6c639aa` ran
  282 selected Windows tests and
  289 portable Linux tests per target on .NET 10 and 11. This qualifies
  the explicit offer path, not every cipher combination or NativeAOT.
- A direct RSA Owner on Linux can offer its size-matched DH and ASYMKEX
  suites together using `AdditionalKeyExchangeSuite` and both existing
  protocol opt-ins. The Owner checks the local voucher and signer against
  both suites before advertising them. The Device still selects its
  configured suite and ASYMKEX still requires an independently provisioned
  RSA Owner key. Delegated TO2 and the default single offer are unchanged.
  Clean `457899d` passed 318 selected Linux tests per target on .NET 10
  and 11, including both choices for each RSA size. The 311 selected
  Windows cases per target verify that the Owner rejects the dual offer
  before sending an acknowledgement because DH is unavailable there.
  This is managed evidence only; it does not extend NativeAOT qualification.
- `RVPref` defaults to weight zero without configured weights, but the
  published text disagrees about who supplies it and places the field
  inside authenticated `to1d`. The library accepts only null
  preferences and forwards the signed blob unchanged. `RVMore` shares
  `/32` with `ProveToRV`; the session distinguishes the requests by phase.
  The Device caches the complete result before starting TO2.

## What blocks the remaining work

| Area | Decision or evidence needed |
|---|---|
| Rendezvous | Non-null `RVPref` needs a decision on who supplies the signed value. Automatic DNS expansion and Device certificate-hash instructions need explicit host destination and TLS trust rules. |
| Version and Errors | Client selection, no-common-version handling, vendor negotiation, and mixed-version voucher versus session AAD need explicit protocol rules. Other earlier-phase Errors still need a disclosure policy and validated framing. Do not retry an alternate version or encoding on rejection. |
| Delegated dispositions and trust | `DispDisable` needs host authorization and durable Device deactivation and recovery semantics. NOM and CA Owner need separate trust and identity rules. The offline status interface does not itself authenticate CRL or OCSP evidence. |
| Platform and interoperability | Windows and macOS lack a verified exact-width DH provider. macOS CCM is unsupported and its CTR execution remains unverified. Hosted macOS and independent peer execution need separate authorization; the paired runs do not establish conformance. |
| Delivery | The library isn't published. An approved local package is not a release. Publishing a package, pushing changes, or making the repository public requires a separate decision. |

[go]: https://github.com/fido-device-onboard/go-fdo/pull/285
