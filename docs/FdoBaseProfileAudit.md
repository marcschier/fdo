# FDO 2.0 Base Profile audit

This audit compares library commit `770f9d6` with the FIDO Alliance
[April 2, 2026 Proposed Standard][fdo]. The paired tests prove the selected
encodings and state transitions with this library on both ends. They do not
establish interoperability, certification, or complete Base Profile support.
The [FIDO Alliance download page][downloads] still lists that April revision.
No published Errata 1 or independent vectors resolving the wire questions
below were verified for this audit.

For later platform evidence, see [qualification and support](FdoQualification.md).

| Requirement | Role and level | Evidence and remaining work |
|---|---|---|
| Version and capabilities, §§1.7.1, 1.7.4, 3.3.2–3.3.3 | Required capability mechanism. §3.3.3.1 requires Owner and Rendezvous version negotiation and recommends it for Devices. No particular legacy version required. | `FdoInitialMessageCodecTests` and `FdoTo2InitialCodecTests` cover message fields and the paired choices. DI and TO2 select 2.0 with bounded capability handling; TO0/TO1 use fixed paired capabilities, and the TO2 delegation opt-in does not verify Rendezvous negotiation. Audit version offers, selection and vendor-capability behavior separately from version 1.x support. |
| HTTP and HTTPS, §§1.7.2, 4 | Rendezvous and Owner: both required; Device: at least one. | `FdoHttpRendezvousStepTests` and `FdoPairedTo2SessionTests` prove paired exchanges and token handling. The Linux configured-root positive case and name/chain rejection cases use internal trust configuration. They do not show configured-root support in the public runners or a Windows TLS positive. Private-CA transport configuration is a separate host option, not a substitute for platform trust coverage. |
| Device attestation, §1.7.3 | Owner and Rendezvous must verify the profiled P-256/P-384 forms; Device must generate at least one. | `FdoTo2OwnerDeviceAuthenticatorTests`, `FdoX5ChainCodecTests`, and the paired suites exercise EC proof and chain checks. Verify every required X.509/X5CHAIN representation through the role flows; an X5CHAIN decoder alone does not establish support wherever a key can appear. Post-quantum support is recommended, not required. |
| Ownership Vouchers, §1.7.5 | Owner and Rendezvous must verify all listed combinations; Device must verify at least one. | `FdoOwnershipVoucherChainVerifierTests`, `FdoOwnershipVoucherTransferTests`, and `FdoPublicKeyCodecTests` cover selected P-256/P-384 and RSA voucher operations and negative cases. `FdoPublicKeyCodec` accepts SubjectPublicKeyInfo only; the ECDSA X5CHAIN public-key form and the full role matrix remain gaps. RSAPSS is outside the profile list, not a missing mandatory RSA form. |
| TO2 key exchange and protection, §1.7.6 | Owner must support all listed combinations; Device must support at least one key exchange and one protection choice. | `FdoEcdhKeyExchangeTests`, `FdoDhKeyExchangeTests`, `FdoAsymKeyExchangeTests`, the paired channel suites and TO2 tests cover selected suites and rejection paths. Exact-width DH is verified on Linux only; macOS DH and CCM are unsupported and macOS CTR execution is unverified. Pairing and provider results do not prove the full Owner matrix or settle the DH, ASYMKEX, or EtM wire choices. |
| Local discovery and directives, §§1.7.7, 3.8, 5.3–5.4 | Local discovery required; Device initialization must contain `rvserver.local`. §3.8 distinguishes role-applicable instructions and recommends Device processing of all DNS results, with a bound permitted. | `FdoDeviceInitializeSessionTests`, `FdoRendezvousInfoTests`, and `FdoRendezvousAttemptPlanTests` cover directive validation and candidate/delay planning. The parser does not cover bypass, external Rendezvous, certificate-hash directives, or provisioning a network medium. Device hosts resolve and admit destinations; the built-in HTTP runners do not pin resolved addresses or prove local-network discovery. |
| Delegated routing and lifetime, §§3.5.3–3.5.4, 5.3–5.4 | Delegation recommended; these rules apply when supported. A non-capable Device must not be sent Delegate records. §5.3.3 separately recommends accepting at least three addresses in `RVTO2Addr`. | `FdoPairedRendezvousTests` prove direct TO0/TO1 and the existing direct lifetime checks. The host-provided single-blob cases in `FdoPairedTo2SessionTests` prove Device-side verification with independent redirect and onboarding authorization. No delegated TO0 admission, TO1 discovery, independent Delegate lifetimes, or RVMore in the baseline. A blob with multiple addresses is also outside the current paired subset; that limit is independent of the number of blobs. |
| Delegated disposition and identity, §§3.5.2, 3.5.5–3.5.6, 6–7 | When delegation is enabled, the corresponding strict permissions and disposition rules apply. | `FdoDelegateChainVerifierTests` and paired TO2 test raw Owner anchoring, separate host authorization and permission checks for redirect, reuse and replacement. They reject unsupported disable and do not implement `DispDisable`. CA Owner and NOM are outside the current raw-key path, not satisfied by it or baseline requirements independent of those features. Offline revocation is separate; explicit `NoCheck` is the only Delegate revocation policy in the baseline. |
| Phase-specific Errors, §§5.1, 5.3–5.5, 3.5.5 | Conditional on phase, error and role. | `FdoErrorMessageCodecTests` and paired TO2 prove the selected protected Error behavior, including authenticated missing-disposition Error 104. Pre-key failures remain silent in the current implementation; DI and TO0/TO1 do not emit protocol Errors. Resolve authenticated missing PERM.1/104 handling and phase, correlation, and confidentiality rules before introducing additional emission. |
| ServiceInfo and selected CSR operations, §5.5 and [CSR module][csr] | TO2 framing is part of the role; `fdo.csr` is separately selected, not a Base Profile prerequisite. | `FdoTo2ServiceInfoStateTests`, `FdoServiceInfoBatchesTests`, and paired TO2 prove bounded batching and phase progression, not arbitrary modules or arbitrary fragmentation of a module value. The CSR tests listed below cover the selected encodings and checks, not independent EST or FSIM interoperability. |

The CSR module specifies CBOR text values for PKCS#10 requests and X.509
certificate responses for simple enrollment and re-enrollment. Re-enrollment
requires the original Subject and SAN unless a `ChangeSubjectName` request
applies. Format 281 for CA distribution is mandatory for the module; 287 is
optional and currently produces module error 5. The module permits a
constrained Device to choose client-side or server-side key generation; CSR
attributes discovery is optional. The server-key-generation response specifies
multipart with boundary `fdo`, PKCS#8 private key and certs-only PKCS#7;
the accompanying prose equating its certificate part with the simple-enrollment
response conflicts with the latter's PKIX certificate format. The paired
implementation uses the explicit multipart types. Evidence: `FdoCsrDeviceModuleTests`,
`FdoCsrReenrollmentTests`, `FdoCsrCaCertificatesTests`, `FdoCsrServerKeygenTests`,
`FdoCsrAttributesTests`, and `FdoCsrBase64TextCodecTests`. Parsing received CA
values does not install trust, and parsing a CRL does not verify revocation.

## Wire decisions to resolve before broadening support

- **RVPref:** §3.5.4 describes Rendezvous-supplied weights not sent in TO0;
  §§3.3.17 and 5.3.3 put the field in the signed address. Do not edit the
  signed blob. Decide how to treat non-null preferences, how to order the
  bounded snapshot, and how to bind RVMore indices to an unchanged snapshot.
  Until then, a delegated single-blob path must be separately selected and
  report multiple eligible records instead of picking one.
- **Capabilities and TO0 admission:** agree on where TO0/TO1 advertise and
  select delegation, how a non-capable peer is handled, and whether a TO0
  response emits Error 104 after the signer and voucher are proven. No
  downgrade or unauthenticated Error emission is inferred.
- **Done20 and transcript inputs:** the CDDL omits `ReplacementHMAC` where
  the prose uses it. The paired implementation puts it in Done20 and uses the
  selected transcript and voucher hash inputs. The public go-fdo
  [PR 282][gofdo] is a lead, not a published erratum or independent result.
- **Voucher signature context:** [App Note 8][aad] explains that voucher
  entries use the voucher version, including when a 2.0 implementation
  extends a 1.x voucher. For `to1d`, its §4.1 introduction points to the
  voucher version while the specific `to1d` bullet points to the negotiated
  session version. The baseline uses 2.0 for both, so its tests do not resolve
  that mixed-version case. Do not select AAD by trying both after a failure.
- **EtM, DH, and ASYMKEX:** the paired implementation selects serialized COSE
  protected maps and the FDO-specific SVK sizes; fixed-width unsigned DH and
  explicit A/B roles; and an independently provisioned RSA Owner key with a
  selected OAEP/KDF mapping. Treat these as paired choices until an
  authoritative clarification or independent vectors settle them. Never
  retry alternate encodings after verification fails.

[fdo]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html
[downloads]: https://fidoalliance.org/specifications/download-iot-specifications/
[csr]: https://raw.githubusercontent.com/fido-alliance/fdo-sim/main/fsim-repository/fdo.csr.md
[gofdo]: https://github.com/fido-device-onboard/go-fdo/pull/282
[aad]: https://fidoalliance.org/specs/fidoiot/fdo-appnote-8-voucher-aad-versioning-v1.0-20261001.html#rule
