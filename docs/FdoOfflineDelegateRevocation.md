# Offline Delegate revocation

Each role can require offline status for the Delegates it uses or verifies.
Without that option, the role uses the existing no-revocation-check policy.
A failed offline check never selects that policy instead.

Configure `FdoDelegateOfflineRevocationPolicy` with a trusted host adapter
and explicit maximum age and lifetime. The adapter uses only local evidence.
It authenticates the evidence, determines whether its source has authority
for this issuer, and checks whether it covers the certificate completely.
For example, parsing a CRL or finding that a serial is absent is not enough
to report `Good` unless the adapter has also established authenticity,
issuer association and scope. The library does not authenticate underlying
CRL or OCSP signatures. Do not populate the adapter from protocol input.

The adapter receives only detached evidence about the exact certificate path
that the library verified. Return one status per certificate, bound to the
certificate and issuer key digests in that request. The library rejects
missing, duplicate, wrong-issuer, unknown, revoked and stale results using
the role's trusted clock. `NextUpdate` is exclusive. The terminating
certificate requires status too. Its issuer is a bare voucher Owner key,
not a CA certificate or an implied authority to sign revocation data. If
the host cannot independently establish revocation authority for that hop,
return `NoAuthority`; the role rejects it as unsupported.

On Device TO2, the source is called after proof verification and final
voucher binding, before host acceptance or key derivation. Redirect and
onboarding policies remain separate. On delegated TO0, the server checks
offline status before host admission and the atomic write. On TO1 it
checks the selected stored Delegate again before returning the blob. No
online calls, ambient trust exceptions, general PKIX validation or new
wire Error behavior are introduced.
