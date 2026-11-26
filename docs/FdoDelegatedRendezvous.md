# Paired delegated Rendezvous

By default the paired TO1 role returns one eligible redirect blob per
lookup. A direct blob has one TO2 address. A delegated blob may have up to
three ordered addresses, all with null `RVPref`.

Select `AtomicRegistrationStore` instead of `RegistrationStore` for both
server roles. Supply `RegistrationAdmission` for TO0. The host chooses the
stable authenticated identity and may authorize replacement of the exact
incumbent in the admitted snapshot. The atomic store compares the snapshot
revision before changing any record. Use the same storage authority for
direct and delegated runs of a Device; do not write it through the legacy
GUID-only store as well.

For delegated TO0, configure the Owner's Delegate leaf signing key,
leaf-first certificate chain, and clock. Pass the observed source IP for
the **OwnerSign request**, either on `FdoHttpServerRequest.ObservedSource`
or directly to the server session. Do not copy the IP from Hello, accept an
unverified forwarded header, or derive the submitter from the signed TO2
destination. Before asking the host to admit the write, the server verifies
the voucher, current nonce, exact `to0d` hash, Delegate chain to the voucher
Owner, exact redirect signature, and Redirect permission. Delegate
verification uses local certificate material. It defaults to NoCheck if
no `DelegateOfflineRevocation` policy is configured. A configured policy
checks status from a trusted host source for each verified certificate
and issuer; the library does not validate CRL or OCSP signatures.
If Redirect permission is the only failed check, the server returns
terminal TO0 Error 104 without calling admission or writing a record.
The HTTP binding returns it as message 255 with status 500 and the
existing session token. Other pre-key errors and protected TO2 Error
behavior are unchanged.

For TO1, `UseDelegatedDiscovery` requests delegation. An opted-in paired
requester requires the server to acknowledge it; there is no fallback in the
same run. A lookup without delegation sees only the direct Owner slot.
Before returning a redirect, the server re-reads the eligible snapshot,
checks its revision and the exact selected record, and rechecks expiry.
It forwards the original signed bytes without rewriting them.

An atomic-store server may explicitly enable `AllowMultipleDelegatedRedirects`
for a mutually opted-in delegated lookup. It accepts up to eight live
records, requires a common exact Device certificate chain, and orders the
snapshot by registration ID for consistent pagination, not preference.
`RVMore` uses `/32` and requests the next index. The server may repeat the
last page once for the exact same `RVMore` request, including the final page
if the host retains the binding. Expiry or a changed revision takes priority
over retransmission. The server does not truncate an oversized snapshot.

Use `RunBatchAsync` or `RunDeviceRendezvousBatchAsync` to cache all pages
before selecting a blob. The library does not automatically retry, select
a blob, or start TO2. Each returned result retains the same one-shot
consumption and route checks as a single-blob result. The older `RunAsync`
entry point still expects exactly one blob.

The Device receives **untrusted** candidates in signed order. To register
multiple addresses, set `AdditionalOwnerAddresses` with up to two extras.
Each multi-address entry must be DNS-only or IP-only. Duplicates by scheme,
port and host are rejected using case-insensitive IDN DNS and normalized
numeric IP comparisons, including IPv4-mapped IPv6.
Rooted DNS names retain their trailing dot; a search-relative URI is not
equivalent. The transport origin must not include an IPv6 zone identifier.

For multiple candidates, the host selects one `CandidateAddresses` index
and sets `RendezvousAddressIndex`. The transport must expose that origin
through `IFdoHttpPeer.BaseAddress`; this checks the declared URI, not a
resolved peer. An invalid index or origin does not consume the result.
Once a matching run starts, it consumes the result even if protocol
verification fails. Host policy still admits the destination, and the
library does not resolve candidates for selection, follow redirects, or try
another candidate. Authenticating the exact blob in TO2 checks the selected
signed entry before the independent redirect approval and key derivation.
`CandidateAddress` remains available for single-address results only.
The redirect signer may differ from both the voucher Owner and the TO2 proof
signer. Redirect approval grants no TO2 onboarding permission.
