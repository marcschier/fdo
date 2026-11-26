# FDO 2.0 standalone library

The design targets the FIDO Device Onboard (FDO) 2.0 Base Profile for Device,
Owner, and Rendezvous in one standalone .NET library and one NuGet package.
The library implements paired Device Initialize (DI), TO0, TO1, and protected
TO2 exchanges with an HTTP binding. Your application authorizes peers, keeps
keys and protocol state, and reconciles outcomes that the exchange can't
confirm. The [qualification notes](FdoQualification.md) distinguish the paths
verified on paired peers from full Base Profile support and interoperability,
which remain unverified.

## Scope

The implementation target is the normative FDO 2.0 Base Profile in the FIDO
Alliance's [FDO 2.0 Proposed Standard](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html).
Each role must implement its own profile requirements:

| Role | Base Profile protocols | Transport requirement |
|---|---|---|
| Device | TO1 and TO2 | HTTP or HTTPS |
| Owner | TO0 and TO2 | HTTP and HTTPS |
| Rendezvous | TO0 and TO1 | HTTP and HTTPS |

The Base Profile also requires version and capability negotiation, Device
attestation, Ownership Voucher processing, TO2 session cryptography, and local
Rendezvous discovery through `rvserver.local`. The library also targets the
non-normative Device Initialize (DI) network example and local provisioning,
but the Base Profile does not require that network protocol. The `fdo.csr`
module is in scope, including server-side key generation and CSR attributes.
Delegation should be supported, but a role may disable it through the capability
flags.

This phase does not include FDO 1.1, an end-to-end sample, or a service-specific
onboarding workflow. It also does not define the manufacturer's factory
process, voucher logistics, or the long-term management protocol used after
onboarding.

## Library boundary

The library owns FDO wire representation, validation, cryptographic operations,
role-specific protocol state, and ServiceInfo exchange. Its public surface
remains independent of application-specific types, identities, and policy.

The library needs explicit boundaries for:

- Device, Owner, and Rendezvous protocol operations and results.
- HTTP/HTTPS transport and message framing.
- Key custody and credential storage.
- Ownership Voucher and Rendezvous registration storage.
- ServiceInfo module dispatch and validation.

The paired role interfaces expose the exchange and its results; they do not
provide a key store, registration database, or recovery protocol. Keep
client-generated private keys in the configured provider. When the Owner
generates a key for the Device, it sends that key over the protected channel
and the Device host installs it. Publish a Device credential update as one
complete transition so that a failure can't leave part of the old credential
active with part of the new one. The paired Device accepts a software-held
voucher HMAC secret or an opaque handle owned by the host. For replacement,
provide a fresh handle and stage the replacement separately.

The paired DI roles use host-owned authorization and persistence.
`FdoDeviceInitializeSession.RunAsync` uses an
`IFdoDeviceInitializeTransport` bound to one manufacturing session. Before
sending `DI.AppStart`, `IFdoDeviceInitializeHandler.AuthorizeAndReserveAsync`
must authorize the station and reserve the Device without replacing an active
credential or an unresolved attempt. `DeviceMfgInfo` is lookup metadata and
does not authenticate the Device. The manufacturer handler must authorize the
actual Device and station relationship and validate its certificate chain and
binding independently of that metadata.

The manufacturer handler durably retains a proposal before
`DI.SetCredentials` and the matching zero-entry voucher before `DI.Done`.
The Device handler validates the proposed credential against host policy and
stages it with its opaque HMAC-secret handle before HMAC computation and
`DI.SetHMAC`. It atomically installs that credential only after a valid
`DI.Done`. The host must create the secret with a cryptographically secure
random source, protect it, and persist the handle. The station cannot verify
the received HMAC without the Device secret.

An interrupted DI response can leave the manufacturer with a retained voucher
while the Device has not installed its credential. A callback that throws or
is canceled may already have changed durable state, and a confirmed handoff
doesn't prove Device receipt. Reconcile both sides before another attempt, using
the local run IDs and the separate callback, message, and handoff observations.
The library does not retry, resume, overwrite an active credential, or
regenerate a proposal on the host's behalf.

The proposal generates a random 16-byte FDO GUID and defaults to a
Device-applicable `rvserver.local` DNS directive. Custom rendezvous information
must contain that directive, even if a later TO2 run explicitly bypasses
rendezvous. The roles check the structure of the remaining rendezvous
instructions, but the host must validate their semantics and policy. The paired
DI implementation supports ECDSA P-256 and P-384 Device attestation keys and
X.509-encoded ECDSA or RSA initial Owner keys. It selects HMAC-SHA-384 if either
key is P-384; otherwise it selects HMAC-SHA-256. The Device host supplies the
secret handle before receiving the header and must know the authorized station's
key type. Both roles explicitly select the provisional header HMAC convention.
This paired path is not independent interoperability evidence.

The resulting voucher has no transfer entries. Paired TO2 requires at least
one. `FdoOwnershipVoucherTransfer.Extend` for ECDSA and `ExtendRsa` for RSA
accept a retained zero-entry or previously transferred voucher, the current
Owner signing key, and an explicitly approved new Owner public key. Each checks
all prior entries, binds the signer to the final current Owner, and appends one
signed entry without changing the prior entry bytes, header, HMAC, or
certificate chain. A later entry hashes the exact previous tagged entry and
retains the verified previous-entry hash algorithm; the first transfer selects
SHA-256 or SHA-384 from the voucher HMAC. Owner key types, signature algorithms,
and RSA sizes must match throughout the chain. The helper
checks the Device certificate-chain hash, but does not establish certificate
or voucher trust and cannot verify the Device-held header HMAC.

The host authorizes the voucher and the new Owner key, prevents concurrent or
conflicting transfers, and durably retains the encoded result and its exposed
components before handoff. An uncertain persistence outcome requires
reconciliation before retrying. The complete extended voucher must fit the
65,535-byte and 255-entry limits.

After transfer, the host can pass
`FdoDeviceInitializeCredential.VoucherHmacSecret` to
`FdoDeviceSessionOptions.VoucherHmacSecretHandle`, along with the credential's
GUID, manufacturer-key hash, and HMAC algorithm. The Device checks the handle's
reported algorithm and size before computing the HMAC over the received header.
The host retains the handle and must not use it concurrently with the session.
A failed check ends the run before voucher-entry requests; the header remains
untrusted until the complete voucher verifies. Local provisioning without the
DI exchange is not implemented.

The paired direct TO0 Owner registers a voucher and one TO2 address through
`FdoOwnerRendezvousSession` and a host-supplied `IFdoRendezvousTransport`.
`FdoRendezvousServerSession` processes either TO0 or TO1. The Owner and server
check the ordered voucher, pinned manufacturer key, Device certificate chain,
and Owner signature; the server cannot verify the Device's voucher HMAC
without its secret. The host chooses the transport and binds each request to
one session. The Owner and Device signing keys remain host-owned. The paired
HTTP runner and server binding also support these TO0 and TO1 exchanges.

The direct path publishes one record per Device GUID through
`IFdoRendezvousRegistrationStore`. Protect each field, bound storage, and
replace a record as one durable update. When the server receives the Device
proof, it rejects an expired record or a change from the record it read for
the challenge. A replacement can still occur after that read. If host policy
requires the record to remain current through response handoff, serialize the
handoff with replacements. Reconcile a failed callback, cancellation, or
uncertain handoff before another write because the record may already exist.

The delegated path uses `IFdoAtomicRendezvousRegistrationStore`. It keeps
the direct Owner record separate from each Delegate record and binds writes
to the observed `OwnerSign` source and an authenticated identity. The source
address selects a slot; the host authorizes the write. A compare-and-swap
revision fences replacement, and an exact mutation receipt lets the host
reconcile an uncertain write. The
[delegated Rendezvous guide](FdoDelegatedRendezvous.md) describes the store
and admission contract.

The expiration time is exclusive. The server floors the whole seconds
remaining after the store returns and sends no acceptance if less than one
second remains. Storage may already have succeeded. A one-second requested or
maximum lifetime can therefore fail with an advancing clock; the host must
choose a lifetime that leaves time for storage and handle any stored record.

`FdoDeviceRendezvousSession` retrieves an `FdoDeviceRendezvousResult` after
the server verifies the Device's nonce-bound attestation proof. The result
contains untrusted candidate addresses and the exact signed redirect. The
Device host applies network policy and selects the transport; TO1 failure
does not authorize bypass. The Device can use each result for only one TO2
session. It verifies the redirect with the voucher-proven Owner key or an
authorized Delegate before deriving the protected channel. For multiple
addresses in a delegated blob, the host selects an index and the Device
checks the transport's declared origin before using the result. The signed
address at that index must match before the Device accepts the redirect.

When both sides opt in to delegated discovery and the server allows batches,
`RunBatchAsync` caches up to eight null-preference blobs. The server reads one
ordered snapshot and rechecks the revision, record contents, and expiry for
each `RVMore` request. It can resend the last page once for an exact repeated
request while the snapshot is still valid. A repeat of the final page also
requires the HTTP host to retain the binding and token within the session's
lifetime. The Device returns no candidates until it has cached every page.
The host selects a blob and address before TO2; the library doesn't choose
either or retry a request.

The public `FdoDeviceSession` runs that TO2 exchange through a host-supplied
`IFdoDeviceTransport`. The public `FdoOwnerSession` processes encoded requests;
the host binds requests to the session, bounds bodies while reading them, and
confirms each response handoff. The paired HTTP runner carries these messages
without exposing a raw protected send. Both peers explicitly enable the intended
credential disposition and the provisional paired profile. The Device chooses either the TO1
result or explicit bypass. The Owner enables one or both routes, but TO2
messages do not reveal which route the Device used. The Owner uses a pinned
manufacturer key and Device certificate trust anchor, with the revocation
behavior selected by the host. The manufacturer key comes from an independently
trusted source, not from a received voucher. `FdoPublicKeyCodec.Encode` converts
the public part of a P-256 or P-384 `ECDsa` key to the FDO PublicKey encoding;
`EncodeRsa` converts a supported RSA key. Neither conversion authenticates the
key.

The paired roles support ECDH, Linux DH, and ASYMKEX with the Owner key types
selected for each suite. Both hosts explicitly enable the provisional DH or
ASYMKEX profile. The ASYMKEX Device host independently provisions the final
RSA Owner public key before the exchange. The Device compares that key with
the voucher-authenticated Owner before protected messages; the Owner validates
the Device proof before decrypting its exchange parameter. The exact choices
and their limits are recorded under
[Provisional wire decisions](#provisional-wire-decisions).

`FdoRendezvousInfo.Parse` reads the encoded RendezvousInfo from a Device
credential, and `ParseVoucherHeader` reads it from an encoded voucher header tag.
Neither method authenticates its input. The parser returns role-applicable HTTP
or HTTPS base addresses in directive order, with DNS before IP and the original
zero-based directive index. It requires a Device-applicable `rvserver.local`
directive and checks the structure and duplicates before filtering by role.
It ignores valid directives and assigned variables that apply only to the
other role. It rejects unsupported applicable instructions rather than
returning a candidate that doesn't meet the configured conditions. The input
limits are 65,535 bytes, 256 directives, and 16 instructions per directive.

How does a host walk the directives without the library opening connections on
its behalf? `FdoRendezvousInfo.ParseDirectives` groups the same candidates by
directive and accepts `RVDelaysec` (13) as a uint32 value; it rejects a
delay-only directive and every other unsupported condition, and `Parse` keeps
rejecting delays. `FdoRendezvousAttemptPlan` is a host-stepped state machine
over those directives. The host supplies an attempt budget from 1 to 65,536, an
absolute deadline, a `TimeProvider`, and optionally the jitter source. `Next`
returns one attempt, a wait with an absolute not-before time, a reconciliation
request, or a terminal step. The plan never sleeps, resolves names, or
connects, and it counts a declined attempt against the budget.

The delay rules are provisional interpretations of the specification. A directive's
delay applies once, after the host has tried all of that directive's
candidates. A directive that belongs only to the other role adds no delay.
After the last applicable directive, the plan waits 120 seconds with ±25%
jitter unless that directive specifies a delay; an explicit delay, including
0, replaces the default and receives the same jitter. When the next wait would
reach the deadline, or the budget is spent, the plan reports exhaustion with
the unshortened not-before time rather than shortening a delay.

Each offered attempt must be reported as succeeded, failed, declined,
uncertain, or stopped, in order. The deadline controls admission only; the plan
does not cancel an attempt that is already running, so the host bounds
in-flight I/O with its own cancellation. Once a TO0 run starts, a failure or
cancellation cannot prove that the Rendezvous Server stored no registration, so
the TO0 step helper reports it as uncertain. The plan then offers no further
attempt until the host calls `Reconcile` with succeeded, failed, or stop.
Cancellation known before the run starts, including cancellation requested
inside the authorization or session callback, reports stop without a request.
A TO1 network failure or an HTTP status the binding does not permit is
reported as failed and returned to the caller; the helper does not retry, and
a later candidate needs another host step and authorization. A TO1 redirect is
a terminal handoff: it is reported as stop and returned unfollowed, because
following it is host policy. A malformed or oversized response, an
authorization-token violation, or an unexpected local failure is also reported
as stop, so the plan does not advance past a failure it cannot classify as
ordinary.

`FdoHttp.RunDeviceRendezvousStepAsync` and `RunOwnerRendezvousStepAsync` take
one plan step over the paired HTTP binding. They call the host's authorization
callback for each candidate URI, report a refusal as declined without
connecting, require a new, unstarted role session from the host's factory, and
use a new HTTP client for each attempt. They never change the scheme. This is
URI-only planning: the client resolves the name through the system resolver
and does not expose or pin the address. A host that must control DNS, the TLS
server name, or the admitted address drives `Next` and `Report` itself through
its own `IFdoRendezvousTransport`. TO0 refresh before the accepted wait ends,
redirect handling, and recovery after TO2 stay with the host. The paired
paths do not discover servers automatically, retry requests, or resume a
failed exchange.

`FdoHttp` creates one direct HTTP or HTTPS client session for each paired DI,
TO0, TO1, or TO2 run. The host selects the address and applies network policy;
the client resolves names without exposing or pinning their addresses, so
address-based restrictions must be enforced on the network path. HTTPS uses
platform certificate validation or the host's explicit `FdoHttpPrivateTrust`
configuration for that run. A private root does not replace hostname
validation. The client does not follow redirects or use proxies or cookies.
HTTP alone does not authenticate
the manufacturing station or protect the bearer token. A host that needs mutual
TLS or another transport policy supplies its own role transport. The host can
cancel the run to bound response body reads.

An HTTP 302 or 307 response to `TO1.HelloRV` ends that session and exposes the
absolute, untrusted target in `FdoTransportException.RedirectLocation`. The
FDO specification recommends attempting the redirected URL; the library
leaves that decision to the host. The target may be a full request URI. It can
contain sensitive data. The host applies endpoint and TLS policy, including
scheme changes and redirect-loop limits, before starting a new session. It
must not use a redirect or failed TO1 to enable rendezvous bypass.

`FdoHttpServerSession` owns one corresponding server role. The host rejects
invalid HTTP framing and supplies the raw target, header values, and a
request-framed body stream. The binding checks the method, numeric version and
request type, content type, authorization token, and configured body limit.
The host registers the issued bearer token before sending the first response,
routes later requests to that binding, protects the token, and limits session
count and lifetime. Send the response's `StatusCode` and `Authorization`.
If `EncodedBody` isn't empty, send it as `application/cbor` and include
the returned `MessageType` in the `Message-Type` header.

The host serializes requests with response handoff. After it sends a complete
nonterminal response, it calls `ConfirmResponseSent`; it doesn't confirm an
`IsTerminal` response. If delivery fails or is uncertain,
the host disposes the binding and reconciles any durable effects; a confirmed
handoff does not prove peer receipt. The client sends HTTP/1.1 with a nonempty
single-use body and without `Expect: 100-continue`. The inspected .NET HTTP/1.1
implementation does not retry an EOF after such a body has been sent. The
library does not retry a failed request, follow a redirect, or choose another
protocol version. Independent HTTP interoperability remains unverified.

For client-key enrollment, the Owner invokes
`IFdoOwnerEnrollmentHandler.AuthorizeAndIssueAsync` after verifying the
Device and activating `fdo.csr`. The callback receives detached Device
identity, run, and exact CSR evidence. The Owner validates that the issued
certificate contains the requested public key. After authenticated Done20,
`CommitAsync` records either kind of enrollment before DoneAck20 is produced.
`CommittedEnrollment`, `DoneAckProduced`, and `DoneAckHandoffConfirmed` report
distinct observations. A successful handoff does not establish Device receipt,
and a throwing or canceled commit can have an unknown durable outcome.

The Device may request CA distribution before enrollment by setting
`FdoDeviceSessionOptions.RequestCaCertificates`. After Device authentication
and module activation, the Owner calls `IFdoOwnerCaCertificatesHandler` with
detached identity and format evidence. The handler supplies
`FdoCaCertificates` containing exact DER certificates, CRLs, or both. The
Device exposes the received values through
`FdoDeviceEnrollment.CaCertificates`; the property is null when distribution
was not requested. An absent or rejecting Owner handler ends the run before
issuance. Neither the Owner nor the library installs trust on the Device.

The Device requests CSR attributes by configuring
`FdoDeviceSessionOptions.CsrAttributesHandler` instead of supplying a
`CertificateSigningRequest`. After authenticating the Device and
the request, the Owner calls `IFdoOwnerCsrAttributesHandler` with detached
Device identity. The Device authenticates the response before calling
`IFdoDeviceCsrAttributesHandler.CreateCertificateSigningRequestAsync` with
the attributes, optional CA material, Device run identifier, and intended
enrollment operation. The callback creates or selects the CSR. Client-key
enrollment requires a valid CSR signature. The constructor rejects both
conflicting CSR sources and an absent source.

`FdoCsrAttributes` preserves the DER CsrAttrs sequence and its ordered OID and
Attribute choices, including an empty sequence. It checks the outer structure,
the Attribute value set, nested framing, and common ASN.1 primitives. Attribute
values are open types; their schema and nested SET ordering remain host
responsibilities. The Device host interprets recognized information and
ignores unknown OIDs and attributes. The Owner's issuance handler receives the
sent attributes as evidence but must separately authorize the CSR and cannot
assume that it includes the requested information. If no Owner attribute
handler is configured, the Owner returns `fdo.csr:error` 3 and the Device ends
the run without issuance. The paired order is optional CA distribution,
optional attribute discovery, then the selected enrollment operation.

The response uses the paired canonical padded-Base64 convention and rejects
whitespace. RFC 8951 recommends that EST receivers tolerate Base64 whitespace;
this profile does not establish EST or independent FDO interoperability. The
response must fit one negotiated ServiceInfo message.

The Device selects simple re-enrollment with
`FdoDeviceSessionOptions.RequestReenrollment`. After authenticating the Device
and accepting the protected request, the Owner calls
`IFdoOwnerReenrollmentHandler.GetPriorCertificateAsync`. The host must resolve
the current certificate for the authenticated Device and enrollment scope,
not select it solely from the CSR's claimed identity. The library verifies the
CSR signature and requires exact DER equality for the ordinary subject and
subject alternative name values. Duplicate subject alternative name extensions
are rejected. Matching SubjectPublicKeyInfo values indicate renewal; different
values indicate rekey. A CSR proves possession of its signing key, not of the
prior private key.

If the signed CSR contains `ChangeSubjectName`, the Owner passes its exact DER
value and requested names to `ApproveIdentityChangeAsync` before issuance. An
absent subject requests an empty subject, and an absent subject alternative
name requests removal of that extension. The Owner verifies that the issued
certificate has the prior identity or the approved requested identity. The
host must authorize the request and validate the names and credential policy;
the library checks GeneralName tags, outer structure, and nested DER framing,
but not all type-specific name contents. It does not establish
prior-certificate trust or possession. The checked prior certificate,
classification, and requested change remain detached through issuance and
commit. CA distribution can precede this exchange without changing the
initial-enrollment default.

Server-side key generation requires the Device and Owner hosts to configure
their respective `ServerKeygenHandler` options. After authenticating the
Device, the Owner calls `IFdoOwnerServerKeygenHandler.AuthorizeAndIssueAsync`
with its identity and the exact PKCS#10 request. The request's public key and
signature are ignored and do not prove possession. The host must authorize the
Device and requested identity independently before returning an
`FdoServerKeygenCredential` containing a certificate and unencrypted DER
PKCS#8 private key. The session checks that the key matches the certificate.
The paired implementation accepts RSA and EC keys. If the Owner handler is
absent, it returns `fdo.csr:error` 3 and the Device ends the run. Server-side
key generation cannot be combined with simple re-enrollment.

The response contains the private key in an `application/pkcs8` MIME part.
The following `application/pkcs7-mime; smime-type=certs-only` part contains
one certificate. The paired codec uses exact headers, CRLF boundaries, and
canonical Base64 wrapped at 76 characters. The complete MIME payload is one
CBOR text value. The Owner and Device reject an item or protected message that
exceeds its negotiated limit instead of fragmenting it.
These encoding choices do not establish interoperability with other peers.

The Owner disposes the credential and clears its owned key copy after encoding.
The Device stages the received key, validates the certificate through the
ordinary validation handler, and passes the key to
`IFdoDeviceServerKeygenHandler.InstallAsync` only after authenticated
DoneAck20. The borrowed key is cleared when the callback returns or throws;
the host must protect and clear its own copies. The generic CBOR pipeline may
create transient managed copies that the session cannot explicitly erase.
Neither the Owner commit evidence nor the Device enrollment receipt contains
the private key.

The Device validates the returned certificate through
`IFdoDeviceEnrollmentHandler.ValidateCertificateAsync` before sending Done20;
that callback must not install it or the distributed trust material. The host
must evaluate CA certificate and CRL trust, signature, freshness, and local
authorization policy. After authenticating DoneAck20 and its challenge, the
Device invokes the client-key or server-key installation handler and returns
an enrollment only when the callback succeeds. `DoneAckAuthenticated`,
`InstallationStarted`, and `InstalledEnrollment` expose the Device's
observations. A throwing or canceled installation can have an unknown durable
outcome. The Device and Owner run IDs are locally generated and are not a
shared wire identifier. The host must reconcile issuance, commit, and
installation when a run ends with an uncertain outcome.

The paired ServiceInfo state checks alternating Device and Owner messages,
their negotiated plaintext limits, empty responses while a peer has more data,
and empty keepalives after the Owner signals completion. It checks the Done20
challenge and requires either a null HMAC for reuse or the selected replacement
HMAC algorithm.
Recording Done20 does not commit enrollment or establish DoneAck20 delivery.
The role must authenticate and decrypt received messages before applying this
state.

Batching across rounds is separate from splitting one value. Both roles divide
a logical transfer at complete-entry boundaries into rounds that fit the
peer's plaintext limit and, once sealed, its message limit. Splitting a single
value is module-specific, and neither `devmod` nor the paired `fdo.csr`
profile defines it, so an entry that can't fit an empty message ends the run
with error 100. The receiver answers each round that reports more data with an
empty message and assembles at most 64 entries and 65,535 encoded bytes before
it invokes a module, so it never accumulates unbounded peer data while waiting
for the last round. A session accepts at most 256 request/response rounds,
counting empty polls and post-completion keepalives once per pair, and checks
that cap before it invokes a module or creates another round. The three limits
are library choices.

The in-repository Owner sends one entry per logical response. A controlled
paired-session test injects a multi-round Owner response to exercise the
Owner's queue and the Device's assembly; the fixture skips inventory validation.

ServiceInfo is an ordered key/value exchange. The library must preserve ordering
and encoded value types, including opaque byte-string contents, and permit empty
exchanges. It must not infer a payload transfer encoding from an application
media type. Application-specific effects belong to modules rather than the
protocol state machine.

## Cryptographic and framework feasibility

The Base Profile sets different cryptographic obligations by role. Device
attestation uses ECDSA with P-256 or P-384. Ownership Vouchers use SHA-256 or
SHA-384, HMAC-SHA-256 or HMAC-SHA-384, RSA2048RESTR or RSAPKCS keys and
signatures, or ECDSA P-256 or P-384 keys and signatures. RSAPSS is not part of
the Base Profile voucher signature set. The Owner and Rendezvous roles verify
all required voucher combinations; the Device verifies at least one.

For TO2, section 1.7.6 says components "SHALL support" the listed session
cryptography, and its Owner requirement is "Generate and verify any combination
of the above." This includes ECDH256,
ECDH384, DHKEXid14, DHKEXid15, ASYMKEX2048, and ASYMKEX3072 with the specified
AES-GCM, AES-CCM, or AESPlainType plus HMAC-SHA-256 or HMAC-SHA-384 protection.
The Device must implement and verify at least one key-exchange choice and one
protection choice. These are normative role requirements, not a recommendation
to negotiate only the algorithms convenient to one runtime. An AES-GCM-only
Owner cannot serve a permitted AES-CCM-only Device and does not meet the complete
Owner requirement.

Microsoft documents AES-GCM, AES-CCM, ECDH, ECDSA, RSA, SHA-2, and HMAC APIs
for .NET Standard 2.1. `AesGcm` and `AesCcm` are public types in the
`netstandard2.1` reference assembly, despite missing entries in the installed
XML documentation. API availability is separate from runtime platform support:
.NET 10 supports AES-GCM on Windows, Linux, and macOS, but its `AesCcm` does not
support macOS.

Neither .NET Standard 2.1 nor .NET 10 exposes a supported managed finite-field
Diffie-Hellman API. `ECDiffieHellman` implements elliptic-curve DH, not
DHKEXid14 or DHKEXid15. Section 3.7.1 specifies a 2048-bit modulus with 256-bit
private exponents for DHKEXid14, and a 3072-bit modulus with 768-bit private
exponents for DHKEXid15, using RFC 3526 parameters and generator 2. These
obligations prevent a complete Owner implementation using only the available
.NET cryptography APIs on either target.

Section 3.7.1 assigns exponent `a` to the Owner and `b` to the Device, but
then describes the Device sending `A = g^a` and the Owner sending `B = g^b`.
Its shared-secret equations likewise use the other assignment. The
paired DH exchange assigns A to the Device and B to the Owner; this choice
does not resolve the specification ambiguity for independent peers. For ECDH,
section 3.7.3 describes the opposite A/B roles from the FDO 2.0 message
definitions in sections 5.5.6 and 5.5.7. The selected 2.0 path follows those
message definitions: the Device sends A and the Owner sends B.

Calling an operating-system provider is a separate implementation choice from
using only managed .NET cryptography APIs:

| Platform | Native facility | Evidence limit |
|---|---|---|
| Windows | CNG documents finite-field DH with custom modulus and generator in the OS-supplied `Bcrypt.dll`. | The documented generation APIs do not establish control over the private-exponent size. A private-key import includes both the exponent and its public value; it does not establish a way to generate that pair with the required size. |
| Linux | OpenSSL documents the RFC 3526 `modp_2048` and `modp_3072` groups and a `priv_len` parameter. | `priv_len` sets a maximum, not a guaranteed number of significant bits. OpenSSL 3.0.16 uses default group bounds of 225 and 275 bits unless configured. Distribution availability, ABI, and FDO's intended interpretation of exponent size remain to be verified. |
| macOS | The checked public CryptoKit and SecKey APIs expose no finite-field DH operation. CommonCrypto's DH and CCM declarations are private SPI. Apple's Security source also contains a `SecDH` header. | `SecDH`'s current SDK inclusion, symbol exports, exponent behavior, and peer validation are unverified. Current OS-bundled `libcrypto`/LibreSSL presence, symbols, loadability, supported ABI, and maintenance status remain unverified. |

The absence of a documented public API in the macOS surfaces checked does not
prove that no OS binary can perform finite-field DH. Likewise, .NET 10 removing
its OpenSSL backend on macOS does not establish that Apple removed its system
libraries. An OpenSSL provider shipped with the application or installed
separately would be an additional provider, not an OS-only implementation.
A Windows/Linux-only Owner does not satisfy the required three-OS scope.

The `SecDH` source header accepts a prime and generator and describes its
private-key length parameter as a minimum, not an exact size. It also describes
a shared-secret output without leading zero bytes. The header alone does not
establish a supported application API, exact FDO exponent behavior, peer-key
validation, or the required secret representation on current macOS releases.
Apple states that `corecrypto` is not a developer interface.

For OpenSSL 3.0.16's named groups, the configured private length is an upper
bound: the implementation samples a value from
`[1, min(2^N - 1, q - 1)]`. Values with fewer significant bits can occur. The
FDO wording specifies 256- and 768-bit private exponents but does not establish
here whether an upper-bounded random value satisfies that wording. A group name
alone also leaves the implementation's shorter default bounds in effect.

`BigInteger.ModPow` does not document constant-time execution for secret
exponents. Building DH over it would be a custom cryptographic implementation,
not a supported .NET DH API. AES-CTR is also absent from the BCL's `CipherMode`
options. The selected direction uses OpenSSL on Linux and public Windows or
macOS cryptographic APIs on the respective platforms where managed APIs are
insufficient. Windows has no documented CNG CTR mode, so the library uses one
construction there: CNG AES-ECB encrypts the counter blocks, and managed code
builds only the NIST SP 800-38A counter sequence and the XOR. Other custom CTR
constructions, managed AES block ciphers, and private Apple SPI are not
approved. The FDO KDF composition uses .NET HMAC.

Apple's public [CommonCryptor header](https://github.com/apple-oss-distributions/CommonCrypto/blob/a0ac082c490b65585ade764511acfdbf1d97bc5e/include/CommonCryptor.h)
declares a CTR mode and a mode-specific cryptor API. .NET does not expose
that API. Its availability in current SDKs, counter behavior against FDO's
nonce and counter format, and NativeAOT interop remain unverified. It does not
resolve the macOS CCM or finite-field DH gaps.

The paired Linux DH exchange generates private exponents of exactly 256 or
768 bits, calculates the public value with OpenSSL's constant-time modular
exponentiation API, and imports the pair into EVP. It checks the imported group
and key pair, requires each peer value to be in the group range and subgroup,
and consumes the private key after one agreement attempt. Public values and
shared secrets use fixed-width unsigned big-endian bytes: 256 bytes for group
14 and 384 bytes for group 15. Section 3.7.1 does not specify those encodings;
they are a paired choice, not an interoperability result. Targeted Linux x64
tests on .NET 10 and 11 exercised both groups and the paired TO2 exchange with
OpenSSL 3.0.13. The tests do not establish provider isolation or end-to-end
timing behavior. Windows rejects paired DH; macOS DH and macOS NativeAOT
behavior remain unverified.

A Windows CNG private blob requires both the public value and the private
exponent. The documented import does not establish how to generate that pair
with the selected exponent length. An independent diagnostic using the
Microsoft Primitive Provider generated eight keys per group: one group 14 key
had the required 256-bit private exponent, and no group 15 key had a 768-bit
exponent. The library must reject a combination it cannot support instead of
silently choosing a weaker suite.

The OpenSSL 3.0.16 source examined above is historical evidence, not a
deployment recommendation. OpenSSL's [release policy](https://openssl-library.org/policies/releasestrat/)
lists version 3.0 as out of support without extended support. A provider
comparison found that [OpenSSL 3.5](https://docs.openssl.org/3.5/man7/EVP_PKEY-DH/)
documents the required DH groups and AES modes, but its native distribution
and FDO-specific behavior need validation. Its
[November 24, 2026 advisory](https://openssl-library.org/news/secadv/20261124.txt)
says releases containing the listed fixes are scheduled for December 1, 2026.
The fixes and every feature used by a deployed build need review before a
version is selected. The
[Bouncy Castle C# DH agreement](https://github.com/bcgit/bc-csharp/blob/release-2.7.0/crypto/src/crypto/agreement/DHBasicAgreement.cs)
calls modular exponentiation whose
[implementation](https://github.com/bcgit/bc-csharp/blob/release-2.7.0/crypto/src/math/BigInteger.cs)
uses an exponent-dependent sliding window. Its use for DH therefore needs a
side-channel decision. OpenSSL is selected for missing Linux primitives and
backs the internal DH implementation described above.

A temporary Windows managed and `win-x64` NativeAOT probe against OpenSSL 3.5.9
exercised both DH groups with padded secrets, AES-128/256 CTR, and AES-128/256
CCM. It matched published CTR and CCM vectors and checked CCM tamper rejection.
DH key management and the cipher fetches reported the default provider; the
probe did not identify the exchange provider, exchange FDO messages, or
establish interoperability. For both DH groups, the named-group public-key
check and peer setup accepted `p-2`, which the probe also found to be outside
the subgroup. The provider's
[source](https://github.com/openssl/openssl/blob/openssl-3.5.9/providers/implementations/keymgmt/dh_kmgmt.c)
uses partial validation for named safe-prime groups. Whether FDO requires a
subgroup check remains unresolved; a successful public-key check must not be
assumed to establish subgroup membership. OpenSSL 3.5.9's
[exchange implementation](https://github.com/openssl/openssl/blob/openssl-3.5.9/providers/implementations/exchange/dh_exch.c)
also defaults to unpadded secrets, a path its
[DH implementation](https://github.com/openssl/openssl/blob/openssl-3.5.9/crypto/dh/dh_key.c)
describes as not constant-time. The required FDO secret encoding remains open.
The same built-in DH method uses the constant-time flag on its private exponent
for public-key generation and, with its normal cache flag, secret derivation.
That does not establish an end-to-end timing guarantee. The selected provider,
key generation, secret conversion, and platform-specific paths still need review.

The paired implementation uses ECDH, DH, or ASYMKEX with AES-GCM, AES-CCM,
AES-CTR and HMAC, or AES-CBC and HMAC where the platform supports the required
operations.
`AesCcm.IsSupported` must be checked at runtime; .NET 10 does not support it on
macOS. Targeted AES-CCM tests passed on Linux with .NET 10 and 11, but macOS
execution remains unverified. Section 4.4 describes an AES-CTR IV as a 12-byte
random session nonce and a big-endian four-byte counter starting at zero. An
internal AES-CTR primitive uses OpenSSL on Linux, CommonCrypto on macOS, and CNG
AES-ECB with the managed counter construction on Windows. It has a 65,535-byte
input limit and a 32-bit counter-wrap check. The Windows path encrypts at most
64 counter blocks per CNG call and clears its counter and keystream buffers.
Its caller must authenticate ciphertext and avoid reusing counter blocks. The
OpenSSL implementation uses the process's default library context, not an
isolated provider configuration. Linux x64 tests with .NET 10 and 11 and OpenSSL
3.0.13 matched AES-128 and AES-256 vectors for full and partial blocks. macOS
execution remains unverified. The opt-in encrypt-then-MAC TO2 profile in
[Provisional wire decisions](#provisional-wire-decisions) allocates counter
blocks across messages.

The project targets `net10.0` and `net11.0`; .NET Standard 2.1 is no longer a
target. Both targets have built and run tests on Windows. Both have also run
targeted tests on Linux x64, including paired CBC exchanges with ECDH, DH, and
ASYMKEX. Paired onboarding scenarios have run under NativeAOT on Windows and
Linux x64 for both targets.

Section 3.7.4 specifies SP800-108 counter-mode HMAC derivation with a one-byte
counter and a two-byte big-endian output length. The .NET
`SP800108HmacCounterKdf` uses four-byte fields for both and cannot be called
directly for this derivation. The library composes the required framing with
.NET HMAC for SHA-256 and SHA-384.
It writes key material to a caller-owned buffer and rejects output lengths that
exceed the counter or length-field limits. For encrypt-then-MAC, a helper
derives the combined length once and splits the result as `SVK || SEK`, as
specified in section 3.7.4. It clears the intermediate buffer; the caller must
validate the supplied hash and key lengths for the selected suite and clear the
two output buffers. The helper does not select a suite or encrypt messages.

The specification's non-normative Appendix B also says `SEVK = SEK || SVK`.
That summary uses the combined-key name and the opposite order, while section
3.7.4 defines `SEVK` separately for authenticated encryption and specifies
`SVK || SEK` for encrypt-then-MAC. The helper implements only the latter split.
Its tests include published mathematical vectors and independently derived
ECDH-GCM vectors, not verified FDO 2.0 interoperability vectors. The absence
of an `HKDF` helper in the older reference is not a blocker for this requirement.

The internal `Hash`/`HMac` component represents the section 3.3.4 array and
checks the algorithm identifier and full hash length. It uses .NET SHA-256,
SHA-384, HMAC-SHA-256, and HMAC-SHA-384 and compares values in fixed time after
checking the caller-selected algorithm. The caller supplies the exact bytes
for the protocol operation and applies algorithm and key policy. An expected
unkeyed digest must come from an authenticated source. The component does not
validate Ownership Vouchers or manage the HMAC secret.

The Ownership Voucher header HMAC helper computes or checks `OVHeaderHMac` over
the CBOR-encoded `OVHeader` bytes inside the `OVHeaderTag` byte string. It
excludes the outer byte-string header and length, as section 3.4.2 requires.
The caller selects HMAC-SHA-256 or HMAC-SHA-384. The helper does not parse the
header or set secret-length policy. Section 3.4.1 defines `DCHmacSecret` as a
random byte string but does not give its length. Section 2.7's size table lists
256 bits for HMAC-SHA-256 and 512 bits for HMAC-SHA-384; non-normative
Appendix B lists 128 and 512 bits. The helper leaves the selected policy to its
caller. Tests cover wrapper exclusion, algorithm selection, changed inputs, and
malformed wrappers.

The internal COSE signing-input component encodes the
[RFC 9052 section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4)
`Sig_structure` for COSE_Sign1:
`["Signature1", body_protected, external_aad, payload]`. Section 3.3.8 sets
`external_aad` to the CBOR encoding of `FDOExternalAAD`, and its table assigns
one `FDODomainTag` to each of the six signing operations: to1d in
`TO0.OwnerSign`, `TO1.ProveToRV`, `TO2.ProveDevice20`, `TO2.ProveOVHdr20`,
`TO2.SetupDevice20`, and each OVEntry. Section 3.3.8 reserves further array
elements for later specifications but defines none, so the component encodes a
one-element array. FDO does not transmit `external_aad`; the signer and the
verifier each construct it from the operation they expect, and a different
operation produces a different signing input. The component copies the received
protected-header and payload byte-string contents without re-encoding them,
because the signature covers those exact bytes. Byte-string headers use the
shortest length encoding required by RFC 9052 section 9.

The component does not parse a COSE_Sign1 message, check the `#6.18` tag,
interpret headers, select an algorithm, or sign or verify. Its tests compare
against byte sequences hand-encoded from the two structure definitions, not FDO
interoperability vectors.

The internal signature primitive signs and verifies ES256, ES384, RS256, and
RS384 with the BCL. It requires the caller's operation, algorithm, and key; it
checks that the protected header contains only the matching algorithm and
returns a copy of a verified payload. The caller must validate the COSE envelope
and its unprotected headers, the payload semantics, FDO key-type restrictions,
key trust, and protocol state. It must also enforce EAT prefix policy: the
primitive does not support a non-empty `MAROEPrefix`. This primitive does not
authenticate a peer or verify a voucher chain. Other protected-header shapes
and signature algorithms remain unsupported.

The COSE_Sign1 codec frames tag 18 around an alg-only protected header, an
empty unprotected map, a CBOR payload byte string, and the signature. It checks
one definite-length embedded payload without re-encoding it. Other unprotected
headers, including an explicitly present empty or non-empty EAT `MAROEPrefix`,
are rejected. Section 3.3.18 says an absent or empty prefix uses ordinary
signing, but does not establish how a non-empty prefix combines with the
COSE signing input and the FDO external data. The specification does not define
how to validate the application identity represented by the prefix. Protected
header profiles outside voucher entries also need clarification. The codec
does not establish peer trust or validate operation-specific claims or nonces.
Whether deterministic encoding applies inside the payload byte string remains
open.

The Base Profile requires ECDSA P-256 or P-384 for Device attestation. Its
voucher signatures exclude RSA-PSS, although the specification defines an
`RSAPSS` key type without assigning it a COSE signature algorithm. The
signature primitive does not enforce the Base Profile's key-type policy;
role-level validation must apply it.

The public-key codec accepts ECDSA P-256 and P-384, RSA2048RESTR, and RSAPKCS
keys encoded as X.509 SubjectPublicKeyInfo. The voucher verifier checks the
version-200 header, ordered entry signatures and hashes, and the final Owner
key. It requires the Owner key type and signature algorithm to remain
consistent across the chain. On the Device, it also checks the provisioned
GUID, manufacturer-key hash, and header HMAC. For an Owner, internal
consistency does not establish manufacturer or Device trust. The verifier can
match an ordered Device certificate chain to the hash in the same header, but
it does not validate that chain or its trust.

The paired Device proof codec checks the EAT signature, GUID, nonce, selected
suites, and hashes of the exact probe and acknowledgement. The Owner-side
authenticator binds that proof and its certificate chain to a checked voucher
and requires an explicit Device trust policy. Its pinned policy checks the
manufacturer key and the ordered certificate path against a configured trust
anchor; the host selects revocation behavior. `NoCheck` skips revocation
checks. The authenticator rejects a certificate whose Key Usage extension
excludes digital signatures. These checks do not authorize the Device for
enrollment, and the caller must supply the fresh acknowledgement from the
current run. Returned evidence contains detached copies rather than exposing
the authenticator's retained buffers.

The paired Owner proof codec checks the Owner's signature and nonce using the
advertised key. It checks the Device credentials and requires every voucher
entry to verify before returning that key and the signed exchange parameter.
The proof checks the parameter's field lengths. ECDH and DH validate the peer
point or public value when deriving the shared secret; ASYMKEX validates its
ciphertext during decryption. Before signing its proof, the Owner must verify
the Device and confirm that the signing key is the voucher's final Owner key.
Enrollment authorization occurs separately after module activation. The
direct Owner path requires at least one voucher entry. When both sides opt
in to delegated TO2, the Device verifies the Delegate chain and proof as
well as the voucher Owner binding, then obtains host approval before
deriving keys. A delegated TO1 redirect goes through a separate host
approval; its signer need not be the TO2 proof signer. Without an explicit
host selection to bypass Rendezvous, the Device verifies the exact TO1
redirect before using the protected channel.

The ECDH component creates one-use P-256 or P-384 key pairs, checks peer points
through the runtime provider, and forms `Shx || DeviceRandom || OwnerRandom`.
It does not authenticate the signed exchange or the voucher. The AEAD primitive
supports A128GCM, A256GCM, and distinct AES-CCM algorithms where available.
The provisional AES-GCM and AES-CCM COSE_Encrypt0 codec uses the exact
protected-header bytes in its associated data. It does not own nonces, prevent replay, establish
trust, or connect encryption to TO2 transport. A separate paired-profile channel
assigns role-specific nonces, rejects replayed or out-of-order counters, and
requires alternating messages. It closes and clears its key copy on a failed
cryptographic operation or state check. Roles must authenticate the key,
validate message semantics, and dispose the channel after a transport failure
or ambiguous delivery.

Neither selected target has a verified complete three-OS cryptographic path.

The project enables NativeAOT analysis. The test-only `tests\Fdo.AotSmoke`
executable completed paired DI, transfer, discovery, TO0, TO1, and protected
TO2 over loopback HTTP on Windows and Linux x64 with .NET 10 and 11 NativeAOT.
The scenarios use generated credentials and cover ECDH with GCM, CTR, or CBC
and ASYMKEX with CBC. Linux also ran DH14 with CBC and DH15 with CTR, using
OpenSSL 3.0.20. Windows rejected both DH groups before TO2. The
`delegated-replacement` scenario covers delegated TO2, voucher X5CHAIN,
offline Delegate status, and credential activation with direct HTTP TO0
and TO1. Linux also ran `direct-rsa-combined-offers`, which selects the
non-primary DH14 and CBC encrypt-then-MAC offers. These NativeAOT runs
do not establish HTTPS behavior, delegated discovery, durable recovery,
or independent interoperability. They also do not establish provider
isolation, timing conformance, or compatibility for untested paths.
See [qualification](FdoQualification.md)
for the separate managed HTTPS evidence. A native publish used for
verification does not authorize NuGet publication.

The approved CBOR dependency is Microsoft's `System.Formats.Cbor`. The internal
codec uses `Canonical`, not `Ctap2Canonical`, for an enclosing FDO value with
byte, nesting, and item limits, and rejects indefinite lengths. It preserves
received message-body bytes and extracts byte-string payloads without rewriting
the contents to be hashed or signed. HTTP metadata and a checked body are
reconstructed as a StreamMsg structure. An initial-message codec checks the
TO0 and TO1 CBOR array shapes, reserved first-byte capability bits, and GUID or
nonce lengths. It preserves additional capability bytes and vendor-string order,
but does not validate reverse-domain notation or authorize vendor capabilities.
These received TO0 and TO1 fields are untrusted; that codec does not negotiate
a version, authenticate a peer, or manage role state.

The internal Device Initialize codec frames `DI.AppStart`,
`DI.SetCredentials`, `DI.SetHMAC`, and `DI.Done` and checks the outer
voucher-header shape. The paired roles validate selected fields and call the
host-owned authorization, HMAC, and persistence interfaces described above.

Embedded manufacturing information is checked for deterministic, definite-length
CBOR; the specification does not explicitly settle whether the deterministic
rule applies inside that byte string. Byte, depth, and item limits apply
independently to the message and the embedded value.

The TO2 initial codec frames the probe and acknowledgement, checks the selected
paired-profile transcript hashes and offered suites, and retains the exact bytes
for those checks. It does not verify a Device proof or establish trust. The TO2
completion codec frames the selected Done20 and DoneAck20 plaintext bodies.
The TO2 ServiceInfo codec frames the provisional Ready and Device messages and
the Owner ServiceInfo body. Neither codec authenticates or decrypts messages,
decides a disposition, or performs a credential transition.

The paired SetupDevice20 codec supports credential reuse and provisional
replacement. For reuse, the verified voucher Owner or an authorized
Delegate signs. For replacement, the Owner signs with a distinct
Owner2 key and includes the Device's Ready nonce in the replacement
credentials. The Device verifies the Owner2 signature and nonce after opening
the channel established with the voucher-proven Owner. Each disposition must
be explicitly allowed. The codec does not authenticate the protected channel,
enforce message order, or update credentials.

The ServiceInfo codec preserves entry order, repeated keys, and each encoded
value inside its byte-string wrapper. It checks each wrapped value as one
definite-length CBOR item without enforcing deterministic encoding within that
wrapper. Whether the section 3.1 deterministic-encoding rule applies to the
embedded value remains open. Limits on depth and item count apply independently
to the envelope and each wrapped value. The codec does not interpret modules,
authenticate the sender, or select a text transfer encoding.

The x5chain codec reads and writes the certificate-chain representation in the
[COSE X.509 draft referenced by FDO](https://www.ietf.org/archive/id/draft-ietf-cose-x509-08.html#section-2).
One certificate is encoded as a CBOR byte string; two or more are encoded as
an array of byte strings. The codec retains the byte-string contents and their
order, applies byte and item limits, and copies input before returning it. It
does not parse X.509 certificates, check their integrity protection, validate a
certificate path, or establish trust. Its tests use framing examples rather
than real certificates.

The certificate-chain hash primitive hashes the ordered certificate contents,
excluding their CBOR wrappers. Its expected digest must come from an
authenticated source; a match does not establish certificate or supply-chain
trust.

FDO section 3.4.2 defines `OVDevCertChain` as `X5CHAIN` and
`OVDevCertChainHash` as `Hash`, with comments that earlier versions used null.
The same section's prose describes a null chain with a null hash. Its hash
example depicts an array without addressing the single-certificate form. The
referenced COSE definition specifies a byte string for one certificate. The
codec implements that COSE representation and rejects CBOR null; it does not
determine whether null is permitted in the enclosing FDO fields. Those fields'
null handling and the example's intended scope need clarification.

The `System.Formats.Cbor` 10.0.0 source compares encoded map keys for
uniqueness. [RFC 8949 section 5.6.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.6.1)
also treats differently encoded values as equivalent keys: integer zero can use
different widths, and `+0.0` and `-0.0` are equivalent. The codec compares
scalar keys by value, including floating-point zero and NaN significands. It
rejects a map containing two array keys, two map keys, or two tagged keys until
compound-key comparison is implemented. Application-specific key and tag
semantics need separate validation.

The specification uses `authtoken` in StreamMsg without defining its CDDL type.
Local HTTP authorization values can be represented as text, but that does not
restrict the direct-stream wire type. The codec preserves an opaque encoded
token and distinguishes an absent token from a token encoded as CBOR null.
Direct-stream interoperability remains subject to a wire definition or reliable
vector.

Section 3.1 requires length-first deterministic encoding, while section 3.2
permits longer integer encodings. The outer codec follows section 3.1.
Section 4.4's table and CDDL name AES-CCM-64 variants, while nearby prose,
section 3.7, and the appendix name AES-CCM-16 variants. These are distinct COSE
algorithms: RFC 9053 assigns values 30 and 31 to the 13-byte-nonce variants and
32 and 33 to the 7-byte-nonce variants. The library must not alias them. The
messages carrying algorithm-selection arrays also remain unclear.

Section 5.1.1 defines `EMErrorCID` as `uint`, while its prose permits
`EMErrorUuid` to be null. The `timestamp` definition names `TIME_T`, but the
declaration uses `TIMET`. The UTC and Device-local integer choices both use
tag 1 and therefore have the same wire representation. The general Error body
and timestamp interpretation need clarification. The paired profile frames
a restricted subset. TO2 seals its Errors only after key exchange; TO0 has
one narrower exception for a verified `OwnerSign` that lacks Redirect
permission. Other earlier failures don't produce protocol Errors.

The HTTP examples in sections 5.5.8, 5.5.10, 5.5.12, and 5.5.14 use `/62`,
`/66`, `/68`, and `/70` for requests whose headings label them types 84, 86,
88, and 90, respectively. Section 5.5.5 labels `TO2.HelloDeviceAck20` type 81
and describes it as an acknowledgement, but its HTTP context shows `POST /101`.
Section 5.5.6 gives no HTTP example for the type-82 request.

The `TO2.Done20` CDDL lists only `NonceTO2ProveDv` while the prose describes a
`ReplacementHMac` field. Sections 5.5.10 and 5.5.12 also place a replacement
HMAC in earlier messages; the first placement precedes receipt of the
replacement credentials. The selected Done20 form does not settle those
earlier fields. No verified FDO 2.0 vector or authoritative resolution has
been identified. The discrepancies are tracked in
[#1](https://github.com/marcschier/fdo/issues/1).

[FIDO App Note 8](https://fidoalliance.org/specs/fidoiot/fdo-appnote-8-voucher-aad-versioning-v1.0-20261001.html#rule)
gives conflicting rules for selecting the `to1d` signature's external AAD.
Its general rule uses the Ownership Voucher's `OVProtVer`, while its
`to1d`-specific rule uses the current session's protocol version. For a
version-101 voucher in a version-200 session, these select different signing
inputs. The OVEntry-specific rule uses the voucher version. Mixed-version
voucher support is outside the current paired profile; the `to1d` rule needs
clarification before adding it.

## Provisional wire decisions

These paired-profile choices address specification conflicts. They are not a
published erratum or interoperability evidence.

- **HTTP paths.** Use `/fdo/200/msg/{message-type}` and the numeric 2.0 message
  headings. Section 4.3 defines the version numerically and the suffix as the
  message type, but its template shows `102pre` and some TO2 examples use
  earlier suffixes. The transport does not retry another version or path.
  The internal generic HTTP sender blocks types 86, 88, and 90. The paired
  runner carries those types only through the Device role and its authenticated,
  replay-checked channel. Error uses `/fdo/200/msg/255` rather than the
  prerelease examples in section 5.1.1.
- **Paired TO0 and TO1.** Rendezvous instructions use
  `[uint8 variable, bstr .cbor value]`. A nondelegated `RVTO2Addr` has five
  fields: an IPv4 or IPv6 byte string or null, a DNS name or null, a nonzero
  port, HTTP or HTTPS, and null preference. At least one address is required;
  four-field and null-port forms are rejected. The Owner signs `to1d` using
  the version-200 TO0 domain and hashes the exact contents of the `to0d` byte
  string, excluding its wrapper. `DelegateChain` is a byte string containing
  CBOR null on the direct path. TO1 uses the version-200 Device-proof domain
  and returns `[1, 0, [to1d]]` for one blob, preserving its signed bytes.
  The opted-in delegated path accepts up to three ordered addresses in a
  blob and eight blobs per lookup, all with null preferences. `RVMore`
  uses `/32`, distinguished from `ProveToRV` by the session phase. Each
  response gives its first index and the snapshot's total count. The server
  does not add preferences to a signed blob. The server accepts known 1.x
  version bits alongside 2.0 in a received Hello, then selects only 2.0.
  The Device accepts the same known version bits in `TO1.HelloRVAck`
  and continues on 2.0. It uses delegation only if requested and advertised
  by both sides. TO0 acknowledgements and `OwnerSign` still require the
  exact paired flags, and vendor extensions are not enabled. These choices do not
  resolve the specification's conflicting address and instruction forms.
  The parser rejects unsupported instructions applicable to the role;
  `ParseDirectives` accepts delays, but `Parse` still rejects them. Owners use HTTPS
  and `RVOwnerPort`. Devices use `RVProtocol` and `RVDevPort`; `RVProtRest`
  selects HTTPS. When the protocol is omitted, the parser selects HTTP for
  Device port 80 and HTTPS for port 443 or an omitted port. A nonstandard
  Device port requires an explicit protocol. The specification's variable
  table names TLS as the default, while its examples use HTTPS and infer HTTP
  from port 80; the paired choice does not resolve that discrepancy.
- **Error body subset.** Encode an unsigned 16-bit code, an unsigned 8-bit
  previous message ID, a non-sensitive description, a null timestamp, and a
  numeric correlation ID. The sender draws a fresh random 64-bit correlation
  ID for each Error, independent of the HTTP token. The codec rejects Error in
  response to Error. Non-null timestamps and null correlation IDs are not
  decoded by this subset; received descriptions remain untrusted. No peer
  interoperability is established.
- **Protected TO2 Error.** After key exchange, section 4.4 protects every
  later TO2 body, so a role seals its Error on the live channel and consumes
  the next directional counter. It never falls back to plaintext. The
  receiver authenticates the Error before reading it and accepts it only when
  its previous message ID names the message actually in flight. A role sends
  nothing when the peer's message doesn't authenticate or the channel has
  failed, because the peer couldn't bind such an Error to the session. The
  Owner returns its Error with HTTP 500; the Device posts its Error and
  requires an empty HTTP 200. Neither role answers an Error with an Error,
  retries, or opens a new run. Codes are 100 for structure or limit failures,
  101 for authenticated semantic rejection, 102 only for credential reuse
  denial, and 500 for unexpected local failures. Voucher and signature
  failures that prevent authentication produce no Error.
- **TO0 Error 104.** If the `OwnerSign` voucher, nonce, hash, Delegate chain,
  leaf signature, and configured trust checks pass, but the verified
  Delegate lacks Redirect permission, the server sends one terminal Error
  with HTTP 500 and the existing token. It sends fixed text, doesn't call host
  admission, and doesn't write a record. Other pre-key rejections have no
  protocol Error body.
- **TO2.Done20.** Use type 90 and encode the nonce followed by
  `ReplacementHMac`, using null for credential reuse and the replacement HMAC
  for credential replacement. The provisional type-86 and type-88 bodies keep
  the earlier HMAC field and require it to be null. These wire choices do not
  determine the credential transition.
- **TO2 transcript hashes.** For the provisional 2.0-only paired profile,
  calculate `hashPrev` over the exact HelloDeviceProbe body using the selected
  offered hash, as section 5.5.5 describes. Section 5.5.4 instead says to append
  the encoded manufacturer-key Hash before hashing; the library must not retry
  with that variant after a verification failure. Signed ProveDevice20 must bind
  `hashPrev2` to the exact HelloDeviceAck20 bytes, including the validated
  `hashPrev` and offers, using the same selected hash algorithm. The paired
  roles use these checks, which do not replace Device certificate or
  supply-chain trust.
- **DH key exchange.** Both roles explicitly select `UseProvisionalPairedDh`.
  The Device sends A and the Owner sends B using RFC 3526 group 14 or 15 and
  generator 2. The private exponents have exactly 256 or 768 significant bits,
  respectively. A, B, and the shared secret are unsigned big-endian byte
  strings, padded to the group width of 256 or 384 bytes. The exchange checks
  the peer value's range and subgroup and consumes each private key after one
  agreement attempt. Section 3.7.1 does not specify the byte encoding and
  assigns the A/B roles inconsistently. This paired choice does not resolve
  either question for other peers. It currently requires Linux and OpenSSL 3.
- **ASYMKEX.** Both roles explicitly select `UseProvisionalPairedAsymkex`.
  Before the exchange, the Device host independently provisions the final RSA
  Owner's CBOR-encoded FDO public key through
  `EncodedAsymkexOwnerPublicKey`. The Device encrypts its random with RSA-OAEP
  using SHA-256, MGF1-SHA256, and an empty label. The Owner authenticates the
  Device proof before decrypting it. Both randoms are 32 bytes for ASYMKEX2048
  or 96 bytes for ASYMKEX3072. The KDF uses the Device random as `ShSe` and
  the Owner random as `ContextRand`. Before sending protected data, the Device
  requires the provisioned key type, algorithm, modulus, and exponent to match
  the authenticated voucher Owner. The provisioned key is not learned from the
  unauthenticated acknowledgement. These choices do not establish independent
  interoperability.
- **RSA Owner suite binding.** DHKEXid14 and ASYMKEX2048 require RSA2048RESTR
  or 2048-bit RSAPKCS with RS256. RSA2048RESTR also requires exponent 65537.
  DHKEXid15 and ASYMKEX3072 require 3072-bit RSAPKCS with RS384. The Owner key
  type and signature algorithm remain consistent throughout the voucher chain.
- **Ownership Voucher entry hashes.** For the first entry, hash the exact
  `OVHeader` byte-string contents followed by the encoded `OVHeaderHMac`. For
  each later entry, hash the complete preceding tagged COSE_Sign1 entry.
  Hash the raw 16-byte GUID followed by UTF-8 DeviceInfo for the header-info
  field. Sections 3.4.2, 3.4.3, and 3.4.6.1 support this chain, while section
  5.5.9 describes conflicting inputs. The verifier does not retry another
  interpretation after a mismatch. It currently requires the previous-entry
  hash algorithm to remain the same across entries; that restriction needs
  review before broader interoperability.
- **COSE_Encrypt0.** For the provisional paired profile, use tag 16 and
  `[bstr({1: alg}), {5: iv}, bstr(ciphertext || tag)]`. The AEAD associated
  data is `["Encrypt0", exact protected bstr, h'']`. Section 4.4 depicts a
  protected map rather than the byte string used by RFC 9052 and the examined
  peer sources. The codec accepts the selected algorithm and IV shape only.
  For explicitly paired peers, the channel uses a zero-padded big-endian role
  identifier (Device 0, Owner 1) followed by a four-byte big-endian counter.
  The IV has 12 bytes for GCM, 13 bytes for CCM-16, and 7 bytes for CCM-64.
  Each direction starts at zero and the channel accepts only the peer's next
  counter. A role must use a fresh key for each run, abort after transport
  ambiguity, establish peer trust, and validate protocol state and message
  contents before using plaintext. Other nonce strategies are not supported.
- **Encrypt-then-MAC.** The host must explicitly select
  `CS_AES128_CTR_HMAC-SHA256` (-17760704), `CS_AES256_CTR_HMAC-SHA384`
  (-17760706), `CS_AES128_CBC_HMAC-SHA256` (-17760703), or
  `CS_AES256_CBC_HMAC-SHA384` (-17760705); none is chosen as a fallback.
  The KDF uses the suite's hash and splits its output as `SVK || SEK`, as
  section 3.7.4 specifies, with a 32-byte SVK and 16-byte SEK or a 64-byte SVK
  and 32-byte SEK. The 64-byte SVK
  follows section 3.7.4 rather than the 48-byte HMAC 384/384 key in RFC 9053.
  Each message is a tagged COSE_Mac0 (tag 17),
  `[bstr({1: macType}), {}, bstr(inner), tag]`, where macType is 5 for
  HMAC-SHA-256 and 6 for HMAC-SHA-384, and the MAC input is
  `["MAC0", exact protected bstr, h'', inner]`. The inner value is a tagged
  COSE_Encrypt0 (tag 16), `[bstr({1: suite}), {5: iv}, bstr(ciphertext)]`,
  with a 16-byte IV. Section 4.4 depicts protected headers as maps; both levels
  use the RFC 9052 serialized-map byte string. The receiver verifies the tag
  in fixed time over the exact received inner bytes before it parses or decrypts
  them. For CTR, each direction uses a random 12-byte prefix fixed for the
  session and a four-byte big-endian block counter that starts at zero and
  continues across messages. A message reserves one block per started 16 bytes
  of plaintext and at least one block, so an empty message does not reuse a
  counter block. The Owner selects a prefix different from the Device's; either
  side rejects a peer prefix equal to its own, a changed prefix, a counter other
  than the next expected one, or a reservation past 2^32 blocks. CBC uses .NET
  AES with PKCS#7 padding and a fresh random IV per message. The channel tracks
  IVs from both directions, rejects reuse, and permits at most 2,000,000
  protected messages in one run. Any failure closes the channel. CBC
  authentication and padding failures return the same exception without an
  inner exception, but the implementation has not established the
  processing-time behavior required by section 4.4. For CTR, go-fdo's FDO 1.1
  implementation differs: it splits the key SEK first, uses 16- or 32-byte
  HMAC keys, sends an untagged
  inner value, carries IDs -65534 and -65532 in the unprotected header, and
  draws a random IV per message. Interoperability with any other peer has not
  been verified.
- **DI.SetHMAC.** Compute the HMAC over the `OVHeader` byte-string contents,
  as in section 3.4.2. Section 5.2.2 instead refers to the whole
  `DI.SetCredentials` body, while section 5.2.3 refers to the `OVHeader` tag.
  The Device holds the secret and can later verify the voucher HMAC; an Owner
  receiving the HMAC does not thereby obtain that secret.
- **Device HMAC secret length.** Use the section 2.7 table: 256 bits for
  HMAC-SHA-256 and 512 bits for HMAC-SHA-384. Non-normative Appendix B instead
  lists 128 bits for HMAC-SHA-256. The internal policy helper generates a
  software-held secret of the selected length, and the DI raw-key method rejects
  other lengths. The Device DI role checks the reported algorithm and size of
  its host-owned opaque secret handle before computing the HMAC, as does the
  paired TO2 Device. Credential and handle persistence remain host
  responsibilities. The general HMAC helper leaves key policy to its caller.
- **DI.DeviceMfgInfo.** Send a `bstr .cbor any`; encode absent information as
  `41 F6`, a byte string containing CBOR null. Accept either wrapped or bare
  null as absent, and reject other non-byte-string values. This chooses the
  section 5.2.1 CDDL while accommodating its null prose.
- **`fdo.csr` certificate formats.** Select
  `application/pkix-cert` for simple enrollment and
  `application/pkcs7-mime; smime-type=certs-only` for the server-key-generation
  certificate part. The module calls the latter identical to the former despite
  naming different formats. The paired implementation uses these separate
  formats; it does not accept them interchangeably. The ordinary `tstr`
  transfer encoding and fragmentation remain unspecified.
- **Paired `fdo.csr` text.** An explicitly selected profile represents each
  enrollment, re-enrollment, CA distribution, or CSR attributes DER payload as
  canonical padded RFC 4648 Base64 in one CBOR text value. Unknown peers do not
  use it by default. It rejects oversize items rather than fragmenting; the role
  must also check the final protected size. This convention does not resolve
  the FSIM's unspecified transfer encoding.
- **Paired `devmod` batching.** The Device may send its `devmod` inventory
  across several ServiceInfo rounds, each carrying complete entries with
  IsMore set on all but the last. The Owner answers each partial round with an
  empty message and validates the nine required entries only after the final
  round. FDO 2.0 doesn't state whether `devmod` may span rounds, so this
  interpretation is provisional.
- **Paired `fdo.csr` activation.** The Device advertises the module through
  `devmod`; the Owner sends `fdo.csr:active=true`. The Device may report
  availability and send its request in the same outgoing ServiceInfo batch.
  Availability does not authorize enrollment, and the host must not issue a
  certificate before the role authenticates the Device and activates the
  module. This profile follows FDO 2.0 sections 3.9.3 and 3.9.3.1 rather than
  the earlier FSIM example in which the Device initiates activation. The
  internal Device module prepares a request after activation or obtains it
  from the host after attribute discovery. It accepts a matching certificate
  only after the caller records that the request was sent. The certificate
  remains pending; trust, authorization, protected transport, and completion
  are not implemented by the module. The Device session does not invoke
  installation if ServiceInfo processing or the channel fails.
- **Paired CA distribution.** The Device requests format 281 after activation,
  before optional CSR attribute discovery and enrollment or re-enrollment.
  The Owner returns a DER certs-only CMS version 1 container with X.509
  certificates and CRLs; at least one is required. The parser requires
  `id-data`, an absent encapsulated content field, and an empty signer set.
  It rejects other certificate and revocation choices and does not accept BER containers.
  Format 287 is not implemented. The Owner sends `fdo.csr:error` 5 for an
  unsupported format. The library parses CRLs with the .NET CRL decoder and
  retains their exact bytes, but does not verify their signatures, freshness,
  or trust. The host decides whether to use or install each value.

The go-fdo pull requests
[#279](https://github.com/fido-device-onboard/go-fdo/pull/279) and
[#282](https://github.com/fido-device-onboard/go-fdo/pull/282) describe a
`/fdo/200/msg/{type}` path and TO2 types 80 to 91. Pull request 282 cites an
"Errata 1" when it places `ReplacementHMAC` in Done20. The branch source at
commit `f50e237` encodes Done20 as `[NonceTO2ProveDv, ReplacementHMAC]`. A Rust
client by the same author also uses `/200`, routes 84, 86, 88, and 90, and a
two-field Done. Both implementations come from one author, and no published
Errata 1 has been found. The official download page still lists the April 2026
Proposed Standard. go-fdo pull request
[#285](https://github.com/fido-device-onboard/go-fdo/pull/285) says its open
`fdo20-core-split` branch passes interop tests with other FDO 2.0 clients, but it
does not name those clients or include a captured vector. The branch README at
commit `304fcdb` documents `/fdo/200/msg/N`. We have not tested against any of
these implementations. Their reports identify possible peers to investigate,
not independent interoperability evidence for this library or a specification
resolution.

## `fdo.csr` ServiceInfo and enrollment

The [FIDO Alliance module repository](https://github.com/fido-alliance/fdo-sim)
describes its modules as defined for FDO 1.1; a separate 2.0 revision or adoption
has not been established. Its simple-enrollment exchange has the Device send a
PKCS#10 CSR in `simpleenroll-req` and the Owner return an X.509 certificate in
`simpleenroll-res`; the CSR signature proves possession of the Device key.
Proof of possession does not by itself authorize an application or complete
onboarding.

Simple enrollment alone is not full-module support. CA-certificate distribution
and simple re-enrollment must not be called optional. In
[fido-alliance/fdo-sim#24](https://github.com/fido-alliance/fdo-sim/issues/24#issuecomment-1348654899),
the module author identifies only server-side key generation and CSR attributes
as optional. The module text permits a constrained Device to implement either
client-side or server-side key generation and explicitly makes CSR-attribute
discovery optional. Its CA distribution section requires the
`application/pkcs7-mime; smime-type=certs-only` format, value 281, and makes
`application/pkix-cert`, value 287, an optional format. Its re-enrollment section
requires the CSR Subject and SubjectAltName fields to match the prior
certificate, even when the signed `ChangeSubjectName` attribute requests
different names for the new certificate. The host must locate the prior
certificate for the authenticated Device and scope and explicitly approve any
requested change. Matching public keys indicate renewal; different keys
indicate rekey. Neither comparison proves possession of the prior credential.
A successful response uses `application/pkix-cert`. Those obligations remain
independent of the selected enrollment path.

Server-side key generation returns a private key in a MIME part without
additional object-level encryption. The paired implementation relies on its
protected FDO channel; the Owner host must protect any connection to an
enrollment service. Authorization and durable key custody remain host
responsibilities. The library doesn't recover an uncertain installation
automatically. Use the [host recovery guide](FdoHostRecovery.md) to
reconcile the retained evidence before starting a new session.

The module declares simple-enrollment values as CBOR `tstr` while naming PKCS#10
and DER X.509 payloads. It does not specify their text transfer encoding in those
sections. Neither the media types nor the server-key-generation MIME example
establish a normative base64 or PEM representation for simple enrollment.
[fido-alliance/fdo-sim#38](https://github.com/fido-alliance/fdo-sim/issues/38)
requests clarification and interoperable CBOR vectors. Encoding remains
unresolved until authoritative evidence is available.

[fido-alliance/fdo-sim#35](https://github.com/fido-alliance/fdo-sim/issues/35)
also remains open: the module lacks a specified way to carry payloads larger
than a ServiceInfo message MTU. Sections 5.5.12 and 5.5.13 require each item to
fit in one message, and section 3.9.1 leaves repeated-key meaning to the module.
The eventual module must report a size failure when an item exceeds the peer's
limit, rather than inventing a split. These limits prevent a full-module
interoperability statement at this stage.

The host must bind issuance and policy changes to an authenticated TO2 run using
durable correlation between the run, Device identity, and issued certificate.
Delivering `simpleenroll-res` is not the completion or authorization event. A
confirmed failure before the Device reaches `TO2.Done20` leaves its previous FDO
credentials in place; staged enrollment authorization must be withdrawn and
issued certificates handled according to the certificate-authority policy.

`TO2.Done20` and `TO2.DoneAck20` are distinct events. For `DispResale`, the
specification places the replacement FDO credential transition at
`TO2.Done20`; credential reuse and
disabling FDO have different dispositions. The Owner records authenticated
receipt of `TO2.Done20` separately from sending the final acknowledgement.
When possible, section 5.5.15 recommends delaying `TO2.DoneAck20` until
agent-to-server communication is established. Some Devices need an earlier
acknowledgement because they cannot maintain FDO while establishing that
communication.

The provisional paired implementation uses a different activation point. The
Device validates replacement values, obtains a fresh opaque HMAC secret from
its host, and stages the replacement before sending `TO2.Done20`. The Owner
commits the replacement voucher before the separate enrollment commit and
returns `TO2.DoneAck20` only after both callbacks succeed. The Device verifies
the acknowledgement and Ready nonce before asking its host to activate the
staged credential and make FDO dormant. This post-acknowledgement activation
differs from sections 5.5.11 and 5.5.14 and does not establish conformance.
The host must reconcile uncertain callback outcomes and delivery before another
run; the library cannot roll back a durable host operation or infer its result
from an exception. The replacement voucher can be committed while enrollment
commit fails, or both can be committed while the Device has not authenticated
the acknowledgement.

The paired wire form sends null replacement HMAC fields in messages 86 and 88
and the replacement HMAC in `TO2.Done20`. Section 5.5.10 places an HMAC before
the replacement values are supplied, section 5.5.12 places it in the first
message 88, and section 5.5.14 describes it in `TO2.Done20` while omitting it
from that message's CDDL. These choices do not resolve the specification
conflict. The replacement Owner key must be distinct and currently must use the
voucher Owner's FDO key type and signing algorithm. The Owner retains the HMAC
received over the authenticated channel; it cannot verify the Device's
host-owned secret.

If agent-to-server communication is required before the acknowledgement, a
blanket gate on all application channels until `TO2.DoneAck20` would deadlock.
The host can permit a narrowly authorized, durably correlated
post-Done channel for that connectivity check. It must not grant general
registration or privileged operations through that provisional channel.
Finalization and compensation require an explicit policy that accounts for
which event each side actually observed.

The host needs a durable, versioned record that binds the TO2
run and its authenticated Device evidence to the exact CSR and SPKI, the
subject and SANs approved under policy, the enrollment request, and the issued
certificate. It must connect the certificate's public key and names to the
approved request before delivery or promotion.

For issuance, delivery, proof of possession, promotion, and later privileged
operations, the host must compare the version and FDO outcome in the same
transaction that records the intent, then check both again when committing
the result. Those checks do not bring external effects into the record
transaction. The host must serialize or fence conflicting operations where
possible and retain enough state to reconcile effects after an abort, restart,
or concurrent transition. Recovery and compensation require explicit policy.
An unobserved effect is not a confirmed failure.

Policy remains open for concurrent TO2 runs, retries after a terminal outcome,
and approval of re-enrollment subject or SAN changes within the module's
requirements. The paired Owner API is an initial integration boundary rather
than a complete FDO implementation.

An unreceived `TO2.DoneAck20` does not show that the Device kept its old
credentials. Nor does an unreceived `TO2.Done20` prove that the Device never
sent it. The Owner must retain the correlated outcome and reconcile uncertainty
under its operational policy; this design does not prescribe a retry, rollback,
or other recovery protocol absent from the specification.

## Release boundary

The [release workflow](FdoRelease.md) publishes a preview for evaluation.
Publication does not establish Base Profile conformance or expand the
[verified support](FdoQualification.md). The project is licensed under the
[MIT License](../LICENSE). Check redistribution notices for any third-party
material shipped with the release.

## Sources

- [FDO 2.0 Proposed Standard](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html), especially §1.7 Base Profile, §§3.1 and 3.3, and §§5.5.10–15.
- [`System.Formats.Cbor` map-key checks at the package build commit](https://github.com/dotnet/dotnet/blob/b0f34d51fccc69fd334253924abd8d6853fad7aa/src/runtime/src/libraries/System.Formats.Cbor/src/System/Formats/Cbor/Reader/CborReader.Map.cs) and its [key-encoding comparisons](https://github.com/dotnet/dotnet/blob/b0f34d51fccc69fd334253924abd8d6853fad7aa/src/runtime/src/libraries/System.Formats.Cbor/src/System/Formats/Cbor/CborConformanceLevel.cs).
- [`fdo.csr` FDO ServiceInfo Module](https://raw.githubusercontent.com/fido-alliance/fdo-sim/main/fsim-repository/fdo.csr.md).
- [RFC 6402 Change Subject Name attribute](https://www.rfc-editor.org/rfc/rfc6402.html#section-2.8).
- [RFC 9053 COSE AES-CCM algorithms](https://www.rfc-editor.org/rfc/rfc9053#section-4.2).
- Module clarification: [fido-alliance/fdo-sim#24](https://github.com/fido-alliance/fdo-sim/issues/24), [fido-alliance/fdo-sim#35](https://github.com/fido-alliance/fdo-sim/issues/35), and [fido-alliance/fdo-sim#38](https://github.com/fido-alliance/fdo-sim/issues/38).
- [.NET AES-GCM API](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-10.0), [.NET AES-CCM API](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesccm?view=net-10.0), and [.NET ECDH API](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdiffiehellman?view=net-10.0).
- [.NET SP800-108 counter KDF](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sp800108hmaccounterkdf?view=net-10.0) and [.NET incremental HMAC](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.incrementalhash.createhmac?view=net-10.0).
- [.NET 10 HTTP/1.1 connection retry handling](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Net.Http/src/System/Net/Http/SocketsHttpHandler/HttpConnection.cs).
- [.NET cross-platform cryptography support](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography) and [.NET NativeAOT deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).
- [Windows DH parameter API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_parameter_header), [Windows DH key blob](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob), and [OpenSSL DH API](https://docs.openssl.org/3.0/man7/EVP_PKEY-DH/).
- OpenSSL 3.0.16 [private-key generation](https://github.com/openssl/openssl/blob/openssl-3.0.16/crypto/ffc/ffc_key_generate.c), [named-group defaults](https://github.com/openssl/openssl/blob/openssl-3.0.16/crypto/ffc/ffc_dh.c), and [DH key generation](https://github.com/openssl/openssl/blob/openssl-3.0.16/crypto/dh/dh_key.c).
- [Apple Security key types](https://developer.apple.com/documentation/security/item-attribute-keys-and-values), [CryptoKit AES](https://developer.apple.com/documentation/cryptokit/aes), and Apple's [`SecDH` source header](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecDH.h).
- CommonCrypto's private [DH](https://github.com/apple-oss-distributions/CommonCrypto/blob/main/include/Private/CommonDH.h) and [cipher](https://github.com/apple-oss-distributions/CommonCrypto/blob/main/include/Private/CommonCryptorSPI.h) headers, and Apple's [`corecrypto` developer-interface statement](https://github.com/apple/corecrypto/blob/main/README.md).
- [.NET 10 removal of its macOS OpenSSL backend](https://learn.microsoft.com/en-us/dotnet/core/compatibility/cryptography/10.0/openssl-macos-unsupported).
