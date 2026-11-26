# Host the FDO roles

The paired FDO roles enforce message order and verify signatures over the
exact encoded data. Your application authorizes peers and destinations, keeps
credentials and registration state, and reconciles a run when one side may
have committed without the other side receiving the response.

Start with the [loopback example](../README.md#quick-start) to see the roles
run together. Use this guide to replace the example's temporary keys and
callbacks with your own host policy and storage.

- [Initialize the Device](#paired-device-initialization) and [transfer its voucher](#voucher-transfer).
- [Register and discover an Owner](#paired-owner-registration-and-device-discovery).
- [Enroll the Device and retain or replace its credential](#paired-device-and-owner-enrollment).
- [Choose a framework and cryptographic suite](#framework-target).
- [Host the HTTP binding and apply message limits](#transport-and-encoding).

## Where your application plugs in

| Role | Start with | What the host supplies |
|---|---|---|
| Manufacturer | `FdoManufacturerInitializeSession` | An independently authorized Device and station relationship, Device chain policy, and a store for the proposal and zero-entry voucher. |
| Device | `FdoDeviceInitializeSession`, `FdoDeviceRendezvousSession`, `FdoDeviceSession` | The attestation key, opaque voucher secret, destination policy, and certificate validation and installation callbacks. |
| Owner | `FdoOwnershipVoucherTransfer`, `FdoOwnerRendezvousSession`, `FdoOwnerSession` | The approved voucher and signing key, Device trust and issuance policy, and durable enrollment and replacement commits. |
| Rendezvous | `FdoRendezvousServerSession` | An HTTP listener or role transport, token routing, registration storage and expiry, and admission policy for delegated writes. |

Use the [integration design](FdoIntegrationDesign.md) for the trust
boundaries, message flow, and choices that require paired peers. The focused
guides explain [delegated Rendezvous](FdoDelegatedRendezvous.md),
[private CA trust for HTTPS](FdoPrivateHttpsTrust.md),
[offline Delegate status](FdoOfflineDelegateRevocation.md),
[voucher keys encoded as X5CHAIN](FdoVoucherX5Chain.md), and
[recovery after uncertain writes or delivery](FdoHostRecovery.md).

## Paired Device initialization

The public `FdoDeviceInitializeSession` and
`FdoManufacturerInitializeSession` implement the non-normative DI example for
paired peers. DI does not authenticate either peer. The Device host must
authorize the station bound to its `IFdoDeviceInitializeTransport` and reserve
the Device before sending `DI.AppStart`. The manufacturer host must authorize
the actual Device and station relationship independently of `DeviceMfgInfo`,
which is untrusted lookup metadata. It must validate the Device certificate
chain and its relationship to that Device.

The Device host supplies an `IFdoDeviceInitializeHmacSecret` handle. It must
generate and protect the secret and persist the handle; the library does not
request the key bytes. The selected HMAC is SHA-384 if either attestation or
manufacturer key is P-384; otherwise it is SHA-256. The respective secret
sizes are 64 and 32 bytes. The host selects the handle before receiving the
header and must know the authorized station's key type. Both roles must set
`UseVoucherHeaderHmac` to select the same
[provisional HMAC input](FdoIntegrationDesign.md#provisional-wire-decisions).
The `StageAsync` callback receives the complete proposed credential and handle
before the Device computes its HMAC. The host must validate the proposal
against its policy, retain it as pending, and install it atomically through
`InstallAsync` only after a valid `DI.Done`.

The manufacturer host creates and durably retains a proposal in
`AuthorizeAndPrepareAsync`, then retains the matching zero-entry voucher in
`PersistVoucherAsync` before the session produces `DI.Done`. It cannot verify
the Device's HMAC without the Device secret. The host confirms each response
handoff with `ConfirmResponseSent`; confirmation does not prove Device receipt.
The host uses `FdoManufacturerInitializeProposal.CreateRsa` when the initial
Owner has an RSA key.
The proposal defaults to a Device-applicable `rvserver.local` DNS directive.
Custom rendezvous information must retain that directive even when a later
TO2 run explicitly bypasses rendezvous.
The roles check the local DNS requirement and the structure of the remaining
rendezvous instructions, but the host must validate their semantics and policy.

Callback failure, cancellation, or uncertain response delivery can leave
durable state on either side. The session exposes reservation, staging,
voucher persistence, handoff, and installation observations; these record
callback returns and message events, not a distributed transaction. The hosts
must reconcile an uncertain run before another attempt. They must not overwrite
an active credential or regenerate an unresolved proposal automatically.
The Device and manufacturer run IDs are local; the FDO GUID is shared in the
voucher and credential.

DI produces a zero-entry voucher. The paired DI wire choices have not been
tested against an independent implementation. Local provisioning without the
DI exchange is not implemented.

## Voucher transfer

Before paired TO2 or a later ownership transfer, the current Owner can pass the
retained voucher, its signing key, and an approved new Owner public key to
`FdoOwnershipVoucherTransfer.Extend` for ECDSA or `ExtendRsa` for RSA. The
method checks every existing entry, binds the signing key to the final current
Owner, and appends one signed entry. It preserves the exact prior entries,
header, HMAC, and certificate chain and hashes the complete previous tagged entry. It
checks the Device certificate-chain hash but does not validate certificate
trust or the Device-held header HMAC. The Device HMAC secret is not needed for
the transfer.

The host must authorize the voucher and new Owner key, prevent concurrent or
conflicting transfers, and retain the encoded result and its exposed components
before handing them to the new Owner. If persistence has an uncertain outcome,
the host must reconcile it before retrying.

The methods accept Owner keys encoded as X.509 SubjectPublicKeyInfo (SPKI)
for ECDSA P-256, ECDSA P-384, RSA2048RESTR, or RSAPKCS. Use
`ExtendWithCertificateChain` to encode an ECDSA Owner key as X5CHAIN. The
first certificate supplies the public key; the other certificates don't
establish trust. The key type and signature algorithm must match throughout
the voucher. The method selects the
SHA family indicated by the voucher HMAC for the first transfer and retains the
verified previous-entry hash algorithm for later transfers. The complete result
must fit the 65,535-byte and 255-entry limits.

## Paired Owner registration and Device discovery

`FdoOwnerRendezvousSession.RunAsync` registers a voucher and signed TO2 address
information through a host-supplied `IFdoRendezvousTransport`.
`FdoRendezvousServerSession` processes one TO0 or TO1 exchange; its host binds
requests to the session, bounds bodies while reading, and confirms each
response handoff. The Owner and server verify the ordered voucher entries,
the pinned manufacturer key, the Device certificate chain, and the final
Owner's signature. The server cannot verify the Device's voucher HMAC without
the Device secret. The paired roles require at least one voucher entry, support
the ECDSA and RSA Owner key types described above, and require explicit
selection of the provisional wire profile.

For direct registration, the host's `IFdoRendezvousRegistrationStore` keeps
one record per Device GUID. Protect all fields, bound storage, and publish
the replacement record as a single durable update. The server reads the
record at the start of TO1 and checks it again when processing the Device
proof. If your application requires the same record through response
handoff, serialize that handoff with replacements. Reconcile before
retrying if a callback fails, the request is canceled, or the response
handoff is uncertain. Any of those outcomes can leave a stored record.

For delegated registration, configure `IFdoAtomicRendezvousRegistrationStore`
and opt in at both roles. The server verifies the Delegate's authority to
sign the redirect. The host supplies the source observed on the `OwnerSign`
request and authorizes the write separately; the source address identifies a
slot, not the submitter's authority to replace it. The atomic store isolates
the direct Owner record from Delegate records. When it applies an authorized
update, it checks that the revision, expiry, and target still match.

Expiration is exclusive. The accepted wait is the number of whole seconds
remaining after the store callback returns, rounded down. If less than one
whole second remains, the server produces no acceptance even if storage
succeeded. A one-second request can therefore fail with an advancing clock;
choose a lifetime that leaves time for storage.

`FdoDeviceRendezvousSession.RunAsync` obtains an
`FdoDeviceRendezvousResult` after proving possession of the Device attestation
key. Its `CandidateAddress` is untrusted: the Device host applies network
policy and chooses a transport before connecting. Pass the result to
`FdoDeviceSessionOptions.RendezvousResult`; it can be used by only one TO2
session. The Device verifies the exact signed redirect with the
voucher-proven Owner key before deriving the protected enrollment channel.
A failed TO1 does not enable rendezvous bypass.

For multiple blobs, enable `AllowMultipleDelegatedRedirects` on the
Rendezvous server and use `FdoDeviceRendezvousSession.RunBatchAsync` or
`FdoHttp.RunDeviceRendezvousBatchAsync` with delegated discovery enabled.
The Device caches up to eight null-preference blobs before returning any
result. Each page refers to the same registration snapshot; a change or an
expired record stops the run. The server can repeat the last page once for
an exact `RVMore` request while the snapshot is still valid. To permit a
repeat of the final page, the HTTP host has to keep that binding and token
available within its session lifetime. The Device runner doesn't retry
automatically.

A delegated blob with multiple addresses requires an explicit
`RendezvousAddressIndex`. The Device checks the transport's declared HTTP
origin before using the result, then verifies that same address in the signed
blob before accepting the redirect. This check does not verify the resolved
IP address. The host still chooses the candidate and admits the connection.

`FdoRendezvousInfo.Parse` reads the encoded RendezvousInfo from a Device
credential. `ParseVoucherHeader` reads it from an encoded voucher header tag.
Neither method authenticates its input. They return role-applicable HTTP or
HTTPS base addresses in directive order, with DNS before IP and the original
zero-based directive index. The parser requires a Device-applicable
`rvserver.local` directive. It validates the structure and checks for
duplicates before ignoring a directive for the other role or an assigned
variable that only applies to that role. The Device still rejects unsupported
applicable instructions, including certificate hashes, network-medium
constraints, bypass, and extensions. `Parse` also rejects delays.
Input is limited to 65,535 bytes, 256 directives, and 16 instructions per
directive.

`FdoRendezvousInfo.ParseDirectives` returns the same candidates grouped by
directive and also accepts the `RVDelaysec` instruction (13) as a uint32
value. It rejects a delay-only directive and every other unsupported
condition; `Parse` still rejects delays. An `FdoRendezvousAttemptPlan` turns
the directives into host-stepped attempts with a required attempt budget (1 to
65,536) and an absolute deadline. `Next` offers one candidate at a time, or a
wait with an absolute not-before time; the plan never sleeps, resolves names,
or connects. The plan applies a directive's delay once, after the host has
tried all its candidates, and adds no delay for directives that belong to the
other role. After the last directive, it waits 120 seconds with ±25% jitter
unless that directive specifies its own delay; explicit delays receive the
same jitter. These delay rules are provisional interpretations of the
specification. When the budget or deadline runs out, the plan reports
exhaustion with the unshortened wait time instead of shortening a delay.

The host reports each offered attempt as succeeded, failed, declined,
uncertain, or stopped. The deadline controls admission only and doesn't cancel
an attempt already in progress. An uncertain TO0 attempt blocks the plan until
the host calls `Reconcile` with succeeded, failed, or stop, because a TO0 run
that has started and then fails can't prove that the Rendezvous Server stored
no registration. `FdoHttp.RunDeviceRendezvousStepAsync` and
`RunOwnerRendezvousStepAsync` take one such step. They ask the host to
authorize each candidate URI, create a new role session and HTTP client for
each attempt, report the outcome, and never change the scheme or follow a
redirect. Cancellation before the run starts reports stop without a request.
A TO1 network failure or disallowed HTTP status reports failed without a
retry; a redirect, malformed response, or unexpected local failure reports
stop. This authorization covers the URI only: the client resolves names
through the system resolver. A host that must control DNS, TLS server name, or
the admitted address drives the plan itself with its own
`IFdoRendezvousTransport`.

The parser does not resolve names or connect. The roles don't schedule TO0
refresh, discover `rvserver.local` automatically, or resume a failed run.
The host makes those decisions using its own network policy and retained
state. The paired wire forms and protocol defaults are recorded in the
[design](FdoIntegrationDesign.md#provisional-wire-decisions).

## Paired Device and Owner enrollment

`FdoDeviceSession` runs one exchange through a host-supplied
`IFdoDeviceTransport`. `FdoOwnerSession` processes the corresponding encoded
requests. The host binds requests to one Owner session, limits incoming bodies
while reading them, and confirms each response handoff. A failed or ambiguous
handoff ends the run; confirmation does not prove Device receipt.

Both roles must explicitly allow a credential disposition and select the
provisional paired profile. When the Owner configures replacement, it selects
replacement even if credential reuse is also allowed. The Device selects exactly
one route: `RendezvousResult` or
`AllowRendezvousBypass`. The Owner enables `AllowRendezvous`,
`AllowRendezvousBypass`, or both. TO2 messages do not reveal which route the
Device used, so an Owner host cannot enforce TO1 use through those options
alone. The exchange supports ECDH256, ECDH384, DHKEXid14, DHKEXid15,
ASYMKEX2048, or ASYMKEX3072 with AES-GCM or AES-CCM when the selected algorithm
is available, or with an explicitly selected AES-CTR or AES-CBC
encrypt-then-MAC suite.
The Device sends its `devmod` inventory and exchanges `fdo.csr` ServiceInfo
for simple enrollment, simple re-enrollment, or opt-in server-side key
generation. The Device can request CA certificates and certificate signing
request (CSR) attributes before enrollment. When the negotiated message
limits require more than one round, the roles send complete entries and
process a transfer only after it has been assembled.

Both roles must set `UseProvisionalPairedDh` for DH or
`UseProvisionalPairedAsymkex` for ASYMKEX. Paired DH currently requires Linux
and OpenSSL 3; Windows and macOS reject it. For ASYMKEX, the Device host also
supplies the independently provisioned, CBOR-encoded FDO public key for the
final RSA Owner in `EncodedAsymkexOwnerPublicKey`. The Device compares its type
and public key with the authenticated voucher Owner before exchanging
protected messages. The Owner verifies the Device proof before decrypting the
ASYMKEX parameter. DHKEXid14 and ASYMKEX2048 require a 2048-bit RSA Owner key;
DHKEXid15 and ASYMKEX3072 require a 3072-bit RSAPKCS Owner key.

Configure `AdditionalCipherSuites` to advertise up to nine supported
alternatives after the required `CipherSuite`. The Device selects its
configured suite, and its signed proof binds the selection to the exact
offer. On Linux, a direct RSA Owner can also configure
`AdditionalKeyExchangeSuite` to offer the size-matched DH and ASYMKEX suites
together. Both exchange opt-ins are required, and the Owner checks that the
voucher and signing key match both suites before advertising them.

Set exactly one of `FdoDeviceSessionOptions.VoucherHmacSecret` and
`VoucherHmacSecretHandle`. The latter accepts the handle retained in the DI
credential. The host retains the handle and keeps it available without
concurrent use until the session finishes. The Device checks its reported
algorithm and key size before invoking it to compute the HMAC over the received
header. The header remains untrusted until the voucher chain and Owner proof
verify. The session snapshots and clears a software-held secret; the caller
protects and clears its own copy. A failed HMAC check or callback ends the run
before the Device requests voucher entries.

Set `FdoDeviceSessionOptions.RequestCaCertificates` to request CA material
before enrollment. The Owner calls the configured
`IFdoOwnerCaCertificatesHandler` only after authenticating the Device and
activating `fdo.csr`. The handler receives detached Device identity and returns
`FdoCaCertificates`, containing DER certificates, certificate revocation lists
(CRLs), or both. The Device exposes these values in
`FdoDeviceEnrollment.CaCertificates` to its validation and installation
callbacks. Without the option, that property is null and enrollment follows
the original exchange.

The paired implementation requests format 281 and accepts DER certs-only CMS
version 1 with X.509 certificates and CRLs. It rejects other certificate or
revocation choices, content-bearing or signed containers, and an empty
container. Format 287 is not implemented; the Owner returns error 5 when a
Device requests an unsupported format. Certificate and CRL decoding does not
establish trust or check CRL signatures and freshness. The host must apply
those policies and decide whether to install the material. The container uses
the paired padded-Base64 convention and must fit one negotiated ServiceInfo
message; it is not fragmented.

To discover CSR attributes, configure
`FdoDeviceSessionOptions.CsrAttributesHandler` and leave
`CertificateSigningRequest` empty. The Owner calls
`IFdoOwnerCsrAttributesHandler` with the authenticated Device identity and
returns its `FdoCsrAttributes` response. The Device calls
`IFdoDeviceCsrAttributesHandler.CreateCertificateSigningRequestAsync` only
after authenticating that response. The Device host interprets recognized
attributes, ignores unrecognized OIDs and attributes, and creates or selects
the CSR. Client-key enrollment requires a signed request. If both a CSR and
the handler are configured, or neither is configured, the Device rejects the
options.

`FdoCsrAttributes` preserves the DER sequence and its OID and Attribute
choices, including an empty sequence. Attribute values are open types: the
library checks their framing and common ASN.1 primitives, while the host
validates the semantics of values it recognizes. The Owner's issuance handler
receives the attributes it sent as evidence, not proof that the CSR contains
them; it must authorize issuance separately. If no Owner attribute handler is
configured, the Owner returns `fdo.csr:error` 3 and this Device ends the run.
When both optional exchanges are selected, the order is CA distribution, CSR
attributes, and then the selected enrollment operation.

The paired response uses canonical padded Base64 in one CBOR text value and
rejects whitespace. RFC 8951 recommends that EST receivers tolerate Base64
whitespace; this paired convention does not establish EST or FDO peer
interoperability. The response must fit one negotiated ServiceInfo message.

Set `FdoDeviceSessionOptions.RequestReenrollment` to send
`fdo.csr:simplereenroll-req` instead of `simpleenroll-req`. The Owner requires
an `IFdoOwnerReenrollmentHandler` to look up the current certificate for the
authenticated Device and enrollment scope. The library verifies the CSR
signature and compares the DER subject and subject alternative name values
with that certificate. It classifies matching SubjectPublicKeyInfo values as
renewal and different values as rekey. These comparisons do not prove
possession of the prior private key; the host must authorize the request and
apply its credential and identity policies.

When the signed CSR includes an RFC 6402 `ChangeSubjectName` attribute, the
Owner calls `ApproveIdentityChangeAsync` before issuance. The callback receives
the exact attribute and requested name values as detached evidence. The Owner
checks the issued certificate against the prior identity or the approved
change before returning it. The library checks the GeneralName structure,
but the host must validate the requested names and their type-specific
contents, certificate trust, and application policy.

Server-side key generation requires
`FdoDeviceSessionOptions.ServerKeygenHandler` and
`FdoOwnerSessionOptions.ServerKeygenHandler`. The Owner calls
`IFdoOwnerServerKeygenHandler.AuthorizeAndIssueAsync` with the authenticated
Device identity and CSR. The CSR public key and signature are ignored, so
they do not prove possession or authorize issuance. The host must authorize
the Device and requested identity independently. If the Owner handler is not
configured, the Owner returns `fdo.csr:error` 3 and the Device ends the run.
This operation cannot be combined with simple re-enrollment.

The Owner handler returns an `FdoServerKeygenCredential` containing one DER
certificate and its unencrypted PKCS#8 private key. The session checks that
the key matches the certificate; the paired path supports RSA and EC keys.
The response carries an `application/pkcs8` part followed by a certs-only
`application/pkcs7-mime` part, with one certificate, in a single CBOR text
value. The selected MIME headers, CRLF boundaries, and wrapped Base64 are
paired choices rather than an interoperability statement. The item and the
protected message must fit their negotiated limits; they are not fragmented.

The session disposes the Owner credential after encoding and clears its owned
private-key copy. The Device validates the certificate before Done20, then
passes the key to `IFdoDeviceServerKeygenHandler.InstallAsync` only after
authenticating DoneAck20. The borrowed key is cleared when that callback
returns or throws. The host must protect and clear any copies it retains.
Generic CBOR processing can create transient managed copies that the session
cannot explicitly erase. Private keys are not included in enrollment receipts.

For client-key enrollment, the Owner verifies the Device proof and configured
trust policy before `IFdoOwnerEnrollmentHandler.AuthorizeAndIssueAsync`
receives detached Device identity and CSR evidence. After authenticating
Done20, the Owner calls `CommitAsync` before producing DoneAck20.
`CommittedEnrollment` records a successful callback return; `DoneAckProduced`
and `DoneAckHandoffConfirmed` record separate observations. A throwing or
canceled commit can have an unknown durable outcome.

The Device calls `IFdoDeviceEnrollmentHandler.ValidateCertificateAsync` before
Done20. The handler must apply certificate trust and local policy without
installing the certificate or distributed trust material. After authenticating
DoneAck20 and its challenge, the Device calls
`IFdoDeviceEnrollmentHandler.InstallAsync` for client-key enrollment or the
server-key installation handler for a generated key.
`DoneAckAuthenticated`, `InstallationStarted`, and `InstalledEnrollment`
distinguish those events. `RunAsync` returns an enrollment only after
installation reports success. A throwing or canceled
installation can have an unknown durable outcome. Owner and Device run IDs are
local identifiers and are not the same wire identifier.

For the provisional paired replacement disposition, configure
`FdoOwnerSessionOptions.Replacement` with a distinct Owner2 signing key,
replacement rendezvous instructions, and an `IFdoOwnerReplacementHandler`.
Configure `FdoDeviceSessionOptions.ReplacementHandler` to accept the
disposition. The Owner signs SetupDevice20 with Owner2 inside the protected
channel established with the voucher-proven Owner. The Device verifies that
signature and the Ready nonce, then constructs the replacement voucher header
from the authenticated original header and the new GUID, rendezvous
instructions, and Owner2 key. The Device host reserves a fresh opaque HMAC
secret and stages the complete replacement without changing the active
credential; the library cannot determine whether distinct handles contain the
same secret. Done20 carries its HMAC over the exact header contents. The
current paired implementation requires Owner2 to use the current Owner's FDO
key type and signing algorithm.

The Owner commits the replacement voucher before committing enrollment and
producing DoneAck20. The Device activates the staged replacement only after
authenticating DoneAck20, then installs enrollment. This paired choice differs
from sections 5.5.11 and 5.5.14, which place the Device credential transition
at Done20. The Device host must leave FDO dormant as part of activation.
If a callback throws or delivery is uncertain, either side can have durable
effects that the other has not observed. A replacement commit can succeed while
enrollment commit fails, and a lost DoneAck can leave the Owner committed while
the Device still has its old credential. A failure before Done20 can leave a
staged but inactive Device credential. The hosts must reconcile these states
without replaying the run. The session observations distinguish callback
starts, successful returns, Done20 sending, and DoneAck authentication; they
do not establish a distributed transaction.

The replacement wire form uses null HMAC fields in messages 86 and 88 and puts
the HMAC in Done20. Section 5.5.12 instead requires it in the first message 88,
and the Done20 CDDL omits it. This paired choice does not resolve that conflict.
Credential reuse remains separately configurable. For delegated TO2, the
Device checks the Delegate proof against the voucher Owner, then applies
separate host approval and disposition permissions. A Delegate that signed
the TO1 redirect does not thereby gain permission to enroll the Device.
Delegated ASYMKEX and `DispDisable` aren't supported. Use the
[recovery guide](FdoHostRecovery.md) to reconcile partial commits before
starting a new session.

## Framework target

The library targets `net10.0` and `net11.0`. Managed and NativeAOT runs cover
selected paths on Windows x64 and Linux x64. Windows rejects paired
finite-field DH; the exact-width DH cases run on Linux with OpenSSL 3.
macOS execution remains unverified. Read the
[qualification notes](FdoQualification.md) before choosing a platform
or suite. A paired run doesn't establish independent interoperability,
provider isolation, or end-to-end timing behavior.

The full FDO 2.0 Base Profile needs finite-field Diffie-Hellman exchanges that
the public .NET cryptography APIs do not expose. .NET 10 `AesCcm` also does not
support macOS. The selected direction uses OpenSSL on Linux, Windows
cryptography on Windows, and macOS cryptography on macOS where managed APIs
are insufficient. The required provider capabilities and FDO wire details
remain incomplete; unsupported combinations are not silently downgraded.
See the [design](FdoIntegrationDesign.md).

<details>
<summary>Cryptographic implementation notes</summary>

FDO's session key derivation uses a one-byte counter and a two-byte output
length. The .NET `SP800108HmacCounterKdf` uses four bytes for each, so it
cannot be used directly for this derivation. The internal KDF composes the
specified input using .NET HMAC-SHA-256 or HMAC-SHA-384. For encrypt-then-MAC,
a helper derives the combined key material and separates the verification key
from the encryption key in the order specified by section 3.7.4. The caller supplies
the hash and key lengths, validates them for the selected suite, and clears
both output buffers. The helper does not negotiate a suite.

The internal FDO `Hash`/`HMac` component encodes the two-field value defined in
section 3.3.4 and uses .NET SHA-256, SHA-384, HMAC-SHA-256, and HMAC-SHA-384.
Comparison rejects an unexpected algorithm and uses a fixed-time byte
comparison when the algorithms match. The caller supplies the exact input
bytes and applies the protocol's algorithm and key policy. An expected
unkeyed digest must come from an authenticated source. The component does not
verify a voucher chain or manage HMAC secrets.

The Ownership Voucher header HMAC helper computes or checks `OVHeaderHMac` over
the CBOR-encoded `OVHeader` bytes inside the `OVHeaderTag` byte string. It
excludes the outer byte-string header and length, as section 3.4.2 requires.
The caller selects HMAC-SHA-256 or HMAC-SHA-384. The helper does not set
secret-length policy or parse the header. Tests cover wrapper exclusion,
algorithm selection, changed inputs, and malformed wrappers.

The internal COSE signing-input component encodes the RFC 9052 `Sig_structure`
for a COSE_Sign1 signature and binds it to one of the six `FDODomainTag` values
in section 3.3.8. The `external_aad` is the CBOR encoding of a one-element array
that contains the tag. FDO does not transmit this value, so the signer and the
verifier each construct it from the operation they expect. The component copies
the protected-header and payload byte-string contents without re-encoding them,
because the signature covers those exact bytes. It does not parse a COSE_Sign1
message, interpret its headers, select an algorithm, or sign or verify a
signature. Its tests compare against byte sequences hand-encoded from the two
structure definitions; they are not FDO interoperability vectors.

A separate internal primitive signs and verifies ES256, ES384, RS256, and RS384
over these inputs using caller-supplied keys. It accepts only a protected header
containing the selected algorithm alone and returns an owned copy of a verified
payload. It does not parse the COSE envelope, validate unprotected headers or
payload semantics, apply FDO key-type restrictions, establish key trust, or
authenticate a peer. It does not support a non-empty EAT `MAROEPrefix`; callers
must enforce the applicable prefix policy. Other signature profiles are not
implemented.

The internal COSE_Sign1 codec combines that primitive with tag 18 framing,
requires an empty unprotected-header map, and checks that the signed payload
contains one definite-length CBOR value. It preserves the signed payload bytes
and does not authenticate a peer or validate operation-specific claims.
An explicitly present but empty `MAROEPrefix` is also rejected because its
header map is not empty. Base Profile Device attestation uses ECDSA P-256 or
P-384; RSA-PSS is outside the profile for voucher signatures.
Embedded deterministic encoding remains an open specification question.

The internal voucher verifier supports ECDSA P-256 and P-384, RSA2048RESTR,
and RSAPKCS keys encoded as X.509 SPKI, and ECDSA voucher keys encoded as
X5CHAIN. It checks ordered entry
signatures and hashes and requires consistent key types and algorithms. For
a Device, it also verifies the provisioned GUID, manufacturer-key hash, and
header HMAC before comparing the final key with the advertised Owner key. The
separate certificate-chain hash check does not validate certificates or trust.

The paired TO2 proof codecs check the signed Device transcript and the Owner's
nonce and signature. The Device-side Owner proof releases the signed Owner key
and exchange parameter only after the Device credentials and every voucher entry
verify. The paired onboarding path requires at least one voucher entry.
When both peers opt in to delegation, the Device verifies the Delegate's
chain and proof separately from the voucher binding and obtains host
authorization before deriving keys. An Owner-side verifier binds the voucher,
certificate chain, and Device proof to one transcript. Its pinned trust policy
requires an explicitly configured manufacturer key, certificate trust anchor,
and revocation mode; it does not authorize enrollment. After those voucher
checks, the Device verifies the signed TO1 redirect before deriving the
protected channel.

The host supplies the manufacturer key from an independently trusted source.
`FdoPublicKeyCodec.Encode` converts the public part of a P-256 or P-384
`ECDsa` key to the FDO PublicKey encoding; `EncodeRsa` converts a supported RSA
key. Neither conversion authenticates the key. A key taken from a received
voucher is not an independent trust source.

The internal SetupDevice20 codec supports credential reuse and the
provisional replacement disposition when explicitly allowed. For reuse, the
verified voucher Owner or an authorized Delegate signs. For replacement,
Owner2 signs the new credential values and the Ready nonce. The role must authenticate
the protected channel and enforce message order; the codec does not change
Device credentials.

The internal ECDH component generates one-use P-256 or P-384 keys and constructs
the FDO 2.0 shared-secret input in Device/Owner order. A separate AEAD primitive
supports the selected AES-GCM and AES-CCM algorithms where the runtime provides
them. The provisional COSE_Encrypt0 codec frames AES-GCM or AES-CCM ciphertext
and authenticates its protected header; it does not own nonces, prevent replay,
establish trust, or transport messages. An internal paired-profile
channel assigns separate Device and Owner counters, checks the next expected
nonce, and enforces alternating messages. Its caller must establish trust,
use a fresh session key, validate message semantics, and discard the channel
after a transport failure or ambiguous delivery.

The paired Linux DH exchange uses fixed-width unsigned big-endian public values
and shared secrets for the two RFC 3526 groups. The FDO specification does not
define this serialization, so it is a choice for paired peers rather than an
interoperability result. ASYMKEX uses RSA-OAEP with SHA-256, MGF1-SHA256, and
an empty label. Its KDF uses the Device random as the shared secret and the
Owner random as context. These choices do not establish interoperability.

`FdoPairedCipherSuite.AesCtr128HmacSha256` and `AesCtr256HmacSha384` select
the CTR encrypt-then-MAC suites. `AesCbc128HmacSha256` and
`AesCbc256HmacSha384` select the CBC suites. Both are opt-in. The channel
authenticates each COSE_Mac0 before parsing or decrypting the inner
COSE_Encrypt0. For CTR, it assigns each direction a separate counter range
across messages. AES-CTR uses OpenSSL on Linux, CommonCrypto on macOS, and CNG
AES-ECB with a managed counter construction on Windows. CBC uses .NET AES with
PKCS#7 padding and a fresh random 16-byte IV for each message. The channel
rejects repeated IVs across both directions and permits at most 2,000,000
protected messages in one run.
Authentication and padding failures produce the same exception and close the
CBC channel, but this does not establish the processing-time behavior required
by FDO 2.0 section 4.4. The
[wire decisions](FdoIntegrationDesign.md#provisional-wire-decisions)
describe the framing and its differences from other implementations.

The test-only `tests\Fdo.AotSmoke` executable completed paired DI, transfer,
discovery, TO0, TO1, and protected TO2 over loopback HTTP on Windows and Linux
x64 with .NET 10 and 11 NativeAOT. The scenarios cover ECDH with GCM, CTR, or
CBC and ASYMKEX with CBC. Linux also ran DH14 with CBC and DH15 with CTR;
Windows rejected both DH groups. The Linux native runs used OpenSSL 3.0.20.
These runs do not establish independent interoperability, HTTPS behavior, or
NativeAOT compatibility for untested paths.

</details>

## Transport and encoding

`FdoHttp` runs the paired Device TO2, Device Initialize, Owner TO0, and Device
TO1 roles over HTTP or HTTPS. Each call creates a client and token scope for
one run. The paired TO2 role encrypts its protected messages before passing
them to the private HTTP path. The internal generic HTTP sender still rejects
protected request types 86, 88, and 90. The generic sender never sends an
FDO 2.0 Error. The paired runner ends the run when it receives an Error or
redirect.

TO2 sends an FDO 2.0 Error only after key exchange. The role seals it on
the live channel, consumes the next directional counter, and uses the
provisional `/fdo/200/msg/255` route. It sends no Error when the received
message doesn't authenticate, the channel has failed, or the message is
itself an Error. The role never retries it as plaintext.

- **Owner Error.** When an authenticated Device request fails its semantic or
  local processing, the Owner returns one sealed Error with HTTP 500 and the
  active token, then ends the binding. The Owner sends no Error before key
  exchange; it ends the binding without a body instead.
- **Device Error.** When the Device rejects an authenticated Owner response 87
  or 89, it posts one sealed Error with the active token and requires an empty
  HTTP 200. A transport, cancellation, or delivery failure ends the run
  without a retry.
- **Rejected traffic.** A bad route, framing, or token, or a type-255 request
  that doesn't authenticate on the live channel, receives a bodiless HTTP
  rejection. A token alone doesn't authenticate the FDO peer.

The Error names the exact previous message type and carries a fresh random
correlation ID and a fixed, non-sensitive description. Its code is 100 for a
structure or limit failure, 101 for an authenticated semantic rejection, 102
only for a credential reuse denial, and 500 for an unexpected local failure.
`FdoPeerErrorException` reports an authenticated peer Error with its code and
previous message type, not its description.

TO0 has one separate terminal response. If the delegated `OwnerSign`
submission passes voucher, nonce, hash, chain, signature, and configured
trust checks but the Delegate lacks Redirect permission, the Rendezvous
server can return Error 104 with HTTP 500. It doesn't call admission or
write a registration. Other pre-key rejections don't send a protocol Error.

For an HTTP 302 or 307 response to `TO1.HelloRV`, the runner throws an
`FdoTransportException` with `Failure` set to
`FdoTransportFailure.RendezvousRedirect`. Its `RedirectLocation` is the
absolute, untrusted target; a relative `Location` is resolved against the
request URI. The target may include the FDO request path, credentials, or
query values, so it is not necessarily a usable base address and must not be
logged without filtering. The host applies endpoint and TLS policy, including
scheme changes and redirect-loop limits, before deciding whether to start a
new Device TO1 session. The original session ends without accepting a token
from the redirect, and a new session starts without an authorization header.
The host must not use a redirect or failed TO1 to enable rendezvous bypass.

The client uses a direct connection without automatic redirects, proxies, or
cookies. HTTPS uses the platform's normal TLS certificate validation unless
the host configures `FdoHttpPrivateTrust` for that run. The custom root doesn't
replace hostname validation or fall back to platform roots. The runner
doesn't offer a trust bypass or client-certificate configuration.
The host selects the endpoint and applies network policy. The client resolves
names without exposing or pinning the resulting addresses, so address-based
restrictions must be enforced on the network path. HTTP alone does not
authenticate a manufacturing station or protect the bearer token; use it only
where the host establishes an equivalent trusted environment. A host that needs
another transport or TLS policy must implement the existing role transport
interface. Pass a cancellation token to limit the run, including response
body reads.

The paired client sends HTTP/1.1 requests with a nonempty, single-use body and
without `Expect: 100-continue`. The library does not retry a failed request or
another route. The inspected .NET HTTP/1.1 implementation does not retry an
EOF after such a body has been sent. A failed request can still have reached
the peer; the host must reconcile any durable effects before another run.
Response reads are bounded by `maxResponseBytes`, from 1 through 65,535 bytes,
and successful responses require `application/cbor`, a valid message type,
and the initial authorization token. Later responses may repeat that token
but cannot change it.

`FdoHttpServerSession.ForOwner`, `ForManufacturer`, and `ForRendezvous` bind
one server role to one run. The host supplies the raw request target, all
authorization and content-type values, a request-framed body stream, and the
validated content length when known. The binding requires `POST`, the
provisional `/fdo/200/msg/{message-type}` route, one `application/cbor`
content type, and the correct session token. An optional `pathPrefix` must
match the client's base path. Its `maxRequestBytes` bounds body reads from
1 through 65,535 bytes. The host must reject invalid HTTP
framing, bound concurrent sessions and their lifetimes, and register the
issued bearer token before sending the first response. It must route later
requests to the same binding and protect tokens from disclosure.

Use the response's `StatusCode` and return its `Authorization` value in
the `Authorization` header. If `EncodedBody` isn't empty, send it as
`application/cbor` and put `MessageType` in the `Message-Type` header.
Serialize request handling with response handoff. After sending a complete
nonterminal response, call `ConfirmResponseSent`; do not confirm a response
whose `IsTerminal` is true. Confirmation records the handoff, not peer
receipt. Dispose the binding if delivery fails or is uncertain, remove its
token when the run ends, and reconcile retained state before retrying.
The binding owns its role session but doesn't host the HTTP listener.

<details>
<summary>Message encoding and ServiceInfo limits</summary>

The enclosing FDO CBOR value is checked with `System.Formats.Cbor` in
`Canonical` mode, with byte, nesting, and item limits. HTTP responses are
checked and reconstructed as StreamMsg structures without adding a wire
envelope. The stream codec reads and writes the five-element envelope,
including its total encoded length. Message bodies retain their received bytes,
and byte-string payload extraction excludes the wrapper without decoding or
rewriting the signed contents.

The ServiceInfo codec preserves entry order, repeated keys, and the encoded CBOR
value inside each byte-string wrapper. It checks each value as one
definite-length CBOR item, without enforcing deterministic encoding within that
wrapper. Whether the FDO deterministic-encoding rule also applies to the
embedded value remains open. The codec does not interpret modules or assume a
text transfer encoding.

The codec compares scalar map keys by value and rejects equivalent keys such as
`+0.0` and `-0.0`. It rejects a map containing two array keys, two map keys,
or two tagged keys because it cannot yet compare compound keys by value.
Application-specific key and tag semantics require additional checks.

The undefined StreamMsg `authtoken` type is also left unrestricted: the codec
retains its opaque encoded value rather than treating HTTP token text as a
normative direct-stream representation.

The initial TO0 and TO1 message codec reads and writes capability flags, vendor
strings, and 16-byte GUID or nonce fields. It rejects reserved bits in the first
capability byte and preserves additional bytes and vendor order. It checks the
CBOR structure, not reverse-domain notation or vendor authorization. It does
not negotiate a version or authenticate a peer.

The internal Device Initialize codec frames the four example-protocol messages
and checks the outer voucher-header shape. The paired DI roles validate selected
header fields and use host callbacks for trust and persistence, as described
above. The TO2 probe and acknowledgement codec checks
the provisional paired-profile transcript hashes and offered suites without
authenticating either peer. The TO2 completion and ServiceInfo codecs frame
plaintext bodies; they do not authenticate messages or change credentials.
The provisional wire choices and unresolved contradictions are recorded in the
[design](FdoIntegrationDesign.md#provisional-wire-decisions).

The internal simple-enrollment helpers validate a PKCS#10 request and check that
the returned certificate contains its public key. An explicitly selected
paired-peer profile carries each enrollment, re-enrollment, CA distribution,
or CSR attributes DER payload as canonical padded Base64 in one CBOR text
value. Unknown peers do not receive that encoding by default. Oversize items
are rejected rather than fragmented. Certificate trust, policy, and the final
protected-message size remain the role's responsibility.
The internal Device module sends the selected request after Owner activation
and optional CSR attribute discovery. It accepts a matching certificate only
after the caller records that the request was sent. For server-generated
keys, it stages the key until the role authenticates DoneAck20. The module
does not install the credential or complete onboarding. The
Device session does not invoke installation if ServiceInfo processing or the
channel fails.

The internal paired ServiceInfo state checks alternating turns, the empty
messages required while a peer has more data, and the final empty keepalive
exchange. It also checks the Done20 challenge and requires a null replacement
HMAC for credential reuse. The caller must authenticate messages and handle
enrollment commit and DoneAck20 separately.

Both paired roles split one logical ServiceInfo transfer into as many rounds
as the peer's limits require. Each round carries only complete entries, so a
single value is never split; an entry that can't fit an otherwise empty
message ends the run with error 100. The sender checks both the negotiated
plaintext limit and the size of the sealed message. The receiver answers each
round that reports more data with an empty message, and it assembles at most
64 entries and 65,535 encoded bytes per transfer before it processes them. A
session accepts at most 256 request/response rounds, counting empty polls and
the keepalives a Device sends after the Owner finishes. The cap is checked
before a module runs or another round is sent. These limits are library
choices, not values from the specification. The Device sends its `devmod`
inventory the same way and the Owner validates it once assembled; FDO 2.0
doesn't say whether `devmod` may span rounds, so this interpretation is
provisional.

The Error codec frames a restricted common subset with a numeric correlation
ID and a non-sensitive description. The paired TO2 roles seal it before
sending; the codec itself provides no protection. Non-null timestamps and null
correlation IDs are not implemented; received descriptions are untrusted and
must not be logged or echoed automatically.

The x5chain codec reads and writes the COSE certificate-chain representation:
one certificate as a byte string, or two or more as an array of byte strings.
It preserves their order and bytes and applies CBOR byte and item limits. It
does not check whether the bytes encode X.509 certificates, whether they have
integrity protection, or whether a chain is trusted. The separate chain-hash
primitive hashes the ordered certificate contents without the CBOR wrappers.
It does not establish certificate validity or trust. FDO section 3.4.2 describes
a null Device certificate chain and hash, while its CDDL names only `X5CHAIN`
and `Hash` and describes null as used in previous versions. The codec handles
x5chain itself and does not decide whether an enclosing FDO field can be null.

The codec checks the length-first deterministic encoding requirement in
[FDO 2.0 section 3.1](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v2.0-20260402/FIDO-Device-Onboard-PS-v2.0-20260402.html).
Section 3.2 also permits longer integer encodings for bounded integer types; that
wording conflicts with section 3.1 and is not treated as an exception. The HTTP
examples and several TO2 message bodies also conflict with their corresponding
definitions. The selected paths do not establish interoperability. The
discrepancies are tracked in
[#1](https://github.com/marcschier/fdo/issues/1).

The library directly references Microsoft's `System.Formats.Cbor` package. The
test project references TUnit 0.79.0. Both dependencies have been restored for
the Windows test runs. The HTTP code delegates protocol-state validation and
cryptography to the paired roles.

</details>
