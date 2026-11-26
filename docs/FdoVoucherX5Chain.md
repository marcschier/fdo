# ECDSA voucher keys encoded as X5CHAIN

The voucher roles accept ECDSA `PublicKey` values with encoding 2 as
described in FDO 2.0 §3.3.6. The body is a COSE X5CHAIN value: a certificate
byte string for one certificate, or an array of certificate byte strings
with the leaf first. The first certificate must contain the declared
P-256 or P-384 key. If that certificate is invalid or has the wrong key,
the verifier rejects the value instead of using a later certificate.

The attached certificates do not establish CA trust, CA Owner support, or
Name-Owner Match (NOM). The library extracts the end-entity public key,
then verifies the voucher with its existing trust and signature checks.
The host still chooses trusted manufacturer material and authorizes voucher
transfers independently. The Device's provisioned manufacturer digest
covers the exact encoded FDO `PublicKey`; a digest of a different encoding
of the same mathematical key is not interchangeable. The Owner proof
carries the voucher's exact final key. Key-to-signer comparisons use the
decoded key, without substituting a re-encoded key into a signed value.

`FdoPublicKeyCodec.EncodeCertificateChain` and
`FdoOwnershipVoucherTransfer.ExtendWithCertificateChain` explicitly select
this representation. Existing SPKI authoring remains unchanged. A
Delegate's offline status request identifies issuer keys by their SPKI
encoding; attaching a certificate to a voucher Owner key does not turn it
into an authoritative revocation source.
