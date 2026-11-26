// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Rendezvous;

namespace Fdo.Enrollment;

/// <summary>HMAC algorithm used by the Device's voucher credentials.</summary>
public enum FdoDeviceHmacAlgorithm
{
    /// <summary>HMAC-SHA-256 with a 32-byte Device secret.</summary>
    HmacSha256 = 0,

    /// <summary>HMAC-SHA-384 with a 64-byte Device secret.</summary>
    HmacSha384 = 1,
}

/// <summary>Device metadata advertised by the paired devmod inventory.</summary>
/// <param name="Os">The operating system reported by the Device.</param>
/// <param name="Architecture">The Device architecture reported in ServiceInfo.</param>
/// <param name="Version">The Device software version reported in ServiceInfo.</param>
/// <param name="Device">The Device description reported in ServiceInfo.</param>
/// <param name="Separator">The separator reported in the Device's ServiceInfo inventory.</param>
/// <param name="BinaryFormats">The binary formats advertised by the Device.</param>
public sealed record FdoDeviceMetadata(
    string Os,
    string Architecture,
    string Version,
    string Device,
    string Separator,
    string BinaryFormats);

/// <summary>
/// Configuration for one paired Device run, optionally accepting a Delegate
/// Owner proof. The caller retains
/// the attestation key and must keep it available without concurrent use until
/// the session finishes.
/// </summary>
public sealed class FdoDeviceSessionOptions
{
    /// <summary>The 16-byte FDO Device GUID in wire order.</summary>
    public required ReadOnlyMemory<byte> DeviceGuid { get; init; }

    /// <summary>
    /// The provisioned manufacturer-key hash as a canonical CBOR FDO Hash.
    /// </summary>
    public required ReadOnlyMemory<byte> EncodedManufacturerKeyHash { get; init; }

    /// <summary>The provisioned voucher HMAC algorithm.</summary>
    public required FdoDeviceHmacAlgorithm VoucherHmacAlgorithm { get; init; }

    /// <summary>
    /// The software-held Device voucher HMAC secret. The session snapshots
    /// this value and clears its copy after use or on disposal. The caller
    /// must protect and clear its own copy. Set this or
    /// <see cref="VoucherHmacSecretHandle"/>, but not both.
    /// </summary>
    public ReadOnlyMemory<byte> VoucherHmacSecret { get; init; }

    /// <summary>
    /// A host-owned handle to the Device voucher HMAC secret, such as the
    /// handle installed by Device Initialize. Keep it available without
    /// concurrent use until the session finishes. Set this or
    /// <see cref="VoucherHmacSecret"/>, but not both.
    /// </summary>
    public IFdoDeviceInitializeHmacSecret? VoucherHmacSecretHandle { get; init; }

    /// <summary>The private key for the Device attestation certificate.</summary>
    public required ECDsa AttestationKey { get; init; }

    /// <summary>
    /// The DER PKCS#10 request. Client-key enrollment requires a valid signature.
    /// Server-generated-key enrollment ignores the request key and signature.
    /// Leave empty when <see cref="CsrAttributesHandler"/> supplies the request.
    /// </summary>
    public ReadOnlyMemory<byte> CertificateSigningRequest { get; init; }

    /// <summary>
    /// When configured, requests CSR attributes before enrollment and obtains
    /// the CSR from this handler. Do not also set
    /// <see cref="CertificateSigningRequest"/>.
    /// </summary>
    public IFdoDeviceCsrAttributesHandler? CsrAttributesHandler { get; init; }

    /// <summary>
    /// Explicitly requests a server-generated key and installs it after
    /// DoneAck20. The ordinary enrollment handler still validates the
    /// certificate but does not install this credential. This option cannot
    /// be combined with <see cref="RequestReenrollment"/>.
    /// </summary>
    public IFdoDeviceServerKeygenHandler? ServerKeygenHandler { get; init; }

    /// <summary>The key-exchange suite selected for this paired profile.</summary>
    public required FdoPairedKeyExchangeSuite KeyExchangeSuite { get; init; }

    /// <summary>
    /// Explicitly enables the Linux-only paired DH encoding. It is not
    /// established as interoperable with other FDO peers.
    /// </summary>
    public bool UseProvisionalPairedDh { get; init; }

    /// <summary>
    /// Explicitly enables paired ASYMKEX using RSA-OAEP SHA-256. It is not
    /// established as interoperable with other FDO peers.
    /// </summary>
    public bool UseProvisionalPairedAsymkex { get; init; }

    /// <summary>
    /// Independently provisioned, CBOR-encoded FDO public key for the final
    /// RSA Owner. Required for ASYMKEX and not accepted for other suites.
    /// The session verifies it against the authenticated voucher Owner before
    /// exchanging protected data.
    /// </summary>
    public ReadOnlyMemory<byte> EncodedAsymkexOwnerPublicKey { get; init; }

    /// <summary>The TO2 cipher suite selected for this paired profile.</summary>
    public required FdoPairedCipherSuite CipherSuite { get; init; }

    /// <summary>
    /// Explicitly allows direct onboarding without TO1. Do not combine this
    /// with <see cref="RendezvousResult"/>. A failed TO1 does not enable bypass.
    /// </summary>
    public required bool AllowRendezvousBypass { get; init; }

    /// <summary>
    /// The untrusted result of a completed TO1 run. The session verifies its
    /// exact signature with the voucher-proven Owner key, or with a redirect
    /// Delegate of that key when <see cref="AcceptDelegatedRendezvousRedirect"/>
    /// is set, before protected enrollment. Each result can be used for only
    /// one Device session.
    /// </summary>
    public FdoDeviceRendezvousResult? RendezvousResult { get; init; }

    /// <summary>
    /// Required zero-based index for a delegated result with multiple candidates.
    /// The transport must expose a matching HTTP origin before the result is used.
    /// Leave null for a single-address result or bypass.
    /// </summary>
    public int? RendezvousAddressIndex { get; init; }

    /// <summary>
    /// Explicitly allows a <see cref="RendezvousResult"/> whose blob carries a
    /// single DelegateChain. Requires <see cref="RendezvousResult"/>,
    /// <see cref="RedirectDelegateAcceptance"/> and
    /// <see cref="RedirectDelegateTimeProvider"/>. It does not change TO1 or
    /// the TO2 capabilities, and it is independent of
    /// <see cref="UseDelegatedOwnerProof"/>: a redirect Delegate may differ
    /// from the TO2 Delegate, and neither permission implies the other.
    /// Without this option the Device rejects a delegated blob.
    /// </summary>
    public bool AcceptDelegatedRendezvousRedirect { get; init; }

    /// <summary>
    /// Host policy that must accept the verified redirect Delegate before key
    /// derivation. Configure only with <see cref="AcceptDelegatedRendezvousRedirect"/>.
    /// </summary>
    public IFdoDeviceRedirectDelegateAcceptance? RedirectDelegateAcceptance { get; init; }

    /// <summary>
    /// Clock used to check redirect Delegate certificate validity periods.
    /// Configure only with <see cref="AcceptDelegatedRendezvousRedirect"/>.
    /// The session does not fetch certificates or check revocation online.
    /// </summary>
    public TimeProvider? RedirectDelegateTimeProvider { get; init; }

    /// <summary>Offline status required for a delegated redirect; null selects no revocation check.</summary>
    public FdoDelegateOfflineRevocationPolicy? RedirectDelegateOfflineRevocation { get; init; }

    /// <summary>Explicitly allows the credential-reuse disposition.</summary>
    public required bool AllowCredentialReuse { get; init; }

    /// <summary>
    /// Explicitly allows an Owner proof signed by a Delegate of the voucher's
    /// final Owner. The Device advertises the delegation capability, requires
    /// the Owner to echo it, and rejects ASYMKEX. Requires
    /// <see cref="DelegateAcceptance"/> and <see cref="DelegateTimeProvider"/>.
    /// Without this option the Device rejects any Delegate chain.
    /// </summary>
    public bool UseDelegatedOwnerProof { get; init; }

    /// <summary>
    /// Host policy that must accept each verified Delegate before key
    /// derivation. Configure only with <see cref="UseDelegatedOwnerProof"/>.
    /// </summary>
    public IFdoDeviceDelegateAcceptance? DelegateAcceptance { get; init; }

    /// <summary>
    /// Clock used to check Delegate certificate validity periods. Configure
    /// only with <see cref="UseDelegatedOwnerProof"/>. The session does not
    /// check revocation or fetch certificates.
    /// </summary>
    public TimeProvider? DelegateTimeProvider { get; init; }

    /// <summary>Offline status required for a delegated TO2 proof; null selects no revocation check.</summary>
    public FdoDelegateOfflineRevocationPolicy? DelegateOfflineRevocation { get; init; }

    /// <summary>
    /// Enables the provisional paired credential-replacement disposition.
    /// The handler owns its protected secret and durable transitions.
    /// </summary>
    public IFdoDeviceReplacementHandler? ReplacementHandler { get; init; }

    /// <summary>
    /// Explicitly selects the provisional paired IV and Base64 ServiceInfo
    /// profile. It is not established as interoperable with other FDO peers.
    /// </summary>
    public required bool UseProvisionalPairedProfile { get; init; }

    /// <summary>
    /// Maximum encoded FDO message body received by the Device, including any
    /// protected envelope and excluding transport framing.
    /// </summary>
    public required ushort MaxMessageSize { get; init; }

    /// <summary>Maximum encoded Owner ServiceInfo plaintext received by the Device.</summary>
    public required ushort MaxOwnerServiceInfoSize { get; init; }

    /// <summary>
    /// Requests format 281 CA certificates and CRLs before the selected
    /// enrollment operation. The host decides whether to trust or install
    /// the returned material.
    /// </summary>
    public bool RequestCaCertificates { get; init; }

    /// <summary>
    /// Requests simple re-enrollment instead of initial enrollment. The host
    /// supplies a CSR whose ordinary subject and SANs match its prior certificate.
    /// </summary>
    public bool RequestReenrollment { get; init; }

    /// <summary>Metadata for the paired devmod inventory.</summary>
    public required FdoDeviceMetadata Metadata { get; init; }

    /// <summary>
    /// Handler that validates the issued certificate and installs it for
    /// client-key enrollment.
    /// </summary>
    public required IFdoDeviceEnrollmentHandler EnrollmentHandler { get; init; }
}
