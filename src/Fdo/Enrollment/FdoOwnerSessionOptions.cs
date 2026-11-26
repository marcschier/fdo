// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.Enrollment;

/// <summary>Key exchange offered by the paired Owner profile.</summary>
public enum FdoPairedKeyExchangeSuite
{
    /// <summary>NIST P-256 ECDH.</summary>
    Ecdh256 = 0,

    /// <summary>NIST P-384 ECDH.</summary>
    Ecdh384 = 1,

    /// <summary>RFC 3526 group 14 DH, with the paired fixed-width encoding.</summary>
    DhkexId14 = 2,

    /// <summary>RFC 3526 group 15 DH, with the paired fixed-width encoding.</summary>
    DhkexId15 = 3,

    /// <summary>Paired RSA-2048 OAEP key exchange.</summary>
    Asymkex2048 = 4,

    /// <summary>Paired RSA-3072 OAEP key exchange.</summary>
    Asymkex3072 = 5,
}

/// <summary>Authenticated encryption offered by the paired Owner profile.</summary>
public enum FdoPairedCipherSuite
{
    /// <summary>AES-128-GCM.</summary>
    A128Gcm = 0,

    /// <summary>AES-256-GCM.</summary>
    A256Gcm = 1,

    /// <summary>AES-128-CCM with a 13-byte nonce and 16-byte tag.</summary>
    AesCcm16_128_128 = 2,

    /// <summary>AES-256-CCM with a 13-byte nonce and 16-byte tag.</summary>
    AesCcm16_128_256 = 3,

    /// <summary>AES-128-CCM with a 7-byte nonce and 16-byte tag.</summary>
    AesCcm64_128_128 = 4,

    /// <summary>AES-256-CCM with a 7-byte nonce and 16-byte tag.</summary>
    AesCcm64_128_256 = 5,

    /// <summary>
    /// FDO 2.0 <c>CS_AES128_CTR_HMAC-SHA256</c> encrypt-then-MAC, using the
    /// provisional paired counter-block profile. Explicit opt-in only.
    /// </summary>
    AesCtr128HmacSha256 = 6,

    /// <summary>
    /// FDO 2.0 <c>CS_AES256_CTR_HMAC-SHA384</c> encrypt-then-MAC with a 64-byte
    /// verification key, using the provisional paired counter-block profile.
    /// Explicit opt-in only.
    /// </summary>
    AesCtr256HmacSha384 = 7,

    /// <summary>
    /// FDO 2.0 <c>CS_AES128_CBC_HMAC-SHA256</c> encrypt-then-MAC with a
    /// fresh random IV per message. Explicit opt-in only.
    /// </summary>
    AesCbc128HmacSha256 = 8,

    /// <summary>
    /// FDO 2.0 <c>CS_AES256_CBC_HMAC-SHA384</c> encrypt-then-MAC with a
    /// fresh random IV per message. Explicit opt-in only.
    /// </summary>
    AesCbc256HmacSha384 = 9,
}

/// <summary>Message types supported by the paired FDO 2.0 TO2 Owner.</summary>
public enum FdoTo2MessageType : ushort
{
    /// <summary>Device version and capability probe.</summary>
    HelloDeviceProbe = 80,

    /// <summary>Owner acknowledgement of the probe.</summary>
    HelloDeviceAck20 = 81,

    /// <summary>Device proof and key-exchange parameter.</summary>
    ProveDevice20 = 82,

    /// <summary>Owner proof and voucher header.</summary>
    ProveOVHdr20 = 83,

    /// <summary>Device request for a voucher entry.</summary>
    GetOVNextEntry20 = 84,

    /// <summary>Owner voucher entry.</summary>
    OVNextEntry20 = 85,

    /// <summary>Protected Device ServiceInfo readiness message.</summary>
    DeviceServiceInfoRdy20 = 86,

    /// <summary>Protected Owner setup message.</summary>
    SetupDevice20 = 87,

    /// <summary>Protected Device ServiceInfo message.</summary>
    DeviceSvcInfo20 = 88,

    /// <summary>Protected Owner ServiceInfo message.</summary>
    OwnerSvcInfo20 = 89,

    /// <summary>Protected Device completion message.</summary>
    Done20 = 90,

    /// <summary>Protected Owner completion acknowledgement.</summary>
    DoneAck20 = 91,

    /// <summary>
    /// Terminal FDO Error. After key exchange it is sealed on the live TO2
    /// channel; an Owner acknowledges a received Error with an empty body.
    /// </summary>
    Error = 255,
}

/// <summary>
/// Configuration for one paired Owner run, optionally signed by a Delegate.
/// The caller retains the
/// signing key and must keep it available without concurrent use until the
/// session is disposed.
/// </summary>
public sealed class FdoOwnerSessionOptions
{
    /// <summary>CBOR-encoded voucher header tag, including its byte-string wrapper.</summary>
    public required ReadOnlyMemory<byte> EncodedVoucherHeaderTag { get; init; }

    /// <summary>CBOR-encoded voucher header HMAC.</summary>
    public required ReadOnlyMemory<byte> EncodedVoucherHeaderHmac { get; init; }

    /// <summary>Ordered CBOR-encoded signed voucher entries.</summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> EncodedVoucherEntries { get; init; }

    /// <summary>CBOR-encoded ordered Device attestation certificate chain.</summary>
    public required ReadOnlyMemory<byte> EncodedDeviceCertificateChain { get; init; }

    /// <summary>CBOR-encoded FDO manufacturer public key to trust.</summary>
    public required ReadOnlyMemory<byte> TrustedManufacturerKey { get; init; }

    /// <summary>DER certificate used as the Device attestation trust anchor.</summary>
    public required ReadOnlyMemory<byte> DeviceTrustAnchor { get; init; }

    /// <summary>Revocation behavior for the Device attestation chain.</summary>
    public required X509RevocationMode DeviceRevocationMode { get; init; }

    /// <summary>Private key corresponding to the voucher's final Owner key.</summary>
    public required AsymmetricAlgorithm OwnerSigningKey { get; init; }

    /// <summary>Handler that authorizes, issues, and durably commits enrollment.</summary>
    public required IFdoOwnerEnrollmentHandler EnrollmentHandler { get; init; }

    /// <summary>
    /// Optional provider for an authenticated Device's CA certificate request.
    /// A request cannot succeed unless this handler is configured.
    /// </summary>
    public IFdoOwnerCaCertificatesHandler? CaCertificatesHandler { get; init; }

    /// <summary>
    /// Optional provider for an authenticated Device's CSR attributes request.
    /// Without it, the Owner returns <c>fdo.csr:error</c> 3.
    /// </summary>
    public IFdoOwnerCsrAttributesHandler? CsrAttributesHandler { get; init; }

    /// <summary>
    /// Explicitly enables server-side key generation for authenticated
    /// Devices. Without it, the Owner returns <c>fdo.csr:error</c> 3.
    /// </summary>
    public IFdoOwnerServerKeygenHandler? ServerKeygenHandler { get; init; }

    /// <summary>
    /// Resolves prior credentials and approves identity changes for simple
    /// re-enrollment. A re-enrollment request requires this handler.
    /// </summary>
    public IFdoOwnerReenrollmentHandler? ReenrollmentHandler { get; init; }

    /// <summary>The single key-exchange suite advertised by this paired profile.</summary>
    public required FdoPairedKeyExchangeSuite KeyExchangeSuite { get; init; }

    /// <summary>
    /// Optional second offer after <see cref="KeyExchangeSuite"/>. Direct RSA
    /// Owners on Linux may pair DH14 and ASYMKEX2048, or DH15 and ASYMKEX3072,
    /// with both existing opt-ins. The Device selects its configured suite.
    /// </summary>
    public FdoPairedKeyExchangeSuite? AdditionalKeyExchangeSuite { get; init; }

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

    /// <summary>The single TO2 cipher suite advertised by this paired profile.</summary>
    public required FdoPairedCipherSuite CipherSuite { get; init; }

    /// <summary>
    /// Up to nine distinct, locally supported suites, offered in this order
    /// after <see cref="CipherSuite"/>. Do not repeat the primary suite.
    /// The session snapshots the list at construction.
    /// The Device selects its configured suite; list order does not imply fallback.
    /// </summary>
    public IReadOnlyList<FdoPairedCipherSuite>? AdditionalCipherSuites { get; init; }

    /// <summary>
    /// Explicitly allows direct onboarding without TO1. The Owner cannot
    /// determine from TO2 whether a Device actually used TO1.
    /// </summary>
    public required bool AllowRendezvousBypass { get; init; }

    /// <summary>
    /// Explicitly allows TO2 after a Device's TO1 lookup. The Owner cannot
    /// distinguish this route from bypass in the TO2 messages.
    /// </summary>
    public bool AllowRendezvous { get; init; }

    /// <summary>Explicitly allows the credential-reuse disposition.</summary>
    public required bool AllowCredentialReuse { get; init; }

    /// <summary>
    /// Selects the provisional paired credential-replacement disposition
    /// instead of credential reuse.
    /// </summary>
    public FdoOwnerReplacementOptions? Replacement { get; init; }

    /// <summary>
    /// Explicitly selects a Delegate-signed Owner proof. The Owner requires the
    /// Device to advertise the delegation capability and echoes it; it does
    /// not fall back to an Owner-signed proof. Requires
    /// <see cref="DelegateSigningKey"/>, <see cref="DelegateCertificateChain"/>
    /// and <see cref="DelegateTimeProvider"/>, and rejects ASYMKEX.
    /// </summary>
    public bool UseDelegatedOwnerProof { get; init; }

    /// <summary>
    /// Private key of the Delegate leaf certificate. It signs the Owner proof
    /// and the credential-reuse disposition; Owner2 still signs a
    /// replacement. The caller retains the key.
    /// </summary>
    public AsymmetricAlgorithm? DelegateSigningKey { get; init; }

    /// <summary>
    /// DER Delegate certificates, leaf first, whose last certificate is signed
    /// by <see cref="OwnerSigningKey"/>. The chain must permit the configured
    /// disposition; a chain that would require FDO disable is rejected.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? DelegateCertificateChain { get; init; }

    /// <summary>
    /// Clock used to check Delegate certificate validity periods, at
    /// construction and before each proof. Revocation is not checked.
    /// </summary>
    public TimeProvider? DelegateTimeProvider { get; init; }

    /// <summary>Offline status required for the configured TO2 Delegate; null selects no revocation check.</summary>
    public FdoDelegateOfflineRevocationPolicy? DelegateOfflineRevocation { get; init; }

    /// <summary>
    /// Explicitly selects the provisional paired IV and Base64 ServiceInfo
    /// profile. It is not established as interoperable with other FDO peers.
    /// </summary>
    public required bool UseProvisionalPairedProfile { get; init; }

    /// <summary>
    /// Maximum encoded FDO message body received by the Owner, including any
    /// protected envelope and excluding transport framing.
    /// </summary>
    public required ushort MaxMessageSize { get; init; }

    /// <summary>Maximum encoded Device ServiceInfo plaintext received by the Owner.</summary>
    public required ushort MaxDeviceServiceInfoSize { get; init; }
}

/// <summary>An Owner response whose encoded body is detached from the session.</summary>
public sealed class FdoOwnerResponse
{
    private readonly byte[] _encodedBody;

    internal FdoOwnerResponse(FdoTo2MessageType messageType, ReadOnlyMemory<byte> encodedBody)
        : this(200, messageType, encodedBody)
    {
    }

    /// <summary>
    /// Snapshots a response received by a Device transport. The host must
    /// enforce its receive limit while reading the body.
    /// </summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    public FdoOwnerResponse(
        ushort protocolVersion,
        FdoTo2MessageType messageType,
        ReadOnlyMemory<byte> encodedBody)
    {
        if (encodedBody.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedBody), "An FDO message body must fit in uint16.");
        }

        ProtocolVersion = protocolVersion;
        MessageType = messageType;
        _encodedBody = encodedBody.ToArray();
    }

    /// <summary>The FDO protocol version, encoded as a number such as 200.</summary>
    public ushort ProtocolVersion { get; }

    /// <summary>The response message type.</summary>
    public FdoTo2MessageType MessageType { get; }

    /// <summary>The exact encoded response body.</summary>
    public ReadOnlyMemory<byte> EncodedBody => (byte[])_encodedBody.Clone();
}
