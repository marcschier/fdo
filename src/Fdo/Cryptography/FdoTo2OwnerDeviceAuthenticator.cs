using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Binds one paired Owner run to its checked voucher, certificate chain,
/// Device proof, and an explicit trust policy. The caller must supply the
/// exact probe and freshly challenged acknowledgement from the current run.
/// Device authorization, rendezvous, and protocol state remain separate.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2OwnerDeviceAuthenticator
{
    private readonly FdoCborCodec _cbor;
    private readonly FdoTo2DeviceProofCodec _proofs;
    private readonly IFdoOwnerDeviceTrustPolicy _trustPolicy;
    private readonly FdoOwnershipVoucherChainVerifier.CheckedOwnerVoucher _voucher;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _entries;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _certificates;
    private readonly ReadOnlyMemory<byte> _header;
    private readonly ReadOnlyMemory<byte> _headerHmac;
    private readonly ReadOnlyMemory<byte> _ownerKey;
    private readonly ReadOnlyMemory<byte> _probe;
    private readonly ReadOnlyMemory<byte> _acknowledgement;
    private int _attempted;

    public FdoTo2OwnerDeviceAuthenticator(
        ReadOnlyMemory<byte> encodedHeader,
        ReadOnlyMemory<byte> encodedHeaderHmac,
        IReadOnlyList<ReadOnlyMemory<byte>> entries,
        ReadOnlyMemory<byte> encodedDeviceCertificateChain,
        AsymmetricAlgorithm ownerSigningKey,
        ReadOnlyMemory<byte> receivedProbe,
        ReadOnlyMemory<byte> sentAcknowledgement,
        IFdoOwnerDeviceTrustPolicy trustPolicy,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(ownerSigningKey);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        int count = entries.Count;
        if (count is < 1 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(entries), "Paired onboarding requires between 1 and 255 voucher entries.");
        }

        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _proofs = new FdoTo2DeviceProofCodec(maxEncodedBytes, maxDepth, maxItems);
        _trustPolicy = trustPolicy;
        _header = _cbor.ValidateAndCopy(encodedHeader);
        _headerHmac = _cbor.ValidateAndCopy(encodedHeaderHmac);
        var copiedEntries = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < copiedEntries.Length; i++)
        {
            copiedEntries[i] = _cbor.ValidateAndCopy(entries[i]);
        }

        _voucher = CheckLocalVoucher(_header, _headerHmac, copiedEntries, encodedDeviceCertificateChain,
            ownerSigningKey, _cbor, maxEncodedBytes, maxDepth, maxItems);
        _ownerKey = _voucher.OwnerKey;
        _entries = Array.AsReadOnly(copiedEntries);
        _certificates = new FdoX5ChainCodec(maxEncodedBytes, maxItems).Decode(_voucher.DeviceCertificateChain);
        _probe = _cbor.ValidateAndCopy(receivedProbe);
        _acknowledgement = _cbor.ValidateAndCopy(sentAcknowledgement);
        var initial = new FdoTo2InitialCodec(maxEncodedBytes, maxDepth, maxItems);
        FdoTo2InitialCodec.CheckedAcknowledgement checkedAck = initial.CheckAcknowledgement(_probe, _acknowledgement);
        if (!CryptographicOperations.FixedTimeEquals(checkedAck.Message.Guid.Span, _voucher.Guid.Span))
        {
            throw new CryptographicException("The TO2 transcript GUID does not match the ownership voucher.");
        }
    }

    internal static FdoOwnershipVoucherChainVerifier.CheckedOwnerVoucher CheckLocalVoucher(
        ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> hmac, IReadOnlyList<ReadOnlyMemory<byte>> entries,
        ReadOnlyMemory<byte> deviceCertificateChain, AsymmetricAlgorithm ownerSigningKey,
        FdoCborCodec cbor, int maxEncodedBytes = ushort.MaxValue, int maxDepth = 32, int maxItems = ushort.MaxValue)
    {
        var keys = new FdoPublicKeyCodec(maxEncodedBytes, maxDepth, maxItems);
        FdoOwnershipVoucherHeader parsed = FdoOwnershipVoucherHeader.Decode(header, cbor);
        using FdoPublicKeyCodec.DecodedKey manufacturer = keys.Decode(parsed.ManufacturerKey);
        ReadOnlyMemory<byte> signingKey = keys.EncodeOwnerKey(ownerSigningKey, manufacturer.KeyType);
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            header, hmac, entries.Count, maxEncodedBytes, maxDepth, maxItems);
        for (int i = 0; i < entries.Count; i++)
        {
            verifier.AppendEntry(i, entries[i]);
        }

        return verifier.CompleteOwnerChecks(signingKey, deviceCertificateChain);
    }

    /// <summary>
    /// Attempts the Device proof once. No result is returned unless the
    /// certificate key verifies this run and the configured policy accepts
    /// the matching manufacturer and certificate chain.
    /// </summary>
    public AuthenticatedDevice Verify(ReadOnlyMemory<byte> encodedDeviceProof)
    {
        if (Interlocked.CompareExchange(ref _attempted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Owner Device proof has already been attempted.");
        }

        ReadOnlyMemory<byte> proof = _cbor.ValidateAndCopy(encodedDeviceProof);
        using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(_certificates[0]);
        FdoDerEncoding.RequireSigningKeyUsage(leaf);
        using ECDsa deviceKey = leaf.GetECDsaPublicKey()
            ?? throw new CryptographicException("The Device certificate must contain an ECDSA public key.");
        FdoTo2DeviceProofCodec.DeviceProof verified = _proofs.Verify(_probe, _acknowledgement, proof, deviceKey);
        if (!CryptographicOperations.FixedTimeEquals(verified.Guid.Span, _voucher.Guid.Span))
        {
            throw new CryptographicException("The Device proof GUID does not match the ownership voucher.");
        }

        var evidenceCertificates = new ReadOnlyMemory<byte>[_certificates.Count];
        for (int i = 0; i < evidenceCertificates.Length; i++)
        {
            evidenceCertificates[i] = _certificates[i].ToArray();
        }

        _trustPolicy.Validate(new FdoOwnerDeviceTrustEvidence(
            _voucher.Guid.ToArray(), _voucher.ManufacturerKey.ToArray(), Array.AsReadOnly(evidenceCertificates)));
        return new AuthenticatedDevice(
            _header, _headerHmac, _entries, _ownerKey, _voucher,
            leaf.RawData, _probe, _acknowledgement, proof, verified);
    }

    /// <summary>
    /// Verified evidence from one run. It does not authorize enrollment,
    /// validate a TO1 redirect, or establish a protected channel.
    /// </summary>
    public sealed class AuthenticatedDevice
    {
        private readonly ReadOnlyMemory<byte> _header;
        private readonly ReadOnlyMemory<byte> _headerHmac;
        private readonly IReadOnlyList<ReadOnlyMemory<byte>> _entries;
        private readonly ReadOnlyMemory<byte> _ownerKey;
        private readonly FdoOwnershipVoucherChainVerifier.CheckedOwnerVoucher _voucher;
        private readonly ReadOnlyMemory<byte> _deviceCertificate;
        private readonly ReadOnlyMemory<byte> _probe;
        private readonly ReadOnlyMemory<byte> _acknowledgement;
        private readonly ReadOnlyMemory<byte> _encodedDeviceProof;
        private readonly FdoTo2DeviceProofCodec.DeviceProof _deviceProof;

        internal AuthenticatedDevice(
            ReadOnlyMemory<byte> header,
            ReadOnlyMemory<byte> headerHmac,
            IReadOnlyList<ReadOnlyMemory<byte>> entries,
            ReadOnlyMemory<byte> ownerKey,
            FdoOwnershipVoucherChainVerifier.CheckedOwnerVoucher voucher,
            ReadOnlyMemory<byte> deviceCertificate,
            ReadOnlyMemory<byte> probe,
            ReadOnlyMemory<byte> acknowledgement,
            ReadOnlyMemory<byte> encodedDeviceProof,
            FdoTo2DeviceProofCodec.DeviceProof deviceProof)
        {
            _header = header;
            _headerHmac = headerHmac;
            _entries = entries;
            _ownerKey = ownerKey;
            _voucher = voucher;
            _deviceCertificate = deviceCertificate;
            _probe = probe;
            _acknowledgement = acknowledgement;
            _encodedDeviceProof = encodedDeviceProof;
            _deviceProof = deviceProof;
        }

        public ReadOnlyMemory<byte> Header => _header.ToArray();
        public ReadOnlyMemory<byte> HeaderHmac => _headerHmac.ToArray();

        public IReadOnlyList<ReadOnlyMemory<byte>> Entries
        {
            get
            {
                var copies = new ReadOnlyMemory<byte>[_entries.Count];
                for (int i = 0; i < copies.Length; i++)
                {
                    copies[i] = _entries[i].ToArray();
                }

                return Array.AsReadOnly(copies);
            }
        }

        public ReadOnlyMemory<byte> OwnerKey => _ownerKey.ToArray();
        public FdoOwnershipVoucherChainVerifier.CheckedOwnerVoucher Voucher => new(
            _voucher.Guid.ToArray(), _voucher.ManufacturerKey.ToArray(), _voucher.DeviceCertificateChain.ToArray(),
            _voucher.OwnerKey.ToArray());
        public ReadOnlyMemory<byte> DeviceCertificate => _deviceCertificate.ToArray();
        public ReadOnlyMemory<byte> Probe => _probe.ToArray();
        public ReadOnlyMemory<byte> Acknowledgement => _acknowledgement.ToArray();
        public ReadOnlyMemory<byte> EncodedDeviceProof => _encodedDeviceProof.ToArray();
        public FdoTo2DeviceProofCodec.DeviceProof DeviceProof => new(
            _deviceProof.Guid.ToArray(), _deviceProof.Exchange, _deviceProof.Cipher,
            _deviceProof.DeviceParameter.ToArray(), _deviceProof.OwnerNonce.ToArray());
    }
}
