// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Signs and checks the FDO 2.0 Owner proof for the paired,
/// non-remanufacturing onboarding profile, with or without a Delegate chain.
/// A Device must finish the voucher checks and separately verify a TO1
/// redirect when rendezvous was used.
/// </summary>
/// <remarks>
/// A delegated proof keeps the voucher Owner key in OwnerPubKey, carries the
/// Delegate chain, and is signed by the Delegate leaf key. The chain must
/// verify against OwnerPubKey, and the Device binds OwnerPubKey to the voucher
/// before it releases the result.
/// </remarks>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2OwnerProofCodec
{
    private const int NonceLength = 16;
    private readonly FdoCborCodec _cbor;
    private readonly FdoPublicKeyCodec _keys;
    private readonly FdoCoseSign1Codec _signatures;
    private readonly int _maxEncodedBytes;
    private readonly int _maxDepth;
    private readonly int _maxItems;

    public FdoTo2OwnerProofCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _keys = new FdoPublicKeyCodec(maxEncodedBytes, maxDepth, maxItems);
        _signatures = new FdoCoseSign1Codec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxDepth = maxDepth;
        _maxItems = maxItems;
    }

    /// <summary>
    /// Signs an Owner proof. The caller must separately verify the voucher,
    /// authorize the Device, and establish that this private key is the
    /// voucher's final Owner key before sending it.
    /// </summary>
    /// <param name="encodedHeaderTag">The exact voucher header, including its CBOR byte-string wrapper.</param>
    /// <param name="encodedHeaderHmac">The encoded voucher header HMAC.</param>
    /// <param name="entryCount">The number of voucher entries.</param>
    /// <param name="ownerNonce">The nonce supplied by the Owner for this exchange.</param>
    /// <param name="exchange">The selected key exchange suite.</param>
    /// <param name="ownerParameter">The Owner's contribution to the negotiated key exchange.</param>
    /// <param name="maxOwnerMessageSize">The maximum encoded Owner message body size, in bytes.</param>
    /// <param name="ownerKey">The Owner public key that anchors verification.</param>
    /// <param name="delegateSigner">The private key that signs on behalf of the Owner.</param>
    /// <param name="encodedVoucherOwnerKey">The encoded final Owner key authenticated by the voucher.</param>
    /// <remarks>
    /// Without a Delegate, <paramref name="ownerKey"/> is the voucher's final
    /// Owner private key and signs the proof. With a
    /// <paramref name="delegateSigner"/>, only the Owner public key is used:
    /// the Delegate chain is verified against it at the supplied time, and the
    /// signing key must be the chain's leaf key.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Paired onboarding requires at least one voucher entry.</exception>
    /// <exception cref="CryptographicException">
    /// The private signing key does not match the voucher Owner key.
    /// </exception>
    public ReadOnlyMemory<byte> Sign(
        ReadOnlyMemory<byte> encodedHeaderTag,
        ReadOnlyMemory<byte> encodedHeaderHmac,
        int entryCount,
        ReadOnlyMemory<byte> ownerNonce,
        FdoKeyExchangeSuite exchange,
        ReadOnlyMemory<byte> ownerParameter,
        ushort maxOwnerMessageSize,
        AsymmetricAlgorithm ownerKey,
        DelegateSigner? delegateSigner = null,
        ReadOnlyMemory<byte>? encodedVoucherOwnerKey = null)
    {
        ArgumentNullException.ThrowIfNull(ownerKey);
        AsymmetricAlgorithm ownerPrivateKey = ownerKey;
        if (entryCount is < 1 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(entryCount), "Paired onboarding requires at least one voucher entry.");
        }

        byte[] nonce = CopyNonce(ownerNonce);
        FdoKeyExchangeSuites.RequireParameterShape(exchange, isOwner: true, ownerParameter.Span);
        byte[] parameter = ownerParameter.ToArray();
        FdoKeyExchangeSuites.RequireParameterShape(exchange, isOwner: true, parameter);
        ReadOnlyMemory<byte> header = _cbor.ValidateAndCopy(encodedHeaderTag);
        ReadOnlyMemory<byte> hmac = _cbor.ValidateAndCopy(encodedHeaderHmac);
        using var voucher = NewVoucher(header, hmac, entryCount);
        FdoOwnershipVoucherHeader voucherHeader = FdoOwnershipVoucherHeader.Decode(header, _cbor);
        using FdoPublicKeyCodec.DecodedKey manufacturer = _keys.Decode(voucherHeader.ManufacturerKey);
        using FdoPublicKeyCodec.DecodedKey owner =
            _keys.Decode(_keys.EncodeOwnerKey(ownerPrivateKey, manufacturer.KeyType));
        using FdoPublicKeyCodec.DecodedKey? voucherOwner =
            encodedVoucherOwnerKey is { } exactKey ? _keys.Decode(exactKey) : null;
        if (voucherOwner is not null && !owner.HasSamePublicKey(voucherOwner))
        {
            throw new CryptographicException("The private signing key does not match the voucher Owner key.");
        }

        ReadOnlyMemory<byte> encodedOwner = voucherOwner?.Encoded ?? owner.Encoded;
        RequireOwnerSuite(exchange, owner);
        ReadOnlyMemory<byte> encodedChain = default;
        FdoCoseSignatureAlgorithm algorithm = owner.Algorithm;
        AsymmetricAlgorithm signingKey = ownerPrivateKey;
        if (delegateSigner is not null)
        {
            FdoVerifiedDelegateChain verified = FdoTo2DelegatePolicy.Verify(
                delegateSigner.Chain, encodedOwner, exchange, delegateSigner.VerificationTime,
                captureRevocationTargets: delegateSigner.OfflineRevocation is not null);
            algorithm = RequireDelegateSigningKey(verified, delegateSigner.SigningKey);
            verified.RequireOfflineStatus(delegateSigner.OfflineRevocation, delegateSigner.VerificationTime);
            encodedChain = new FdoX5ChainCodec(_maxEncodedBytes, _maxItems).Encode(delegateSigner.Chain);
            signingKey = delegateSigner.SigningKey;
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(8);
        writer.WriteEncodedValue(header.Span);
        writer.WriteInt32(entryCount);
        writer.WriteEncodedValue(hmac.Span);
        writer.WriteByteString(nonce);
        writer.WriteByteString(parameter);
        writer.WriteUInt64(maxOwnerMessageSize);
        writer.WriteEncodedValue(encodedOwner.Span);
        if (delegateSigner is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteEncodedValue(encodedChain.Span);
        }

        writer.WriteEndArray();
        return _signatures.Sign(
            FdoSignatureOperation.TO2ProveOVHdr, algorithm, signingKey, writer.Encode());
    }

    /// <summary>
    /// Verifies an Owner's configured Delegate against the voucher's final
    /// Owner key before any proof is signed, and returns the verified chain.
    /// </summary>
    /// <param name="encodedHeaderTag">The exact voucher header, including its CBOR byte-string wrapper.</param>
    /// <param name="ownerKey">The Owner public key that anchors verification.</param>
    /// <param name="exchange">The selected key exchange suite.</param>
    /// <param name="delegateSigner">The private key that signs on behalf of the Owner.</param>
    internal FdoVerifiedDelegateChain VerifyDelegateSigner(
        ReadOnlyMemory<byte> encodedHeaderTag,
        AsymmetricAlgorithm ownerKey,
        FdoKeyExchangeSuite exchange,
        DelegateSigner delegateSigner)
    {
        ArgumentNullException.ThrowIfNull(ownerKey);
        ArgumentNullException.ThrowIfNull(delegateSigner);
        FdoTo2DelegatePolicy.RequireExchange(exchange);
        ReadOnlyMemory<byte> header = _cbor.ValidateAndCopy(encodedHeaderTag);
        FdoOwnershipVoucherHeader voucherHeader = FdoOwnershipVoucherHeader.Decode(header, _cbor);
        using FdoPublicKeyCodec.DecodedKey manufacturer = _keys.Decode(voucherHeader.ManufacturerKey);
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(_keys.EncodeOwnerKey(ownerKey, manufacturer.KeyType));
        RequireOwnerSuite(exchange, owner);
        FdoVerifiedDelegateChain verified = FdoTo2DelegatePolicy.Verify(
            delegateSigner.Chain, owner.Encoded, exchange, delegateSigner.VerificationTime,
            captureRevocationTargets: delegateSigner.OfflineRevocation is not null);
        RequireDelegateSigningKey(verified, delegateSigner.SigningKey);
        verified.RequireOfflineStatus(delegateSigner.OfflineRevocation, delegateSigner.VerificationTime);
        return verified;
    }

    /// <summary>
    /// Requires the signing key to be the verified Delegate leaf key and
    /// returns its COSE algorithm.
    /// </summary>
    /// <param name="verified">The previously verified data for this operation.</param>
    /// <param name="signingKey">The private key that signs the encoded value.</param>
    /// <exception cref="CryptographicException">
    /// The Delegate signing key is not the Delegate leaf certificate key.
    /// </exception>
    internal FdoCoseSignatureAlgorithm RequireDelegateSigningKey(
        FdoVerifiedDelegateChain verified, AsymmetricAlgorithm signingKey)
    {
        ArgumentNullException.ThrowIfNull(verified);
        ArgumentNullException.ThrowIfNull(signingKey);
        using FdoPublicKeyCodec.DecodedKey leaf = _keys.Decode(verified.DelegateKey);
        using FdoPublicKeyCodec.DecodedKey signer = _keys.Decode(_keys.EncodeOwnerKey(signingKey, leaf.KeyType));
        if (!leaf.HasSamePublicKey(signer))
        {
            throw new CryptographicException("The Delegate signing key is not the Delegate leaf certificate key.");
        }

        return leaf.Algorithm;
    }

    /// <summary>
    /// Verifies the Owner signature and freshness using its early advertised
    /// key, checks the Device's voucher credentials, and returns a pending
    /// verifier. The early key is not trusted until all entries are checked.
    /// </summary>
    /// <param name="encodedProof">The exact encoded proof to read or verify.</param>
    /// <param name="expectedOwnerNonce">The Owner nonce that the proof must echo.</param>
    /// <param name="exchange">The selected key exchange suite.</param>
    /// <param name="expectedGuid">The independently known Device GUID.</param>
    /// <param name="expectedManufacturerKeyHash">The provisioned hash of the manufacturer key.</param>
    /// <param name="expectedHmacAlgorithm">The HMAC algorithm required by the provisioned credential.</param>
    /// <param name="deviceHmacSecret">The Device's voucher HMAC key.</param>
    /// <param name="delegateVerificationTime">The instant used to check the Delegate certificates.</param>
    /// <param name="captureRevocationTargets">
    /// Whether to retain the verified issuer path for offline status checks.
    /// </param>
    public PendingOwnerProof BeginDeviceVerification(
        ReadOnlyMemory<byte> encodedProof,
        ReadOnlyMemory<byte> expectedOwnerNonce,
        FdoKeyExchangeSuite exchange,
        ReadOnlySpan<byte> expectedGuid,
        FdoHashValue expectedManufacturerKeyHash,
        FdoHashAlgorithm expectedHmacAlgorithm,
        ReadOnlySpan<byte> deviceHmacSecret,
        DateTimeOffset? delegateVerificationTime = null,
        bool captureRevocationTargets = false)
    {
        (OwnerFields fields, ReadOnlyMemory<byte> ownerKey, FdoVerifiedDelegateChain? delegated) =
            ReadEarlyDeviceProof(encodedProof, expectedOwnerNonce, exchange, delegateVerificationTime, captureRevocationTargets);
        FdoOwnershipVoucherChainVerifier voucher = NewVoucher(
            fields.HeaderTag, fields.HeaderHmac, fields.EntryCount);
        bool completed = false;
        try
        {
            voucher.CheckDeviceCredentials(
                expectedGuid, expectedManufacturerKeyHash, expectedHmacAlgorithm, deviceHmacSecret);
            var pending = new PendingOwnerProof(
                voucher, fields.EntryCount, ownerKey,
                fields.OwnerParameter, fields.MaxOwnerMessageSize, fields.HeaderTag, delegated);
            completed = true;
            return pending;
        }
        finally
        {
            if (!completed)
            {
                voucher.Dispose();
            }
        }
    }

    /// <summary>
    /// Verifies the early proof and Device credentials using a host-owned
    /// HMAC handle. The voucher entries must still be checked.
    /// </summary>
    /// <param name="encodedProof">The exact encoded proof to read or verify.</param>
    /// <param name="expectedOwnerNonce">The Owner nonce that the proof must echo.</param>
    /// <param name="exchange">The selected key exchange suite.</param>
    /// <param name="expectedGuid">The independently known Device GUID.</param>
    /// <param name="expectedManufacturerKeyHash">The provisioned hash of the manufacturer key.</param>
    /// <param name="expectedHmacAlgorithm">The HMAC algorithm required by the provisioned credential.</param>
    /// <param name="computeHmac">The host callback that computes the voucher HMAC without exporting its key.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <param name="delegateVerificationTime">The instant used to check the Delegate certificates.</param>
    /// <param name="captureRevocationTargets">
    /// Whether to retain the verified issuer path for offline status checks.
    /// </param>
    public async ValueTask<PendingOwnerProof> BeginDeviceVerificationAsync(
        ReadOnlyMemory<byte> encodedProof,
        ReadOnlyMemory<byte> expectedOwnerNonce,
        FdoKeyExchangeSuite exchange,
        ReadOnlyMemory<byte> expectedGuid,
        FdoHashValue expectedManufacturerKeyHash,
        FdoHashAlgorithm expectedHmacAlgorithm,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<ReadOnlyMemory<byte>>> computeHmac,
        CancellationToken cancellationToken,
        DateTimeOffset? delegateVerificationTime = null,
        bool captureRevocationTargets = false)
    {
        (OwnerFields fields, ReadOnlyMemory<byte> ownerKey, FdoVerifiedDelegateChain? delegated) =
            ReadEarlyDeviceProof(encodedProof, expectedOwnerNonce, exchange, delegateVerificationTime, captureRevocationTargets);
        FdoOwnershipVoucherChainVerifier voucher = NewVoucher(
            fields.HeaderTag, fields.HeaderHmac, fields.EntryCount);
        bool completed = false;
        try
        {
            await voucher.CheckDeviceCredentialsAsync(
                expectedGuid, expectedManufacturerKeyHash, expectedHmacAlgorithm,
                computeHmac, cancellationToken).ConfigureAwait(false);
            var pending = new PendingOwnerProof(
                voucher, fields.EntryCount, ownerKey,
                fields.OwnerParameter, fields.MaxOwnerMessageSize, fields.HeaderTag, delegated);
            completed = true;
            return pending;
        }
        finally
        {
            if (!completed)
            {
                voucher.Dispose();
            }
        }
    }

    private (OwnerFields Fields, ReadOnlyMemory<byte> OwnerKey, FdoVerifiedDelegateChain? Delegate) ReadEarlyDeviceProof(
        ReadOnlyMemory<byte> encodedProof,
        ReadOnlyMemory<byte> expectedOwnerNonce,
        FdoKeyExchangeSuite exchange,
        DateTimeOffset? delegateVerificationTime,
        bool captureRevocationTargets)
    {
        byte[] expectedNonce = CopyNonce(expectedOwnerNonce);
        ReadOnlyMemory<byte> proof = _cbor.ValidateAndCopy(encodedProof);
        ReadOnlyMemory<byte> untrustedPayload = ReadUntrustedPayload(proof);
        (ReadOnlyMemory<byte> advertisedKey, ReadOnlyMemory<byte> encodedChain) = ReadAdvertisedKey(untrustedPayload);
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(advertisedKey);
        RequireOwnerSuite(exchange, owner);
        FdoVerifiedDelegateChain? delegated = null;
        if (!encodedChain.IsEmpty)
        {
            if (delegateVerificationTime is not DateTimeOffset now)
            {
                throw new NotSupportedException("Delegated Owner proofs were not enabled.");
            }

            IReadOnlyList<ReadOnlyMemory<byte>> chain = new FdoX5ChainCodec(_maxEncodedBytes, _maxItems).Decode(encodedChain);
            delegated = FdoTo2DelegatePolicy.Verify(chain, owner.Encoded, exchange, now, captureRevocationTargets);
        }

        ReadOnlyMemory<byte> verifiedPayload;
        if (delegated is null)
        {
            verifiedPayload = owner.VerifySignature(_signatures, FdoSignatureOperation.TO2ProveOVHdr, proof);
        }
        else
        {
            using FdoPublicKeyCodec.DecodedKey signer = _keys.Decode(delegated.DelegateKey);
            verifiedPayload = signer.VerifySignature(_signatures, FdoSignatureOperation.TO2ProveOVHdr, proof);
        }

        OwnerFields fields = ReadOwnerFields(verifiedPayload, delegated is not null);
        if (!CryptographicOperations.FixedTimeEquals(fields.Nonce.Span, expectedNonce))
        {
            throw new CryptographicException("The Owner proof nonce does not match the Device challenge.");
        }

        FdoKeyExchangeSuites.RequireParameterShape(exchange, isOwner: true, fields.OwnerParameter.Span);
        return (fields, owner.Encoded, delegated);
    }

    private FdoOwnershipVoucherChainVerifier NewVoucher(
        ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> hmac, int entryCount) =>
        new(header, hmac, entryCount, _maxEncodedBytes, _maxDepth, _maxItems);

    private ReadOnlyMemory<byte> ReadUntrustedPayload(ReadOnlyMemory<byte> proof)
    {
        var reader = new CborReader(proof, CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.Tag || reader.ReadTag() != (CborTag)18 ||
            reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 4)
        {
            throw new CborContentException("The Owner proof requires a tagged COSE_Sign1.");
        }

        reader.ReadEncodedValue();
        reader.ReadEncodedValue();
        ReadOnlyMemory<byte> payload = ReadBytes(reader);
        reader.ReadEncodedValue();
        reader.ReadEndArray();
        return _cbor.ValidateEmbeddedValueAndCopy(payload);
    }

    /// <summary>Returns OwnerPubKey and the encoded Delegate chain, which is empty when null.</summary>
    /// <param name="payload">The payload of the FDO message.</param>
    private static (ReadOnlyMemory<byte> Key, ReadOnlyMemory<byte> Chain) ReadAdvertisedKey(ReadOnlyMemory<byte> payload)
    {
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        RequireArray(reader, 8);
        for (int i = 0; i < 6; i++)
        {
            reader.ReadEncodedValue();
        }

        ReadOnlyMemory<byte> key = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> chain = default;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
        }
        else
        {
            chain = reader.ReadEncodedValue();
        }

        reader.ReadEndArray();
        return (key, chain);
    }

    private static OwnerFields ReadOwnerFields(ReadOnlyMemory<byte> payload, bool delegated)
    {
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        RequireArray(reader, 8);
        ReadOnlyMemory<byte> header = reader.ReadEncodedValue();
        ulong entryCount = ReadUnsigned(reader);
        if (entryCount is 0 or > byte.MaxValue)
        {
            throw new CborContentException("Paired onboarding requires between 1 and 255 voucher entries.");
        }

        ReadOnlyMemory<byte> hmac = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> nonce = ReadBytes(reader);
        if (nonce.Length != NonceLength)
        {
            throw new CborContentException("The Owner proof nonce must contain exactly 16 bytes.");
        }

        ReadOnlyMemory<byte> parameter = ReadBytes(reader);
        ulong maxSize = ReadUnsigned(reader);
        if (maxSize > ushort.MaxValue)
        {
            throw new CborContentException("The Owner message size must fit in uint16.");
        }

        reader.ReadEncodedValue();
        if ((reader.PeekState() == CborReaderState.Null) == delegated)
        {
            throw new CborContentException("The Owner proof Delegate field does not match its signer.");
        }

        reader.SkipValue();
        reader.ReadEndArray();
        return new OwnerFields(header, (int)entryCount, hmac, nonce, parameter, (ushort)maxSize);
    }

    internal static void RequireOwnerSuite(FdoKeyExchangeSuite exchange, FdoPublicKeyCodec.DecodedKey key)
    {
        bool matches = exchange switch
        {
            FdoKeyExchangeSuite.Ecdh256 => key.KeyType == 10,
            FdoKeyExchangeSuite.Ecdh384 => key.KeyType == 11,
            FdoKeyExchangeSuite.DhkexId14 or FdoKeyExchangeSuite.Asymkex2048 =>
                key.KeyType is FdoPublicKeyCodec.Rsa2048Restricted or FdoPublicKeyCodec.RsaPkcs
                && key.Algorithm == FdoCoseSignatureAlgorithm.RS256,
            FdoKeyExchangeSuite.DhkexId15 or FdoKeyExchangeSuite.Asymkex3072 =>
                key.KeyType == FdoPublicKeyCodec.RsaPkcs && key.Algorithm == FdoCoseSignatureAlgorithm.RS384,
            _ => throw new ArgumentOutOfRangeException(nameof(exchange)),
        };
        if (!matches)
        {
            throw new CryptographicException("The key-exchange suite does not match the Owner key.");
        }
    }

    private static byte[] CopyNonce(ReadOnlyMemory<byte> nonce)
    {
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException("The Owner-proof nonce must contain exactly 16 bytes.", nameof(nonce));
        }

        return nonce.ToArray();
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The Owner proof has the wrong payload shape.");
        }
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The Owner proof field must be an unsigned integer.");
        }

        return reader.ReadUInt64();
    }

    private static ReadOnlyMemory<byte> ReadBytes(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The Owner proof field must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }

    private sealed record OwnerFields(
        ReadOnlyMemory<byte> HeaderTag,
        int EntryCount,
        ReadOnlyMemory<byte> HeaderHmac,
        ReadOnlyMemory<byte> Nonce,
        ReadOnlyMemory<byte> OwnerParameter,
        ushort MaxOwnerMessageSize);

    /// <summary>
    /// Holds the checked early proof while the Device verifies each voucher
    /// entry. The Owner parameter is unavailable until completion succeeds.
    /// </summary>
    public sealed class PendingOwnerProof : IDisposable
    {
        private readonly FdoOwnershipVoucherChainVerifier _voucher;
        private readonly ReadOnlyMemory<byte> _ownerKey;
        private readonly ReadOnlyMemory<byte> _ownerParameter;
        private readonly ushort _maxOwnerMessageSize;
        private readonly ReadOnlyMemory<byte> _headerTag;
        private readonly FdoVerifiedDelegateChain? _delegate;
        private bool _closed;

        internal PendingOwnerProof(
            FdoOwnershipVoucherChainVerifier voucher,
            int entryCount,
            ReadOnlyMemory<byte> ownerKey,
            ReadOnlyMemory<byte> ownerParameter,
            ushort maxOwnerMessageSize,
            ReadOnlyMemory<byte> headerTag,
            FdoVerifiedDelegateChain? delegated = null)
        {
            _voucher = voucher;
            _delegate = delegated;
            EntryCount = entryCount;
            _ownerKey = ownerKey;
            _ownerParameter = ownerParameter;
            _maxOwnerMessageSize = maxOwnerMessageSize;
            _headerTag = headerTag.ToArray();
        }

        public int EntryCount { get; }

        public void AppendEntry(int index, ReadOnlyMemory<byte> encodedEntry)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            bool completed = false;
            try
            {
                _voucher.AppendEntry(index, encodedEntry);
                completed = true;
            }
            finally
            {
                if (!completed)
                {
                    Dispose();
                }
            }
        }

        /// <summary>
        /// Returns the signed Owner key and exchange parameter after the voucher
        /// has verified. Rendezvous redirect validation, when applicable, is
        /// still required before deriving or using session keys.
        /// </summary>
        public OwnerProof CompleteDeviceChecks()
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            try
            {
                ReadOnlyMemory<byte> exactOwnerKey = _voucher.CompleteDeviceChecks(_ownerKey);
                return new OwnerProof(exactOwnerKey, _ownerParameter, _maxOwnerMessageSize, _headerTag, _delegate);
            }
            finally
            {
                Dispose();
            }
        }

        public void Dispose()
        {
            _voucher.Dispose();
            _closed = true;
        }
    }

    /// <summary>
    /// Owner proof and voucher results. This does not verify a TO1 redirect or
    /// establish that rendezvous bypass was configured.
    /// </summary>
    public sealed class OwnerProof
    {
        private readonly byte[] _ownerKey;
        private readonly byte[] _ownerParameter;
        private readonly byte[] _headerTag;

        internal OwnerProof(
            ReadOnlyMemory<byte> ownerKey,
            ReadOnlyMemory<byte> ownerParameter,
            ushort maxOwnerMessageSize,
            ReadOnlyMemory<byte> headerTag = default,
            FdoVerifiedDelegateChain? delegated = null)
        {
            _ownerKey = ownerKey.ToArray();
            _ownerParameter = ownerParameter.ToArray();
            _headerTag = headerTag.ToArray();
            MaxOwnerMessageSize = maxOwnerMessageSize;
            Delegate = delegated;
        }

        /// <summary>The voucher's final Owner key, bound to the voucher.</summary>
        public ReadOnlyMemory<byte> OwnerKey => (byte[])_ownerKey.Clone();

        /// <summary>
        /// The key that signed the proof and that must sign a reuse
        /// SetupDevice: the Delegate leaf key, or the Owner key without a Delegate.
        /// </summary>
        public ReadOnlyMemory<byte> SigningKey => Delegate is null ? OwnerKey : Delegate.DelegateKey;

        /// <summary>
        /// The verified Delegate chain, or null for a nondelegated proof. The
        /// Device host must still accept the Delegate before key derivation.
        /// </summary>
        public FdoVerifiedDelegateChain? Delegate { get; }

        public ReadOnlyMemory<byte> OwnerParameter => (byte[])_ownerParameter.Clone();

        public ReadOnlyMemory<byte> HeaderTag => (byte[])_headerTag.Clone();

        public ushort MaxOwnerMessageSize { get; }
    }

    /// <summary>
    /// A Delegate that signs the Owner proof: its private key, its leaf-first
    /// certificate chain, and the time at which the chain must be valid.
    /// </summary>
    /// <param name="SigningKey">The private key that signs the encoded value.</param>
    /// <param name="Chain">The ordered certificates that make up the chain.</param>
    /// <param name="VerificationTime">The instant used to evaluate certificate validity.</param>
    /// <param name="OfflineRevocation">The optional offline status policy for the Delegate path.</param>
    public sealed record DelegateSigner(
        AsymmetricAlgorithm SigningKey,
        IReadOnlyList<ReadOnlyMemory<byte>> Chain,
        DateTimeOffset VerificationTime,
        FdoDelegateOfflineRevocationPolicy? OfflineRevocation = null);
}
