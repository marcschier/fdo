using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Checks a 2.0 voucher header and its ordered ownership entries.
/// Internal consistency does not establish supply-chain trust or verify the
/// Owner's separate proof. Only the supported X.509-encoded EC and RSA keys are accepted.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoOwnershipVoucherChainVerifier : IDisposable
{
    private const int GuidLength = 16;
    private readonly FdoCborCodec _cbor;
    private readonly FdoPublicKeyCodec _keys;
    private readonly FdoCoseSign1Codec _signatures;
    private readonly FdoCertificateChainHash _certificateChains;
    private readonly int _entryCount;
    private readonly int _keyType;
    private readonly FdoCoseSignatureAlgorithm _keyAlgorithm;
    private readonly ReadOnlyMemory<byte> _header;
    private readonly ReadOnlyMemory<byte> _guid;
    private readonly ReadOnlyMemory<byte> _manufacturerKey;
    private readonly byte[] _headerInfo;
    private readonly FdoHashValue _headerHmac;
    private readonly FdoHashValue _deviceCertificateChainHash;
    private ReadOnlyMemory<byte> _previousHashInput;
    private FdoPublicKeyCodec.DecodedKey? _currentKey;
    private FdoHashAlgorithm? _previousHashAlgorithm;
    private int _nextEntry;
    private bool _deviceCredentialsChecked;
    private bool _closed;

    /// <summary>
    /// Starts an untrusted chain. The header tag includes its byte-string
    /// wrapper; the HMAC is the exact encoded FDO HMac value.
    /// </summary>
    public FdoOwnershipVoucherChainVerifier(
        ReadOnlyMemory<byte> encodedHeaderTag,
        ReadOnlyMemory<byte> encodedHeaderHmac,
        int entryCount,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        if (entryCount is < 0 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(entryCount));
        }

        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _keys = new FdoPublicKeyCodec(maxEncodedBytes, maxDepth, maxItems);
        _signatures = new FdoCoseSign1Codec(maxEncodedBytes, maxDepth, maxItems);
        _certificateChains = new FdoCertificateChainHash(maxEncodedBytes, maxItems);
        _entryCount = entryCount;
        FdoOwnershipVoucherHeader parsed = FdoOwnershipVoucherHeader.Decode(encodedHeaderTag, _cbor);
        ReadOnlyMemory<byte> header = parsed.Contents;
        ReadOnlyMemory<byte> encodedHmac = _cbor.ValidateAndCopy(encodedHeaderHmac);
        FdoHashValue hmac = FdoHashValue.Decode(encodedHmac);
        if (!hmac.IsHmac)
        {
            throw new CborContentException("An ownership voucher header requires an HMAC.");
        }

        ReadOnlyMemory<byte> guid = parsed.Guid;
        FdoPublicKeyCodec.DecodedKey manufacturer = _keys.Decode(parsed.ManufacturerKey);
        bool completed = false;
        try
        {
            _header = header;
            _guid = guid;
            _manufacturerKey = manufacturer.Encoded;
            _keyType = manufacturer.KeyType;
            _keyAlgorithm = manufacturer.Algorithm;
            _currentKey = manufacturer;
            _headerInfo = parsed.CreateHeaderInfo();
            _headerHmac = hmac;
            _deviceCertificateChainHash = parsed.CertificateChainHash;
            _previousHashInput = parsed.CreateInitialEntryHashInput(encodedHmac.Span);
            completed = true;
        }
        finally
        {
            if (!completed)
            {
                manufacturer.Dispose();
            }
        }
    }

    /// <summary>
    /// Checks the ordered certificate contents against this voucher header and
    /// returns an owned encoding. The header may still be untrusted. A match
    /// does not validate certificates, establish Device trust, or verify proof
    /// of possession; the role must bind those checks to this same run.
    /// </summary>
    public ReadOnlyMemory<byte> CheckDeviceCertificateChain(ReadOnlyMemory<byte> encodedChain)
    {
        ThrowIfClosed();
        bool completed = false;
        try
        {
            ReadOnlyMemory<byte> owned = _cbor.ValidateAndCopy(encodedChain);
            if (!_certificateChains.Verify(
                _deviceCertificateChainHash.Algorithm, owned, _deviceCertificateChainHash))
            {
                throw new CryptographicException("The Device certificate chain does not match the voucher header.");
            }

            completed = true;
            return owned;
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
    /// Checks the received header against the Device's provisioned GUID,
    /// manufacturer-key hash, and HMAC secret. It does not verify the Owner's
    /// proof or, when rendezvous was used, the signed redirect.
    /// </summary>
    public void CheckDeviceCredentials(
        ReadOnlySpan<byte> expectedGuid,
        FdoHashValue expectedManufacturerKeyHash,
        FdoHashAlgorithm expectedHmacAlgorithm,
        ReadOnlySpan<byte> deviceHmacSecret)
    {
        ThrowIfClosed();
        bool completed = false;
        try
        {
            FdoDeviceHmacSecretPolicy.ValidateLength(expectedHmacAlgorithm, deviceHmacSecret.Length);
            CheckDeviceAnchors(expectedGuid, expectedManufacturerKeyHash);

            if (!_headerHmac.MatchesHmac(expectedHmacAlgorithm, deviceHmacSecret, _header.Span))
            {
                throw new CryptographicException("The ownership voucher header HMAC did not verify.");
            }

            _deviceCredentialsChecked = true;
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
    /// Checks the Device anchors and compares the header HMAC computed by
    /// the host without requesting the secret bytes.
    /// </summary>
    public async ValueTask CheckDeviceCredentialsAsync(
        ReadOnlyMemory<byte> expectedGuid,
        FdoHashValue expectedManufacturerKeyHash,
        FdoHashAlgorithm expectedHmacAlgorithm,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<ReadOnlyMemory<byte>>> computeHmac,
        CancellationToken cancellationToken)
    {
        ThrowIfClosed();
        bool completed = false;
        try
        {
            ArgumentNullException.ThrowIfNull(computeHmac);
            _ = FdoDeviceHmacSecretPolicy.GetRequiredLength(expectedHmacAlgorithm);
            CheckDeviceAnchors(expectedGuid.Span, expectedManufacturerKeyHash);
            if (_headerHmac.Algorithm != expectedHmacAlgorithm)
            {
                throw new CryptographicException("The ownership voucher header HMAC did not verify.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            ReadOnlyMemory<byte> result = await computeHmac(
                _header.ToArray(), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            int expectedLength = expectedHmacAlgorithm == FdoHashAlgorithm.HmacSha256
                ? HMACSHA256.HashSizeInBytes : HMACSHA384.HashSizeInBytes;
            if (result.Length != expectedLength)
            {
                throw new CryptographicException("The ownership voucher header HMAC did not verify.");
            }

            byte[] computed = result.ToArray();
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_headerHmac.MatchesComputedHmac(expectedHmacAlgorithm, computed))
                {
                    throw new CryptographicException("The ownership voucher header HMAC did not verify.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(computed);
            }

            _deviceCredentialsChecked = true;
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
    /// Verifies the next complete tagged COSE_Sign1 entry and advances to its
    /// signed next-owner key. A failed check closes the verifier.
    /// </summary>
    public void AppendEntry(int index, ReadOnlyMemory<byte> encodedEntry)
    {
        ThrowIfClosed();
        FdoPublicKeyCodec.DecodedKey? nextKey = null;
        bool completed = false;
        try
        {
            if (index != _nextEntry || _nextEntry >= _entryCount)
            {
                throw new InvalidOperationException("The ownership voucher entry is out of order.");
            }

            ReadOnlyMemory<byte> entry = _cbor.ValidateAndCopy(encodedEntry);
            ReadOnlyMemory<byte> payload = _currentKey!.VerifySignature(
                _signatures, FdoSignatureOperation.OVEntry, entry);
            var reader = new CborReader(payload, CborConformanceMode.Strict);
            RequireArray(reader, 4);
            FdoHashValue previousHash = FdoHashValue.Decode(reader.ReadEncodedValue());
            FdoHashValue headerInfoHash = FdoHashValue.Decode(reader.ReadEncodedValue());
            ReadExtra(reader);
            ReadOnlyMemory<byte> encodedNextKey = reader.ReadEncodedValue();
            reader.ReadEndArray();

            if (previousHash.IsHmac ||
                (_previousHashAlgorithm is FdoHashAlgorithm selected && previousHash.Algorithm != selected) ||
                !previousHash.MatchesDigest(previousHash.Algorithm, _previousHashInput.Span))
            {
                throw new CryptographicException("The ownership voucher previous-entry hash did not verify.");
            }

            if (headerInfoHash.IsHmac ||
                !headerInfoHash.MatchesDigest(headerInfoHash.Algorithm, _headerInfo))
            {
                throw new CryptographicException("The ownership voucher header-info hash did not verify.");
            }

            nextKey = _keys.Decode(encodedNextKey);
            if (nextKey.KeyType != _keyType || nextKey.Algorithm != _keyAlgorithm)
            {
                throw new CryptographicException("The ownership voucher public-key type or algorithm changed within the chain.");
            }

            _currentKey.Dispose();
            _currentKey = nextKey;
            nextKey = null;
            _previousHashAlgorithm = previousHash.Algorithm;
            _previousHashInput = entry;
            _nextEntry++;
            completed = true;
        }
        finally
        {
            nextKey?.Dispose();
            if (!completed)
            {
                Dispose();
            }
        }
    }

    /// <summary>
    /// Completes internal chain checks and compares the final key with the
    /// advertised Owner key. This alone does not establish trust.
    /// </summary>
    /// <returns>The verified previous-entry hash algorithm, or null for a zero-entry voucher.</returns>
    public FdoHashAlgorithm? CompleteInternalConsistency(ReadOnlyMemory<byte> advertisedOwnerKey)
    {
        Complete(advertisedOwnerKey, requireDeviceCredentials: false);
        return _previousHashAlgorithm;
    }

    /// <summary>
    /// Completes the non-remanufacturing Owner checks and binds the supplied
    /// certificate chain to this header. Manufacturer and Device trust remain
    /// the caller's responsibility.
    /// </summary>
    public CheckedOwnerVoucher CompleteOwnerChecks(
        ReadOnlyMemory<byte> ownerKey,
        ReadOnlyMemory<byte> encodedDeviceCertificateChain)
    {
        ThrowIfClosed();
        try
        {
            if (_entryCount == 0)
            {
                throw new InvalidOperationException("Paired onboarding requires at least one voucher entry.");
            }

            ReadOnlyMemory<byte> checkedChain = CheckDeviceCertificateChain(encodedDeviceCertificateChain);
            ReadOnlyMemory<byte> exactOwnerKey = Complete(ownerKey, requireDeviceCredentials: false);
            return new CheckedOwnerVoucher(_guid, _manufacturerKey, checkedChain, exactOwnerKey);
        }
        finally
        {
            Dispose();
        }
    }

    /// <summary>
    /// Completes the ordered voucher checks and returns its final Owner key.
    /// The caller must still establish manufacturer and Device trust and
    /// verify the Owner's separate signature.
    /// </summary>
    public CheckedRendezvousVoucher CompleteRendezvousChecks(
        ReadOnlyMemory<byte> encodedDeviceCertificateChain)
    {
        ThrowIfClosed();
        try
        {
            if (_entryCount == 0 || _nextEntry != _entryCount)
            {
                throw new InvalidOperationException("Rendezvous requires a complete voucher with at least one entry.");
            }

            ReadOnlyMemory<byte> ownerKey = _currentKey!.Encoded.ToArray();
            CheckedOwnerVoucher voucher = CompleteOwnerChecks(ownerKey, encodedDeviceCertificateChain);
            return new CheckedRendezvousVoucher(voucher, ownerKey);
        }
        finally
        {
            Dispose();
        }
    }

    /// <summary>
    /// Requires the Device credential checks as well as internal chain checks.
    /// The caller must still verify the Owner proof using this same key.
    /// </summary>
    public ReadOnlyMemory<byte> CompleteDeviceChecks(ReadOnlyMemory<byte> advertisedOwnerKey) =>
        Complete(advertisedOwnerKey, requireDeviceCredentials: true);

    public void Dispose()
    {
        _currentKey?.Dispose();
        _currentKey = null;
        _closed = true;
    }

    public sealed record CheckedOwnerVoucher(
        ReadOnlyMemory<byte> Guid,
        ReadOnlyMemory<byte> ManufacturerKey,
        ReadOnlyMemory<byte> DeviceCertificateChain,
        ReadOnlyMemory<byte> OwnerKey);

    public sealed record CheckedRendezvousVoucher(
        CheckedOwnerVoucher Voucher,
        ReadOnlyMemory<byte> OwnerKey);

    private void CheckDeviceAnchors(ReadOnlySpan<byte> expectedGuid, FdoHashValue expectedManufacturerKeyHash)
    {
        ArgumentNullException.ThrowIfNull(expectedManufacturerKeyHash);
        if (expectedGuid.Length != GuidLength)
        {
            throw new ArgumentException("The provisioned Device GUID must contain 16 bytes.", nameof(expectedGuid));
        }

        if (!CryptographicOperations.FixedTimeEquals(_guid.Span, expectedGuid))
        {
            throw new CryptographicException("The ownership voucher GUID does not match the Device credential.");
        }

        if (expectedManufacturerKeyHash.IsHmac ||
            !expectedManufacturerKeyHash.MatchesDigest(
                expectedManufacturerKeyHash.Algorithm, _manufacturerKey.Span))
        {
            throw new CryptographicException("The ownership voucher manufacturer key does not match the Device credential.");
        }
    }

    private ReadOnlyMemory<byte> Complete(ReadOnlyMemory<byte> advertisedOwnerKey, bool requireDeviceCredentials)
    {
        ThrowIfClosed();
        try
        {
            if (_nextEntry != _entryCount)
            {
                throw new InvalidOperationException("The ownership voucher chain is incomplete.");
            }

            if (requireDeviceCredentials && !_deviceCredentialsChecked)
            {
                throw new InvalidOperationException("The Device credential checks have not completed.");
            }

            using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(advertisedOwnerKey);
            if (!_currentKey!.HasSamePublicKey(owner))
            {
                throw new CryptographicException("The advertised Owner key does not match the voucher chain.");
            }

            return _currentKey.Encoded;
        }
        finally
        {
            Dispose();
        }
    }

    private void ReadExtra(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return;
        }

        ReadOnlyMemory<byte> encoded = _cbor.ValidateEmbeddedValueAndCopy(ReadByteString(reader));
        var extra = new CborReader(encoded, CborConformanceMode.Strict);
        if (extra.PeekState() != CborReaderState.StartMap)
        {
            throw new CborContentException("An ownership voucher extra field must contain a CBOR map.");
        }

        int count = extra.ReadStartMap()
            ?? throw new CborContentException("The ownership voucher extra map must have a definite length.");
        for (int i = 0; i < count; i++)
        {
            if (extra.PeekState() == CborReaderState.NegativeInteger)
            {
                extra.ReadCborNegativeIntegerRepresentation();
            }
            else
            {
                ReadUnsigned(extra);
            }

            ReadByteString(extra);
        }

        extra.ReadEndMap();
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The ownership voucher array has the wrong number of fields.");
        }
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("An ownership voucher integer must be unsigned.");
        }

        return reader.ReadUInt64();
    }

    private static ReadOnlyMemory<byte> ReadByteString(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The ownership voucher field must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }

    private void ThrowIfClosed() => ObjectDisposedException.ThrowIf(_closed, this);
}
