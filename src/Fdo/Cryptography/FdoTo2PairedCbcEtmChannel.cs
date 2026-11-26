// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Protects an explicitly paired, ordered TO2 exchange with AES-CBC and
/// HMAC. Both directions use fresh random IVs. The channel tracks IVs used in
/// either direction to reject replay, reflection, and IV collisions.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2PairedCbcEtmChannel : IFdoTo2PairedChannel
{
    private const int MaximumIvs = 2_000_000;
    private readonly object _sync = new();
    private readonly FdoCoseAeadAlgorithm _suite;
    private readonly FdoCoseEncryptThenMacCodec _codec;
    private readonly byte[] _verificationKey;
    private readonly byte[] _encryptionKey;
    private readonly HashSet<Guid> _usedIvs = [];
    private readonly int _maxIvs;
    private bool _expectSend;
    private bool _closed;

    public FdoTo2PairedCbcEtmChannel(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> sessionKey,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
        : this(role, suite, sessionKey, maxEncodedBytes, maxDepth, maxItems, MaximumIvs)
    {
    }

    internal FdoTo2PairedCbcEtmChannel(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> sessionKey,
        int maxEncodedBytes,
        int maxDepth,
        int maxItems,
        int maxIvs)
    {
        _expectSend = role switch
        {
            FdoTo2PairedRole.Device => true,
            FdoTo2PairedRole.Owner => false,
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };
        if (!FdoTo2CipherSuites.IsAesCbc(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "The suite is not an AES-CBC suite.");
        }

        FdoTo2CipherSuites.EncryptThenMacParameters parameters = FdoTo2CipherSuites.GetEncryptThenMacParameters(suite);
        if (sessionKey.Length != parameters.VerificationKeySize + parameters.EncryptionKeySize)
        {
            throw new ArgumentException("The session key length does not match the selected suite.", nameof(sessionKey));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxIvs);
        if (!FdoAesCbc.IsSupported)
        {
            throw new PlatformNotSupportedException("AES-CBC is not available on this platform.");
        }

        _codec = new FdoCoseEncryptThenMacCodec(maxEncodedBytes, maxDepth, maxItems);
        _suite = suite;
        _verificationKey = sessionKey[..parameters.VerificationKeySize].ToArray();
        _encryptionKey = sessionKey[parameters.VerificationKeySize..].ToArray();
        _maxIvs = maxIvs;
    }

    /// <inheritdoc/>
    public long GetSealedLength(int plaintextLength) =>
        FdoCoseEncryptThenMacCodec.GetEncodedLength(_suite, plaintextLength);

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> Seal(ReadOnlyMemory<byte> encodedPlaintext)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            bool completed = false;
            try
            {
                if (!_expectSend)
                {
                    throw new InvalidOperationException("The paired TO2 channel is awaiting a message.");
                }

                byte[] iv = RandomNumberGenerator.GetBytes(FdoAesCbc.BlockSize);
                ReserveIv(iv);
                ReadOnlyMemory<byte> result = _codec.Encrypt(
                    _suite, _verificationKey, _encryptionKey, iv, encodedPlaintext);
                _expectSend = false;
                completed = true;
                return result;
            }
            finally
            {
                if (!completed)
                {
                    Close();
                }
            }
        }
    }

    /// <inheritdoc/>
    public byte[] Open(ReadOnlyMemory<byte> encoded)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            byte[]? plaintext = null;
            bool completed = false;
            try
            {
                if (_expectSend)
                {
                    throw new InvalidOperationException("The paired TO2 channel is awaiting a local message.");
                }

                FdoCoseEncryptThenMacCodec.AuthenticatedMessage message =
                    _codec.VerifyAndParse(_suite, _verificationKey, encoded);
                ReserveIv(message.CounterBlock);
                plaintext = _codec.Decrypt(_suite, _encryptionKey, message);
                _expectSend = true;
                completed = true;
                return plaintext;
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("The protected TO2 message is invalid.");
            }
            finally
            {
                if (!completed)
                {
                    if (plaintext is not null)
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }

                    Close();
                }
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            Close();
        }
    }

    private void ReserveIv(ReadOnlySpan<byte> iv)
    {
        if (_usedIvs.Count >= _maxIvs)
        {
            throw new CryptographicException("The paired TO2 IV limit has been reached.");
        }

        if (!_usedIvs.Add(new Guid(iv)))
        {
            throw new CryptographicException("The paired TO2 IV was already used.");
        }
    }

    private void Close()
    {
        CryptographicOperations.ZeroMemory(_verificationKey);
        CryptographicOperations.ZeroMemory(_encryptionKey);
        _usedIvs.Clear();
        _closed = true;
    }
}
