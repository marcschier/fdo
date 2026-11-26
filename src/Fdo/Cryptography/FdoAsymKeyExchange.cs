// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal enum FdoAsymSuite
{
    Asym2048 = 0,
    Asym3072 = 1,
}

internal enum FdoAsymParty
{
    Device = 0,
    Owner = 1,
}

/// <summary>
/// Creates one internal paired RSA-OAEP exchange. The Device key must be
/// provisioned before the exchange and matched to the authenticated voucher
/// Owner before protected data is used. The Owner must authenticate the Device
/// proof before decrypting its parameter. This type does not authenticate peers.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoAsymKeyExchange : IFdoPairedKeyExchange
{
    private readonly object _sync = new();
    private readonly FdoAsymParty _party;
    private readonly int _randomLength;
    private readonly int _ciphertextLength;
    private readonly byte[] _parameter;
    private RSA? _ownerKey;
    private byte[]? _deviceRandom;
    private bool _attempted;
    private bool _disposed;

    private FdoAsymKeyExchange(
        FdoAsymParty party, int randomLength, int ciphertextLength,
        byte[] parameter, RSA? ownerKey, byte[]? deviceRandom)
    {
        _party = party;
        _randomLength = randomLength;
        _ciphertextLength = ciphertextLength;
        _parameter = parameter;
        _ownerKey = ownerKey;
        _deviceRandom = deviceRandom;
    }

    /// <summary>
    /// Creates a Device exchange using a provisioned Owner public key, or an
    /// Owner exchange using its private key. The caller retains key ownership.
    /// </summary>
    /// <param name="suite">The selected cryptographic suite.</param>
    /// <param name="party">The participant whose contribution is being processed.</param>
    /// <param name="ownerKey">The Owner public key that anchors verification.</param>
    /// <exception cref="ArgumentOutOfRangeException">The RSA Owner key does not match the exchange suite.</exception>
    /// <exception cref="CryptographicException">
    /// The RSA Owner key does not match the exchange suite. The RSA provider returned a ciphertext of an unexpected
    /// length.
    /// </exception>
    public static FdoAsymKeyExchange Create(FdoAsymSuite suite, FdoAsymParty party, RSA ownerKey)
    {
        ArgumentNullException.ThrowIfNull(ownerKey);
        if (party is not (FdoAsymParty.Device or FdoAsymParty.Owner))
        {
            throw new ArgumentOutOfRangeException(nameof(party));
        }

        (int keyBits, int randomLength) = suite switch
        {
            FdoAsymSuite.Asym2048 => (2048, 32),
            FdoAsymSuite.Asym3072 => (3072, 96),
            _ => throw new ArgumentOutOfRangeException(nameof(suite)),
        };
        if (ownerKey.KeySize != keyBits)
        {
            throw new CryptographicException("The RSA Owner key does not match the exchange suite.");
        }

        int ciphertextLength = keyBits / 8;
        byte[] random = RandomNumberGenerator.GetBytes(randomLength);
        if (party == FdoAsymParty.Owner)
        {
            return new FdoAsymKeyExchange(party, randomLength, ciphertextLength, random, ownerKey, null);
        }

        bool transferred = false;
        try
        {
            byte[] encrypted = ownerKey.Encrypt(random, RSAEncryptionPadding.OaepSHA256);
            if (encrypted.Length != ciphertextLength)
            {
                throw new CryptographicException("The RSA provider returned a ciphertext of an unexpected length.");
            }

            var exchange = new FdoAsymKeyExchange(party, randomLength, ciphertextLength, encrypted, null, random);
            transferred = true;
            return exchange;
        }
        finally
        {
            if (!transferred)
            {
                CryptographicOperations.ZeroMemory(random);
            }
        }
    }

    public byte[] ExportParameter()
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            return (byte[])_parameter.Clone();
        }
    }

    /// <summary>
    /// Consumes the exchange even on failure. Returns DeviceRandom as ShSe and
    /// OwnerRandom as ContextRand. The caller owns and must clear both arrays.
    /// </summary>
    /// <param name="peerParameter">The peer's contribution to the negotiated key exchange.</param>
    /// <param name="contextRand">The random bytes included in the key derivation context.</param>
    /// <exception cref="CryptographicException">
    /// The decrypted ASYMKEX random has an invalid length. The peer ASYMKEX parameter has an invalid length.
    /// </exception>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerParameter, out byte[] contextRand)
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            _attempted = true;
            byte[]? secret = null;
            try
            {
                int expectedLength = _party == FdoAsymParty.Device ? _randomLength : _ciphertextLength;
                if (peerParameter.Length != expectedLength)
                {
                    throw new CryptographicException("The peer ASYMKEX parameter has an invalid length.");
                }

                if (_party == FdoAsymParty.Device)
                {
                    secret = _deviceRandom!;
                    _deviceRandom = null;
                    contextRand = peerParameter.ToArray();
                }
                else
                {
                    secret = _ownerKey!.Decrypt(peerParameter.ToArray(), RSAEncryptionPadding.OaepSHA256);
                    if (secret.Length != _randomLength)
                    {
                        throw new CryptographicException("The decrypted ASYMKEX random has an invalid length.");
                    }

                    contextRand = (byte[])_parameter.Clone();
                }

                byte[] result = secret;
                secret = null;
                return result;
            }
            finally
            {
                if (secret is not null)
                {
                    CryptographicOperations.ZeroMemory(secret);
                }

                ClearPrivateState();
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (!_disposed)
            {
                _disposed = true;
                ClearPrivateState();
            }
        }
    }

    private void ClearPrivateState()
    {
        if (_deviceRandom is not null)
        {
            CryptographicOperations.ZeroMemory(_deviceRandom);
            _deviceRandom = null;
        }

        _ownerKey = null;
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_attempted)
        {
            throw new InvalidOperationException("The ASYMKEX exchange has already been consumed.");
        }
    }
}
