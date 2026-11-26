// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal enum FdoEcdhParty
{
    Device = 0,
    Owner = 1,
}

/// <summary>
/// Creates one FDO 2.0 ECDH exchange using an ephemeral BCL key. Parameters
/// are untrusted until their enclosing signed messages and voucher chain are
/// authenticated. This type does not verify a peer or establish a session.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoEcdhKeyExchange : IFdoPairedKeyExchange
{
    private readonly object _sync = new();
    private readonly FdoEcdhParty _party;
    private readonly ECCurve _curve;
    private readonly int _coordinateLength;
    private readonly int _randomLength;
    private readonly byte[] _parameter;
    private ECDiffieHellman? _key;
    private bool _attempted;
    private bool _disposed;

    private FdoEcdhKeyExchange(
        FdoEcdhParty party,
        ECCurve curve,
        int coordinateLength,
        int randomLength,
        ECDiffieHellman key,
        byte[] parameter)
    {
        _party = party;
        _curve = curve;
        _coordinateLength = coordinateLength;
        _randomLength = randomLength;
        _key = key;
        _parameter = parameter;
    }

    /// <summary>Generates a new ephemeral key and a fresh exchange random.</summary>
    /// <param name="suite">The selected cryptographic suite.</param>
    /// <param name="party">The participant whose contribution is being processed.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The suite is not ECDH256 or ECDH384, or the party is not Device or Owner.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The ECDH provider returns public coordinates with an unexpected length.
    /// </exception>
    public static FdoEcdhKeyExchange Create(FdoKeyExchangeSuite suite, FdoEcdhParty party)
    {
        if (party is not (FdoEcdhParty.Device or FdoEcdhParty.Owner))
        {
            throw new ArgumentOutOfRangeException(nameof(party));
        }

        (ECCurve curve, int coordinateLength, int randomLength) = suite switch
        {
            FdoKeyExchangeSuite.Ecdh256 => (ECCurve.NamedCurves.nistP256, 32, 16),
            FdoKeyExchangeSuite.Ecdh384 => (ECCurve.NamedCurves.nistP384, 48, 48),
            _ => throw new ArgumentOutOfRangeException(nameof(suite)),
        };

        ECDiffieHellman key = ECDiffieHellman.Create(curve);
        try
        {
            ECParameters publicKey = key.ExportParameters(false);
            if (publicKey.Q.X is not byte[] x || x.Length != coordinateLength ||
                publicKey.Q.Y is not byte[] y || y.Length != coordinateLength)
            {
                throw new CryptographicException("The ECDH provider returned coordinates of an unexpected length.");
            }

            var parameter = new byte[6 + (2 * coordinateLength) + randomLength];
            int offset = 0;
            WriteField(parameter, ref offset, x);
            WriteField(parameter, ref offset, y);
            BinaryPrimitives.WriteUInt16BigEndian(parameter.AsSpan(offset), (ushort)randomLength);
            RandomNumberGenerator.Fill(parameter.AsSpan(offset + 2, randomLength));
            return new FdoEcdhKeyExchange(party, curve, coordinateLength, randomLength, key, parameter);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Returns an owned copy of the local parameter for the signed TO2 message.
    /// For FDO 2.0, Device sends A and Owner sends B.
    /// </summary>
    public byte[] ExportParameter()
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            return (byte[])_parameter.Clone();
        }
    }

    /// <summary>
    /// Consumes the ephemeral key once and returns Shx || DeviceRandom ||
    /// OwnerRandom. The caller must clear the result and must not use it as
    /// key material without the FDO KDF. A failed attempt also consumes the key.
    /// </summary>
    /// <param name="peerParameter">The peer's contribution to the negotiated key exchange.</param>
    /// <exception cref="CryptographicException">
    /// The ECDH provider returned a shared secret of an unexpected length. The peer ECDH parameter has an invalid
    /// length. The peer ECDH public key matches the local ephemeral key.
    /// </exception>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerParameter)
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            _attempted = true;
            byte[]? rawSecret = null;
            try
            {
                int expectedLength = 6 + (2 * _coordinateLength) + _randomLength;
                if (peerParameter.Length != expectedLength)
                {
                    throw new CryptographicException("The peer ECDH parameter has an invalid length.");
                }

                int offset = 0;
                ReadOnlySpan<byte> x = ReadField(peerParameter, ref offset, _coordinateLength);
                ReadOnlySpan<byte> y = ReadField(peerParameter, ref offset, _coordinateLength);
                ReadOnlySpan<byte> peerRandom = ReadField(peerParameter, ref offset, _randomLength);
                ReadOnlySpan<byte> localX = _parameter.AsSpan(2, _coordinateLength);
                ReadOnlySpan<byte> localY = _parameter.AsSpan(4 + _coordinateLength, _coordinateLength);
                if (x.SequenceEqual(localX) && y.SequenceEqual(localY))
                {
                    throw new CryptographicException("The peer ECDH public key matches the local ephemeral key.");
                }

                var peerKey = new ECParameters
                {
                    Curve = _curve,
                    Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() },
                };
                using ECDiffieHellman peer = ImportPeer(peerKey);
                using ECDiffieHellmanPublicKey publicKey = peer.PublicKey;
                rawSecret = _key!.DeriveRawSecretAgreement(publicKey);
                if (rawSecret.Length == 0 || rawSecret.Length > _coordinateLength)
                {
                    throw new CryptographicException("The ECDH provider returned a shared secret of an unexpected length.");
                }

                byte[] result = new byte[_coordinateLength + (2 * _randomLength)];
                rawSecret.CopyTo(result.AsSpan(_coordinateLength - rawSecret.Length));
                ReadOnlySpan<byte> localRandom = _parameter.AsSpan(_parameter.Length - _randomLength);
                if (_party == FdoEcdhParty.Device)
                {
                    localRandom.CopyTo(result.AsSpan(_coordinateLength));
                    peerRandom.CopyTo(result.AsSpan(_coordinateLength + _randomLength));
                }
                else
                {
                    peerRandom.CopyTo(result.AsSpan(_coordinateLength));
                    localRandom.CopyTo(result.AsSpan(_coordinateLength + _randomLength));
                }

                return result;
            }
            finally
            {
                if (rawSecret is not null)
                {
                    CryptographicOperations.ZeroMemory(rawSecret);
                }

                _key!.Dispose();
                _key = null;
            }
        }
    }

    byte[] IFdoPairedKeyExchange.DeriveSharedSecret(ReadOnlySpan<byte> peerParameter, out byte[] contextRand)
    {
        contextRand = Array.Empty<byte>();
        return DeriveSharedSecret(peerParameter);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (!_disposed)
            {
                _disposed = true;
                _key?.Dispose();
                _key = null;
            }
        }
    }

    private static void WriteField(Span<byte> parameter, ref int offset, ReadOnlySpan<byte> field)
    {
        BinaryPrimitives.WriteUInt16BigEndian(parameter[offset..], (ushort)field.Length);
        offset += 2;
        field.CopyTo(parameter[offset..]);
        offset += field.Length;
    }

    private static ECDiffieHellman ImportPeer(ECParameters peerKey)
    {
        try
        {
            return ECDiffieHellman.Create(peerKey);
        }
        catch (PlatformNotSupportedException exception)
        {
            throw new CryptographicException("The peer ECDH point is invalid or cannot be imported by the provider.", exception);
        }
    }

    private static ReadOnlySpan<byte> ReadField(ReadOnlySpan<byte> parameter, ref int offset, int expectedLength)
    {
        int length = BinaryPrimitives.ReadUInt16BigEndian(parameter[offset..]);
        offset += 2;
        if (length != expectedLength)
        {
            throw new CryptographicException("The peer ECDH parameter has an invalid field length.");
        }

        ReadOnlySpan<byte> field = parameter.Slice(offset, length);
        offset += length;
        return field;
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_attempted)
        {
            throw new InvalidOperationException("The ephemeral ECDH key has already been consumed.");
        }
    }
}
