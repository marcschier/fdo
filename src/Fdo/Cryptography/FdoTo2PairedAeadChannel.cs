// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

internal enum FdoTo2PairedRole
{
    Device = 0,
    Owner = 1,
}

/// <summary>
/// Protects an explicitly paired, ordered TO2 exchange using role-separated
/// AEAD counters. This type does not authenticate either peer or validate TO2
/// message semantics; those checks belong to the role state machines.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2PairedAeadChannel : IFdoTo2PairedChannel
{
    private readonly object _sync = new();
    private readonly FdoTo2PairedRole _role;
    private readonly FdoCoseAeadAlgorithm _algorithm;
    private readonly FdoCoseEncrypt0Codec _codec;
    private readonly byte[] _key;
    private ulong _sendCounter;
    private ulong _receiveCounter;
    private bool _expectSend;
    private bool _closed;

    /// <summary>
    /// Creates a channel for a fresh, already-authenticated session key.
    /// Both peers must explicitly select this paired nonce profile. The caller
    /// must never construct another session with the same key.
    /// </summary>
    /// <param name="role">The local protocol role.</param>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    /// <param name="key">The key used by this operation.</param>
    /// <param name="maxEncodedBytes">The maximum size of the encoded value, in bytes.</param>
    /// <param name="maxDepth">The maximum permitted CBOR nesting depth.</param>
    /// <param name="maxItems">The maximum number of CBOR items to process.</param>
    public FdoTo2PairedAeadChannel(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _expectSend = role switch
        {
            FdoTo2PairedRole.Device => true,
            FdoTo2PairedRole.Owner => false,
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };
        (int keySize, _, _) = FdoCoseAead.GetParameters(algorithm);
        if (key.Length != keySize)
        {
            throw new ArgumentException("The key length does not match the selected AEAD algorithm.", nameof(key));
        }

        if (!FdoCoseAead.IsSupported(algorithm))
        {
            throw new PlatformNotSupportedException("The selected AEAD algorithm is not available on this platform.");
        }

        _codec = new FdoCoseEncrypt0Codec(maxEncodedBytes, maxDepth, maxItems);
        _role = role;
        _algorithm = algorithm;
        _key = key.ToArray();
    }

    /// <inheritdoc/>
    public long GetSealedLength(int plaintextLength) =>
        FdoCoseEncrypt0Codec.GetEncodedLength(_algorithm, plaintextLength);

    /// <summary>
    /// Reserves the next local IV and encrypts one CBOR value. The caller must
    /// dispose the channel if delivery fails or its outcome is ambiguous.
    /// </summary>
    /// <param name="encodedPlaintext">The exact CBOR payload before channel protection.</param>
    /// <exception cref="InvalidOperationException">The paired TO2 channel is awaiting a message.</exception>
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

                byte[] nonce = CreateNonce(_role, _sendCounter++, _algorithm);
                ReadOnlyMemory<byte> result = _codec.Encrypt(_algorithm, _key, nonce, encodedPlaintext);
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

    /// <summary>
    /// Returns plaintext only after the AEAD tag, peer role, and exact next
    /// counter are verified. The caller owns and must clear the returned bytes.
    /// It must also validate the expected TO2 message and its contents before
    /// passing them to ServiceInfo; on failure it must dispose the channel.
    /// </summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    /// <exception cref="InvalidOperationException">The paired TO2 channel is awaiting a local message.</exception>
    /// <exception cref="CryptographicException">The paired TO2 message has an unexpected role or counter.</exception>
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

                FdoTo2PairedRole peer = _role == FdoTo2PairedRole.Device
                    ? FdoTo2PairedRole.Owner
                    : FdoTo2PairedRole.Device;
                byte[] expectedNonce = CreateNonce(peer, _receiveCounter, _algorithm);
                FdoCoseEncrypt0Codec.DecryptedMessage message = _codec.Decrypt(_algorithm, _key, encoded);
                plaintext = message.Plaintext;
                if (!CryptographicOperations.FixedTimeEquals(expectedNonce, message.Nonce))
                {
                    throw new CryptographicException("The paired TO2 message has an unexpected role or counter.");
                }

                _receiveCounter++;
                _expectSend = true;
                completed = true;
                return plaintext;
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

    /// <summary>Aborts the session and clears its copy of the key.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            Close();
        }
    }

    internal static byte[] CreateNonce(
        FdoTo2PairedRole role, ulong counter, FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A128Gcm)
    {
        byte prefix = role switch
        {
            FdoTo2PairedRole.Device => 0,
            FdoTo2PairedRole.Owner => 1,
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };
        if (counter > uint.MaxValue)
        {
            throw new InvalidOperationException("The paired TO2 message counter is exhausted.");
        }

        (_, int nonceSize, _) = FdoCoseAead.GetParameters(algorithm);
        byte[] nonce = new byte[nonceSize];
        nonce[nonceSize - 5] = prefix;
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(nonceSize - 4), (uint)counter);
        return nonce;
    }

    private void Close()
    {
        CryptographicOperations.ZeroMemory(_key);
        _closed = true;
    }
}
