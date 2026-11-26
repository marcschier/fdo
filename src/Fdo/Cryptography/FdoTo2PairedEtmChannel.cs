using System;
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Protects an explicitly paired, ordered TO2 exchange with an FDO
/// encrypt-then-MAC suite. Each direction uses its own random 12-byte counter
/// block prefix, fixed for the session, followed by a 32-bit big-endian block
/// counter that starts at zero and continues across messages. The Owner learns
/// the Device prefix from the first Device message and selects a different
/// prefix; the Device rejects an Owner prefix equal to its own. Each message
/// reserves the counter blocks it consumes, at least one, so no counter block
/// is used twice under the shared encryption key. This type does not
/// authenticate either peer or validate TO2 message semantics.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2PairedEtmChannel : IFdoTo2PairedChannel
{
    private const int PrefixSize = 12;
    private readonly object _sync = new();
    private readonly FdoCoseAeadAlgorithm _suite;
    private readonly FdoCoseEncryptThenMacCodec _codec;
    private readonly byte[] _verificationKey;
    private readonly byte[] _encryptionKey;
    private byte[]? _sendPrefix;
    private byte[]? _receivePrefix;
    private ulong _sendCounter;
    private ulong _receiveCounter;
    private bool _expectSend;
    private bool _closed;

    /// <summary>
    /// Creates a channel for a fresh, already-authenticated session key laid out
    /// as SVK followed by SEK. Both peers must explicitly select this suite. The
    /// caller must never construct another session with the same key.
    /// </summary>
    public FdoTo2PairedEtmChannel(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> sessionKey,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
        : this(role, suite, sessionKey, null, maxEncodedBytes, maxDepth, maxItems)
    {
    }

    internal FdoTo2PairedEtmChannel(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> sessionKey,
        byte[]? sendPrefix,
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
        if (!FdoTo2CipherSuites.IsAesCtr(suite))
        {
            throw new ArgumentOutOfRangeException(nameof(suite), suite, "The suite is not an AES-CTR suite.");
        }

        FdoTo2CipherSuites.EncryptThenMacParameters parameters = FdoTo2CipherSuites.GetEncryptThenMacParameters(suite);
        if (sessionKey.Length != parameters.VerificationKeySize + parameters.EncryptionKeySize)
        {
            throw new ArgumentException("The session key length does not match the selected suite.", nameof(sessionKey));
        }

        if (sendPrefix is not null && sendPrefix.Length != PrefixSize)
        {
            throw new ArgumentException("The counter block prefix must contain 12 bytes.", nameof(sendPrefix));
        }

        if (!FdoAesCtr.IsSupported)
        {
            throw new PlatformNotSupportedException("AES-CTR is not available on this platform.");
        }

        _codec = new FdoCoseEncryptThenMacCodec(maxEncodedBytes, maxDepth, maxItems);
        _suite = suite;
        _verificationKey = sessionKey[..parameters.VerificationKeySize].ToArray();
        _encryptionKey = sessionKey[parameters.VerificationKeySize..].ToArray();
        _sendPrefix = (byte[]?)sendPrefix?.Clone();
    }

    /// <summary>Test hook that positions the next local counter.</summary>
    internal ulong SendCounter
    {
        get { lock (_sync) { return _sendCounter; } }
        set { lock (_sync) { _sendCounter = value; } }
    }

    /// <summary>Test hook that positions the next expected peer counter.</summary>
    internal ulong ReceiveCounter
    {
        get { lock (_sync) { return _receiveCounter; } }
        set { lock (_sync) { _receiveCounter = value; } }
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

                _sendPrefix ??= CreatePrefix(_receivePrefix);
                if (_receivePrefix is not null && _sendPrefix.AsSpan().SequenceEqual(_receivePrefix))
                {
                    throw new CryptographicException("Both TO2 directions would use the same counter block prefix.");
                }

                if (!FdoAesCtr.TryReserve(_sendCounter, encodedPlaintext.Length, out uint initial, out ulong following))
                {
                    throw new CryptographicException("The paired TO2 send counter space is exhausted.");
                }

                byte[] counterBlock = CreateCounterBlock(_sendPrefix, initial);
                ReadOnlyMemory<byte> result = _codec.Encrypt(
                    _suite, _verificationKey, _encryptionKey, counterBlock, encodedPlaintext);
                _sendCounter = following;
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
                ReadOnlySpan<byte> prefix = message.CounterBlock.AsSpan(0, PrefixSize);
                uint counter = BinaryPrimitives.ReadUInt32BigEndian(message.CounterBlock.AsSpan(PrefixSize));
                if (_receivePrefix is null)
                {
                    if (_sendPrefix is not null && prefix.SequenceEqual(_sendPrefix))
                    {
                        throw new CryptographicException("The peer uses the local counter block prefix.");
                    }
                }
                else if (!prefix.SequenceEqual(_receivePrefix))
                {
                    throw new CryptographicException("The paired TO2 message changed its counter block prefix.");
                }

                if (counter != _receiveCounter)
                {
                    throw new CryptographicException("The paired TO2 message has an unexpected counter.");
                }

                if (!FdoAesCtr.TryReserve(_receiveCounter, message.Ciphertext.Length, out _, out ulong following))
                {
                    throw new CryptographicException("The paired TO2 receive counter space is exhausted.");
                }

                plaintext = _codec.Decrypt(_suite, _encryptionKey, message);
                _receivePrefix ??= prefix.ToArray();
                _receiveCounter = following;
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

    /// <summary>Aborts the session and clears its copies of the keys.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            Close();
        }
    }

    private static byte[] CreatePrefix(byte[]? peerPrefix)
    {
        byte[] prefix = new byte[PrefixSize];
        do
        {
            RandomNumberGenerator.Fill(prefix);
        }
        while (peerPrefix is not null && prefix.AsSpan().SequenceEqual(peerPrefix));

        return prefix;
    }

    private static byte[] CreateCounterBlock(byte[] prefix, uint counter)
    {
        byte[] block = new byte[FdoCoseEncryptThenMacCodec.CounterBlockSize];
        prefix.CopyTo(block, 0);
        BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(PrefixSize), counter);
        return block;
    }

    private void Close()
    {
        CryptographicOperations.ZeroMemory(_verificationKey);
        CryptographicOperations.ZeroMemory(_encryptionKey);
        _closed = true;
    }
}
