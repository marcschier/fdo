using System;
using System.Runtime.Versioning;

namespace Fdo.Cryptography;

/// <summary>
/// An ordered, paired TO2 message protection channel. The Device sends first and
/// the roles then alternate. Any failure closes the channel.
/// </summary>
internal interface IFdoTo2PairedChannel : IDisposable
{
    /// <summary>
    /// Protects one CBOR value. The caller must dispose the channel if delivery
    /// fails or its outcome is ambiguous.
    /// </summary>
    ReadOnlyMemory<byte> Seal(ReadOnlyMemory<byte> encodedPlaintext);

    /// <summary>
    /// Returns the exact protected length that <see cref="Seal"/> produces for
    /// a plaintext of the given length, without consuming channel state.
    /// </summary>
    long GetSealedLength(int plaintextLength);

    /// <summary>
    /// Returns plaintext only after authentication and the channel's replay
    /// checks. The caller owns and must clear the returned bytes and must
    /// validate the TO2 message before acting on it.
    /// </summary>
    byte[] Open(ReadOnlyMemory<byte> encoded);
}

/// <summary>Creates the paired channel for a negotiated TO2 cipher suite.</summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoTo2PairedChannels
{
    public static IFdoTo2PairedChannel Create(
        FdoTo2PairedRole role,
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> sessionKey,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue) =>
        FdoTo2CipherSuites.IsAesCbc(suite)
            ? new FdoTo2PairedCbcEtmChannel(role, suite, sessionKey, maxEncodedBytes, maxDepth, maxItems)
            : FdoTo2CipherSuites.IsAesCtr(suite)
            ? new FdoTo2PairedEtmChannel(role, suite, sessionKey, maxEncodedBytes, maxDepth, maxItems)
            : new FdoTo2PairedAeadChannel(role, suite, sessionKey, maxEncodedBytes, maxDepth, maxItems);
}
