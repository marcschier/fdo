// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Serialization;
using Fdo.Transport;

namespace Fdo.Rendezvous;

/// <summary>Configuration for one TO1 Device lookup.</summary>
public sealed class FdoDeviceRendezvousOptions
{
    /// <summary>The 16-byte FDO Device GUID in wire order.</summary>
    public required ReadOnlyMemory<byte> DeviceGuid { get; init; }

    /// <summary>The private key for the Device attestation certificate.</summary>
    public required ECDsa AttestationKey { get; init; }

    /// <summary>Maximum encoded message body accepted or sent by the Device.</summary>
    public ushort MaxMessageSize { get; init; } = ushort.MaxValue;

    /// <summary>Explicitly selects the provisional paired rendezvous wire choices.</summary>
    public required bool UseProvisionalPairedProfile { get; init; }

    /// <summary>Requests delegated discovery and requires the server to select it in this run.</summary>
    public bool UseDelegatedDiscovery { get; init; }
}

/// <summary>
/// An untrusted TO1 address and the exact signed blob to check during TO2.
/// </summary>
/// <remarks>
/// The host applies its network policy before connecting to the candidate.
/// The address is not authenticated by TO1. Pass this result to one Device
/// TO2 session; it verifies the signature with the voucher-proven Owner key
/// before opening the protected enrollment channel.
/// </remarks>
public sealed class FdoDeviceRendezvousResult
{
    private readonly byte[] _guid;
    private readonly byte[] _signedRedirect;
    private int _claimed;

    internal FdoDeviceRendezvousResult(
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> signedRedirect,
        FdoRendezvousAddress address)
        : this(guid, signedRedirect, new[] { address })
    {
    }

    private FdoDeviceRendezvousResult(
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> signedRedirect,
        IReadOnlyList<FdoRendezvousAddress> addresses)
    {
        _guid = guid.ToArray();
        _signedRedirect = signedRedirect.ToArray();
        var copy = new FdoRendezvousAddress[addresses.Count];
        for (int i = 0; i < copy.Length; i++)
        {
            copy[i] = addresses[i];
        }

        CandidateAddresses = Array.AsReadOnly(copy);
    }

    /// <summary>The unverified candidate when the result contains exactly one address.</summary>
    /// <exception cref="InvalidOperationException">The host must explicitly select among multiple addresses.</exception>
    public FdoRendezvousAddress CandidateAddress => CandidateAddresses.Count == 1
        ? CandidateAddresses[0] : throw new InvalidOperationException("The redirect has multiple candidate addresses.");

    /// <summary>Unverified candidate addresses in signed blob order. This list does not select a route.</summary>
    public IReadOnlyList<FdoRendezvousAddress> CandidateAddresses { get; }

    /// <summary>
    /// Wraps a to1d blob that the host obtained outside this library's TO1
    /// session, for example from a Rendezvous Server through its own client.
    /// </summary>
    /// <remarks>
    /// This method does not perform TO1 discovery. It checks only the blob
    /// structure; the blob may carry a single DelegateChain and
    /// stays untrusted. A Device TO2 session authenticates it after the voucher
    /// proves the Owner key. A delegated blob additionally requires
    /// <see cref="Fdo.Enrollment.FdoDeviceSessionOptions.AcceptDelegatedRendezvousRedirect"/>.
    /// </remarks>
    /// <param name="deviceGuid">The 16-byte FDO Device GUID in wire order.</param>
    /// <param name="signedRedirect">The exact untrusted COSE_Sign1 to1d blob.</param>
    /// <exception cref="ArgumentException">The GUID is not 16 bytes.</exception>
    /// <exception cref="System.Formats.Cbor.CborContentException">The blob is not a structurally valid to1d blob.</exception>
    /// <exception cref="NotSupportedException">The blob uses an unsupported field, such as RVPref.</exception>
    [UnsupportedOSPlatform("browser")]
    public static FdoDeviceRendezvousResult FromUntrustedBlob(
        ReadOnlyMemory<byte> deviceGuid, ReadOnlyMemory<byte> signedRedirect)
    {
        if (deviceGuid.Length != 16)
        {
            throw new ArgumentException("The Device GUID must contain 16 bytes.", nameof(deviceGuid));
        }

        byte[] blob = signedRedirect.ToArray();
        return FromWireBlob(deviceGuid, blob, allowDelegateChain: true);
    }

    internal static FdoDeviceRendezvousResult FromWireBlob(
        ReadOnlyMemory<byte> guid, ReadOnlyMemory<byte> blob, bool allowDelegateChain) =>
        new(guid, blob, new FdoRendezvousCodec().ReadUntrustedRedirectAddresses(blob, allowDelegateChain));

    /// <summary>The exact, not-yet-authenticated Owner-signed or Delegate-signed TO1 blob.</summary>
    public ReadOnlyMemory<byte> SignedRedirect => (byte[])_signedRedirect.Clone();

    internal ReadOnlyMemory<byte> Claim(ReadOnlySpan<byte> expectedGuid)
    {
        RequireGuid(expectedGuid);
        if (Interlocked.CompareExchange(ref _claimed, 1, 0) != 0)
        {
            throw new InvalidOperationException("The TO1 result has already been used for a Device run.");
        }

        return (byte[])_signedRedirect.Clone();
    }

    internal void RequireGuid(ReadOnlySpan<byte> expectedGuid)
    {
        if (!CryptographicOperations.FixedTimeEquals(_guid, expectedGuid))
        {
            throw new CryptographicException("The TO1 result belongs to a different Device GUID.");
        }
    }
}

/// <summary>Retrieves one untrusted Owner candidate using paired TO1.</summary>
/// <remarks>
/// The caller owns the attestation key and keeps it available without
/// concurrent use until the run ends. The host selects the Rendezvous Server
/// and applies its transport policy. A failed or uncertain run is not
/// retried automatically and does not authorize rendezvous bypass.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoDeviceRendezvousSession
{
    private readonly FdoRendezvousCodec _codec = new();
    private readonly byte[] _guid;
    private readonly ECDsa _attestationKey;
    private readonly ushort _maxMessageSize;
    private readonly bool _delegated;
    private int _started;

    internal bool IsStarted => Volatile.Read(ref _started) != 0;

    /// <summary>Snapshots the Device GUID and checks the attestation key type.</summary>
    public FdoDeviceRendezvousSession(FdoDeviceRendezvousOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.AttestationKey);
        if (!options.UseProvisionalPairedProfile)
        {
            throw new InvalidOperationException("The paired rendezvous wire choices require explicit opt-in.");
        }

        if (options.DeviceGuid.Length != 16 || options.MaxMessageSize == 0)
        {
            throw new ArgumentException("TO1 requires a 16-byte Device GUID and a nonzero message limit.", nameof(options));
        }

        using FdoPublicKeyCodec.DecodedKey key =
            new FdoPublicKeyCodec().Decode(new FdoPublicKeyCodec().Encode(options.AttestationKey));
        _guid = options.DeviceGuid.ToArray();
        _attestationKey = options.AttestationKey;
        _maxMessageSize = options.MaxMessageSize;
        _delegated = options.UseDelegatedDiscovery;
    }

    /// <summary>Performs TO1 once and returns an untrusted Owner candidate.</summary>
    public async ValueTask<FdoDeviceRendezvousResult> RunAsync(
        IFdoRendezvousTransport transport,
        CancellationToken cancellationToken = default)
    {
        ReadOnlyMemory<byte> response = await StartLookupAsync(transport, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> blob = _codec.ReadRedirect(response, allowDelegateChain: _delegated);
        return FdoDeviceRendezvousResult.FromWireBlob(_guid, blob, allowDelegateChain: _delegated);
    }

    /// <summary>Caches all pages of one delegated TO1 lookup before returning untrusted blobs for host selection.</summary>
    /// <remarks>No page is returned early, and no page request is retried automatically.</remarks>
    public async ValueTask<IReadOnlyList<FdoDeviceRendezvousResult>> RunBatchAsync(
        IFdoRendezvousTransport transport, CancellationToken cancellationToken = default)
    {
        if (!_delegated)
        {
            throw new InvalidOperationException("A TO1 batch requires delegated discovery.");
        }

        ReadOnlyMemory<byte> response = await StartLookupAsync(transport, cancellationToken).ConfigureAwait(false);
        var (total, index, blobs) = _codec.ReadRedirectPage(response);
        var results = new FdoDeviceRendezvousResult[total];
        int next = 0;
        while (true)
        {
            if (index != next)
            {
                throw new CborContentException("The TO1 redirect page does not start at the expected index.");
            }

            foreach (ReadOnlyMemory<byte> blob in blobs)
            {
                results[next++] = FdoDeviceRendezvousResult.FromWireBlob(_guid, blob, allowDelegateChain: true);
            }

            if (next == total)
            {
                return Array.AsReadOnly(results);
            }

            response = await FdoRendezvousExchange.SendAsync(
                transport, FdoRendezvousMessageType.ProveToRendezvous, FdoRendezvousCodec.EncodeRvMore(next),
                FdoRendezvousMessageType.Redirect, _maxMessageSize, cancellationToken).ConfigureAwait(false);
            int pageTotal;
            (pageTotal, index, blobs) = _codec.ReadRedirectPage(response);
            if (pageTotal != total)
            {
                throw new CborContentException("The total TO1 redirect count changed between pages.");
            }
        }
    }

    private async ValueTask<ReadOnlyMemory<byte>> StartLookupAsync(
        IFdoRendezvousTransport transport, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Device rendezvous session has already been started.");
        }

        ReadOnlyMemory<byte> hello = _codec.EncodeInitial(FdoMessageTypes.TO1HelloRV, _guid, _delegated);
        ReadOnlyMemory<byte> ack = await FdoRendezvousExchange.SendAsync(
            transport, FdoRendezvousMessageType.DeviceHello, hello,
            FdoRendezvousMessageType.DeviceHelloAck, _maxMessageSize, cancellationToken).ConfigureAwait(false);
        var selection = _codec.ReadInitial(FdoMessageTypes.TO1HelloRVAck, ack, _delegated);
        if (FdoRendezvousCodec.IsDelegated(selection.CapabilityFlags) != _delegated)
        {
            throw new NotSupportedException("The Rendezvous Server did not select the requested TO1 capability.");
        }

        ReadOnlyMemory<byte> nonce = selection.GuidOrNonce!.Value;
        ReadOnlyMemory<byte> proof = _codec.SignDeviceProof(_guid, nonce, _attestationKey);
        return await FdoRendezvousExchange.SendAsync(
            transport, FdoRendezvousMessageType.ProveToRendezvous, proof,
            FdoRendezvousMessageType.Redirect, _maxMessageSize, cancellationToken).ConfigureAwait(false);
    }
}
