// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.Transport;

namespace Fdo.Rendezvous;

/// <summary>Configuration for one direct or delegated TO0 Owner registration.</summary>
public sealed class FdoOwnerRendezvousOptions
{
    /// <summary>CBOR-encoded voucher header tag, including its byte-string wrapper.</summary>
    public required ReadOnlyMemory<byte> EncodedVoucherHeaderTag { get; init; }

    /// <summary>CBOR-encoded voucher header HMAC.</summary>
    public required ReadOnlyMemory<byte> EncodedVoucherHeaderHmac { get; init; }

    /// <summary>Ordered, signed voucher entries, including at least one entry.</summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> EncodedVoucherEntries { get; init; }

    /// <summary>CBOR-encoded ordered Device attestation certificate chain.</summary>
    public required ReadOnlyMemory<byte> EncodedDeviceCertificateChain { get; init; }

    /// <summary>CBOR-encoded FDO manufacturer public key to trust.</summary>
    public required ReadOnlyMemory<byte> TrustedManufacturerKey { get; init; }

    /// <summary>DER trust anchor for Device attestation certificates.</summary>
    public required ReadOnlyMemory<byte> DeviceTrustAnchor { get; init; }

    /// <summary>Revocation behavior for the Device attestation chain.</summary>
    public required X509RevocationMode DeviceRevocationMode { get; init; }

    /// <summary>The private key of the final voucher Owner, or the Delegate leaf when delegation is configured.</summary>
    public required AsymmetricAlgorithm OwnerSigningKey { get; init; }

    /// <summary>The primary TO2 address to register.</summary>
    public required FdoRendezvousAddress OwnerAddress { get; init; }

    /// <summary>Up to two extra addresses in signed order. Only available with a Delegate chain.</summary>
    public IReadOnlyList<FdoRendezvousAddress>? AdditionalOwnerAddresses { get; init; }

    /// <summary>Leaf-first DER Delegate certificates. Setting this opts into delegated TO0.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>>? DelegateCertificates { get; init; }

    /// <summary>Required with a Delegate chain. The role does not download certificates or check revocation online.</summary>
    public TimeProvider? DelegateTimeProvider { get; init; }

    /// <summary>Offline status required for the configured TO0 Delegate; null selects no revocation check.</summary>
    public FdoDelegateOfflineRevocationPolicy? DelegateOfflineRevocation { get; init; }

    /// <summary>The requested registration lifetime in seconds, greater than zero.</summary>
    public required uint WaitSeconds { get; init; }

    /// <summary>Maximum encoded message body accepted or sent by the Owner.</summary>
    public ushort MaxMessageSize { get; init; } = ushort.MaxValue;

    /// <summary>Explicitly selects the provisional paired rendezvous wire choices.</summary>
    public required bool UseProvisionalPairedProfile { get; init; }
}

/// <summary>Registers one voucher and Owner address with a Rendezvous Server.</summary>
/// <remarks>
/// The caller owns the signing key and keeps it available without concurrent
/// use until the run ends. The host chooses and authenticates the Rendezvous
/// Server transport. A failed or uncertain run is not retried automatically.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoOwnerRendezvousSession
{
    private readonly FdoRendezvousCodec _codec = new();
    private readonly ReadOnlyMemory<byte> _voucher;
    private readonly FdoRendezvousCodec.CheckedVoucher _checkedVoucher;
    private readonly AsymmetricAlgorithm _signingKey;
    private readonly FdoRendezvousAddress _address;
    private readonly FdoRendezvousAddress[]? _additionalAddresses;
    private readonly uint _waitSeconds;
    private readonly ushort _maxMessageSize;
    private readonly ReadOnlyMemory<byte> _delegateChain;
    private readonly TimeProvider? _delegateTime;
    private readonly FdoDelegateOfflineRevocationPolicy? _delegateOfflineRevocation;
    private int _started;

    internal bool IsStarted => Volatile.Read(ref _started) != 0;

    /// <summary>Snapshots and verifies the voucher and configured trust material.</summary>
    public FdoOwnerRendezvousSession(FdoOwnerRendezvousOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.EncodedVoucherEntries);
        ArgumentNullException.ThrowIfNull(options.OwnerSigningKey);
        ArgumentNullException.ThrowIfNull(options.OwnerAddress);
        if (!options.UseProvisionalPairedProfile)
        {
            throw new InvalidOperationException("The paired rendezvous wire choices require explicit opt-in.");
        }

        if (options.WaitSeconds == 0 || options.MaxMessageSize == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Registration wait and message limits must be nonzero.");
        }

        _voucher = _codec.EncodeVoucher(
            options.EncodedVoucherHeaderTag, options.EncodedVoucherHeaderHmac,
            options.EncodedDeviceCertificateChain, options.EncodedVoucherEntries);
        var trustPolicy = new FdoPinnedDeviceTrustPolicy(
            options.TrustedManufacturerKey.ToArray(),
            options.DeviceTrustAnchor.ToArray(), options.DeviceRevocationMode);
        if ((options.DelegateCertificates is null) != (options.DelegateTimeProvider is null) ||
            (options.DelegateCertificates is null && options.DelegateOfflineRevocation is not null))
        {
            throw new ArgumentException("Delegated TO0 requires both certificates and a host clock.", nameof(options));
        }

        _checkedVoucher = _codec.CheckVoucher(
            _codec.ReadVoucher(_voucher, byte.MaxValue), trustPolicy,
            options.DelegateCertificates is null ? options.OwnerSigningKey : null);
        _signingKey = options.OwnerSigningKey;
        if (options.AdditionalOwnerAddresses is { Count: > 0 } extra)
        {
            int count = extra.Count;
            if (count > 2 || options.DelegateCertificates is null)
            {
                throw new ArgumentException("Only a delegated registration can add up to two TO2 addresses.", nameof(options));
            }

            var all = new FdoRendezvousAddress[count + 1];
            all[0] = options.OwnerAddress;
            for (int i = 0; i < count; i++)
            {
                all[i + 1] = extra[i];
            }

            FdoDelegatedRendezvousRoutes.Validate(all);
            _additionalAddresses = all[1..];
        }
        if (options.DelegateCertificates is { } certificates)
        {
            var chains = new FdoX5ChainCodec();
            _delegateChain = chains.Encode(certificates);
            _delegateTime = options.DelegateTimeProvider!;
            _delegateOfflineRevocation = options.DelegateOfflineRevocation;
            DateTimeOffset now = _delegateTime.GetUtcNow();
            FdoVerifiedDelegateChain verified = new FdoDelegateChainVerifier(X509RevocationMode.NoCheck)
                .Verify(chains.Decode(_delegateChain), _checkedVoucher.OwnerKey, now,
                    captureRevocationTargets: _delegateOfflineRevocation is not null);
            verified.Require(FdoDelegatePermissions.Redirect);
            var keys = new FdoPublicKeyCodec();
            using FdoPublicKeyCodec.DecodedKey leaf = keys.Decode(verified.DelegateKey);
            using FdoPublicKeyCodec.DecodedKey signer = keys.Decode(keys.EncodeOwnerKey(_signingKey, leaf.KeyType));
            if (!leaf.HasSamePublicKey(signer))
            {
                throw new CryptographicException("The TO0 signing key does not match the Delegate leaf.");
            }

            verified.RequireOfflineStatus(_delegateOfflineRevocation, now);
        }

        _address = options.OwnerAddress;
        _waitSeconds = options.WaitSeconds;
        _maxMessageSize = options.MaxMessageSize;
    }

    /// <summary>
    /// Registers once and returns the server's accepted lifetime in seconds.
    /// A transport failure may leave a registration in the server's store.
    /// </summary>
    public async ValueTask<uint> RunAsync(
        IFdoRendezvousTransport transport,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Owner rendezvous session has already been started.");
        }

        bool delegated = !_delegateChain.IsEmpty;
        ReadOnlyMemory<byte> hello = _codec.EncodeInitial(FdoMessageTypes.TO0Hello, delegated: delegated);
        ReadOnlyMemory<byte> ack = await FdoRendezvousExchange.SendAsync(
            transport, FdoRendezvousMessageType.OwnerHello, hello,
            FdoRendezvousMessageType.OwnerHelloAck, _maxMessageSize, cancellationToken).ConfigureAwait(false);
        var selection = _codec.ReadInitial(FdoMessageTypes.TO0HelloAck, ack, delegated);
        if (FdoRendezvousCodec.IsDelegated(selection.CapabilityFlags) != delegated)
        {
            throw new NotSupportedException("The Rendezvous Server did not select the requested TO0 capability.");
        }

        ReadOnlyMemory<byte> nonce = selection.GuidOrNonce!.Value;
        ReadOnlyMemory<byte> ownerSign = _codec.EncodeOwnerSign(
            _voucher, _waitSeconds, nonce, _address, _checkedVoucher.HashAlgorithm, _signingKey, _delegateChain, _additionalAddresses);
        FdoRendezvousCodec.OwnerSubmission signed = _codec.ReadOwnerSign(ownerSign, byte.MaxValue, delegated);
        if (delegated)
        {
            _codec.VerifyDelegatedRedirect(signed.SignedRedirect, _checkedVoucher.OwnerKey,
                _delegateTime!.GetUtcNow(), signed.To0Data, _checkedVoucher.HashAlgorithm, _delegateOfflineRevocation);
        }
        else
        {
            _codec.VerifyRedirect(signed.SignedRedirect, _checkedVoucher.OwnerKey, signed.To0Data, _checkedVoucher.HashAlgorithm);
        }
        ReadOnlyMemory<byte> accept = await FdoRendezvousExchange.SendAsync(
            transport, FdoRendezvousMessageType.OwnerSign, ownerSign,
            FdoRendezvousMessageType.AcceptOwner, _maxMessageSize, cancellationToken).ConfigureAwait(false);
        return _codec.ReadAcceptOwner(accept, _waitSeconds);
    }
}

internal static class FdoRendezvousExchange
{
    public static async ValueTask<ReadOnlyMemory<byte>> SendAsync(
        IFdoRendezvousTransport transport,
        FdoRendezvousMessageType requestType,
        ReadOnlyMemory<byte> request,
        FdoRendezvousMessageType expectedResponse,
        ushort maxMessageSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.IsEmpty || request.Length > maxMessageSize)
        {
            throw new CborContentException("The rendezvous request exceeds the local message limit or is empty.");
        }

        FdoRendezvousResponse response = await transport.SendAsync(
            200, requestType, request.ToArray(), cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The rendezvous transport returned no response.");
        cancellationToken.ThrowIfCancellationRequested();
        ReadOnlyMemory<byte> body = response.EncodedBody;
        if (response.ProtocolVersion != 200 || response.MessageType != expectedResponse ||
            body.IsEmpty || body.Length > maxMessageSize)
        {
            throw new CborContentException("The rendezvous response version, type, or size is invalid.");
        }

        return body;
    }
}
