// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Serialization;

namespace Fdo.Initialization;

/// <summary>Device Initialize message types.</summary>
public enum FdoDeviceInitializeMessageType : ushort
{
    /// <summary>Device manufacturing lookup information.</summary>
    AppStart = 10,

    /// <summary>Proposed Ownership Voucher header.</summary>
    SetCredentials = 11,

    /// <summary>Device HMAC of the proposed header.</summary>
    SetHmac = 12,

    /// <summary>Manufacturer completion response.</summary>
    Done = 13,
}

/// <summary>A detached Device Initialize response.</summary>
public sealed class FdoDeviceInitializeResponse
{
    private readonly byte[] _encodedBody;

    /// <summary>Snapshots one response received by a Device transport.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    public FdoDeviceInitializeResponse(
        ushort protocolVersion,
        FdoDeviceInitializeMessageType messageType,
        ReadOnlyMemory<byte> encodedBody)
    {
        if (encodedBody.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedBody));
        }

        ProtocolVersion = protocolVersion;
        MessageType = messageType;
        _encodedBody = encodedBody.ToArray();
    }

    /// <summary>The FDO protocol version.</summary>
    public ushort ProtocolVersion { get; }

    /// <summary>The response message type.</summary>
    public FdoDeviceInitializeMessageType MessageType { get; }

    /// <summary>The exact encoded response body.</summary>
    public ReadOnlyMemory<byte> EncodedBody => (byte[])_encodedBody.Clone();
}

/// <summary>Exchanges messages with one authorized manufacturing station.</summary>
/// <remarks>
/// The host authenticates the station or establishes an equivalent trusted
/// manufacturing environment. It binds all messages to one manufacturer
/// session, bounds responses while reading, and does not retry or redirect an
/// uncertain request. The Device session does not own this transport.
/// </remarks>
public interface IFdoDeviceInitializeTransport
{
    /// <summary>Sends one request and returns the station's response.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<FdoDeviceInitializeResponse> SendAsync(
        ushort protocolVersion,
        FdoDeviceInitializeMessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken);
}

/// <summary>An opaque, host-owned handle to a Device voucher HMAC secret.</summary>
/// <remarks>
/// The host creates the secret with a cryptographically secure random source,
/// keeps it confidential, and persists the handle so it can be used after a
/// restart. The reported algorithm and key size describe the protected key.
/// During TO2, the supplied header is untrusted until the voucher is verified.
/// </remarks>
public interface IFdoDeviceInitializeHmacSecret
{
    /// <summary>The HMAC algorithm supported by this secret.</summary>
    FdoDeviceHmacAlgorithm Algorithm { get; }

    /// <summary>The secret size in bytes, without exporting the secret.</summary>
    int KeySizeInBytes { get; }

    /// <summary>Computes an HMAC over the supplied encoded header contents.</summary>
    /// <param name="encodedHeaderContents">
    /// The encoded voucher header contents, excluding the enclosing byte string.
    /// </param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
        ReadOnlyMemory<byte> encodedHeaderContents,
        CancellationToken cancellationToken);
}

/// <summary>Authorizes, stages, and installs a Device's initialization.</summary>
/// <remarks>
/// <see cref="AuthorizeAndReserveAsync"/> must authorize this Device's
/// relationship to the station on the supplied transport and durably reserve
/// an initialization without replacing an active credential or an unresolved
/// prior attempt. <see cref="StageAsync"/> must apply host policy to the
/// proposed credential, including rendezvous instructions, and durably retain
/// the complete credential and its opaque secret handle before returning.
/// <see cref="InstallAsync"/> must atomically install that staged credential
/// without overwriting an active one. A throwing or canceled callback can have
/// an unknown durable outcome; the host must reconcile it before another run.
/// </remarks>
public interface IFdoDeviceInitializeHandler
{
    /// <summary>Authorizes the station, reserves the Device, and returns its secret handle.</summary>
    /// <param name="runId">The local identifier of the protocol run.</param>
    /// <param name="transport">The exchange transport bound to the peer for this run.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
        Guid runId,
        IFdoDeviceInitializeTransport transport,
        CancellationToken cancellationToken);

    /// <summary>Durably stages the proposed credential and secret handle.</summary>
    /// <param name="credential">The Device credential for this operation.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken);

    /// <summary>Installs the staged credential after a valid DI.Done.</summary>
    /// <param name="credential">The Device credential for this operation.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken);
}

/// <summary>The complete proposed Device credential and its opaque HMAC handle.</summary>
public sealed class FdoDeviceInitializeCredential
{
    private readonly byte[] _guid;
    private readonly byte[] _rendezvousInfo;
    private readonly byte[] _manufacturerKeyHash;
    private readonly byte[] _headerTag;

    internal FdoDeviceInitializeCredential(
        Guid runId,
        FdoOwnershipVoucherHeader header,
        ReadOnlyMemory<byte> headerTag,
        FdoHashValue manufacturerKeyHash,
        FdoDeviceHmacAlgorithm hmacAlgorithm,
        IFdoDeviceInitializeHmacSecret hmacSecret)
    {
        RunId = runId;
        DeviceInfo = header.DeviceInfo;
        _guid = header.Guid.ToArray();
        _rendezvousInfo = header.RendezvousInfo.ToArray();
        _manufacturerKeyHash = manufacturerKeyHash.Encode().ToArray();
        _headerTag = headerTag.ToArray();
        VoucherHmacAlgorithm = hmacAlgorithm;
        VoucherHmacSecret = hmacSecret;
    }

    /// <summary>The local identifier for the Device run.</summary>
    public Guid RunId { get; }

    /// <summary>Initialized credentials activate FDO.</summary>
    [SuppressMessage("Performance", "CA1822", Justification = "Part of the persisted credential instance contract.")]
    public bool Active => true;

    /// <summary>The FDO protocol version.</summary>
    [SuppressMessage("Performance", "CA1822", Justification = "Part of the persisted credential instance contract.")]
    public ushort ProtocolVersion => 200;

    /// <summary>The manufacturer-supplied Device information string.</summary>
    public string DeviceInfo { get; }

    /// <summary>The 16-byte FDO GUID in wire order.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_guid.Clone();

    /// <summary>The encoded RendezvousInfo, including rvserver.local.</summary>
    public ReadOnlyMemory<byte> EncodedRendezvousInfo => (byte[])_rendezvousInfo.Clone();

    /// <summary>The encoded FDO Hash of the manufacturer public key.</summary>
    public ReadOnlyMemory<byte> EncodedManufacturerKeyHash => (byte[])_manufacturerKeyHash.Clone();

    /// <summary>The proposed voucher header, including its byte-string wrapper.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_headerTag.Clone();

    /// <summary>The selected voucher HMAC algorithm.</summary>
    public FdoDeviceHmacAlgorithm VoucherHmacAlgorithm { get; }

    /// <summary>The host-owned handle to the Device's protected HMAC secret.</summary>
    public IFdoDeviceInitializeHmacSecret VoucherHmacSecret { get; }
}

/// <summary>Configuration for one Device Initialize run.</summary>
public sealed class FdoDeviceInitializeOptions
{
    /// <summary>
    /// The installed Device attestation key. The host retains the key and
    /// verifies that it belongs to the Device being initialized.
    /// </summary>
    public required ECDsa AttestationKey { get; init; }

    /// <summary>Host authorization and credential persistence callbacks.</summary>
    public required IFdoDeviceInitializeHandler Handler { get; init; }

    /// <summary>
    /// Optional encoded CBOR manufacturing lookup information, without the
    /// enclosing byte string. This is not Device authentication.
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedDeviceMfgInfo { get; init; }

    /// <summary>The maximum encoded message body accepted or sent by the Device.</summary>
    public ushort MaxMessageSize { get; init; } = ushort.MaxValue;

    /// <summary>
    /// Selects the provisional HMAC over OVHeader contents, excluding its
    /// byte-string wrapper. Both roles must use this choice.
    /// </summary>
    public required bool UseVoucherHeaderHmac { get; init; }
}

/// <summary>Runs one Device side of the example Device Initialize protocol.</summary>
/// <remarks>
/// DI does not authenticate either peer by itself. Authorization, protected
/// storage, transport trust, and reconciliation after an uncertain result
/// belong to the host. This role does not retry or resume a run.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoDeviceInitializeSession
{
    private readonly FdoDeviceInitializeCodec _codec = new();
    private readonly FdoCborCodec _cbor = new();
    private readonly IFdoDeviceInitializeHandler _handler;
    private readonly ReadOnlyMemory<byte> _appStart;
    private readonly int _deviceKeyType;
    private readonly ushort _maxMessageSize;
    private int _started;

    /// <summary>Creates a single-use Device Initialize session.</summary>
    /// <param name="options">The configuration for this operation.</param>
    public FdoDeviceInitializeSession(FdoDeviceInitializeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.AttestationKey);
        ArgumentNullException.ThrowIfNull(options.Handler);
        if (!options.UseVoucherHeaderHmac)
        {
            throw new InvalidOperationException("The selected Device Initialize HMAC convention requires explicit opt-in.");
        }

        ArgumentOutOfRangeException.ThrowIfZero(options.MaxMessageSize);
        _deviceKeyType = FdoInitializationFields.GetKeyType(options.AttestationKey);
        _handler = options.Handler;
        _maxMessageSize = options.MaxMessageSize;
        _appStart = _codec.EncodeAppStart(new FdoDeviceInitializeCodec.AppStart(
            new byte[] { (byte)FdoKnownCapabilities.Fdo20 }, Array.Empty<string>(), options.EncodedDeviceMfgInfo));
        RequireBodySize(_appStart);
        RunId = Guid.NewGuid();
    }

    /// <summary>The local identifier for this Device run.</summary>
    public Guid RunId { get; }

    /// <summary>Whether the authorization and reservation callback started.</summary>
    public bool ReservationStarted { get; private set; }

    /// <summary>Whether the reservation callback returned a secret handle.</summary>
    public bool ReservationConfirmed { get; private set; }

    /// <summary>Whether the Device entered its staging callback.</summary>
    public bool StagingStarted { get; private set; }

    /// <summary>Whether the staging callback returned successfully.</summary>
    public bool CredentialStaged { get; private set; }

    /// <summary>Whether the Device started sending DI.SetHMAC.</summary>
    public bool SetHmacSendStarted { get; private set; }

    /// <summary>Whether the Device accepted a valid DI.Done.</summary>
    public bool DoneReceived { get; private set; }

    /// <summary>Whether the Device entered its installation callback.</summary>
    public bool InstallationStarted { get; private set; }

    /// <summary>The credential whose installation callback returned successfully.</summary>
    public FdoDeviceInitializeCredential? InstalledCredential { get; private set; }

    /// <summary>
    /// Runs once. A successful return follows a valid DI.Done and a successful
    /// installation callback. A failure does not roll back host storage.
    /// </summary>
    /// <param name="transport">The exchange transport bound to the peer for this run.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <exception cref="InvalidOperationException">
    /// The Device Initialize session has already been started. The Device initialization handler returned no HMAC
    /// secret handle.
    /// </exception>
    /// <exception cref="CborContentException">The station returned an unrequested vendor capability.</exception>
    /// <exception cref="CryptographicException">
    /// The Device and manufacturer key sizes require a different HMAC algorithm.
    /// </exception>
    public async ValueTask<FdoDeviceInitializeCredential> RunAsync(
        IFdoDeviceInitializeTransport transport,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Device Initialize session has already been started.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        ReservationStarted = true;
        IFdoDeviceInitializeHmacSecret secret = await _handler.AuthorizeAndReserveAsync(
            RunId, transport, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The Device initialization handler returned no HMAC secret handle.");
        ReservationConfirmed = true;
        FdoDeviceHmacAlgorithm algorithm = secret.Algorithm;
        FdoInitializationFields.ValidateHmacSecretHandle(secret, algorithm);
        FdoHashAlgorithm hmacAlgorithm = FdoInitializationFields.HmacAlgorithm(algorithm);
        cancellationToken.ThrowIfCancellationRequested();

        FdoDeviceInitializeResponse response = await transport.SendAsync(
            200, FdoDeviceInitializeMessageType.AppStart, _appStart, cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> body = RequireResponse(response, FdoDeviceInitializeMessageType.SetCredentials);
        FdoDeviceInitializeCodec.SetCredentials message = _codec.DecodeSetCredentials(body);
        FdoInitializationFields.RequireFdo20(message.CapabilityFlags);
        if (message.VendorCapabilities.Count != 0)
        {
            throw new CborContentException("The station returned an unrequested vendor capability.");
        }

        FdoOwnershipVoucherHeader header = FdoInitializationFields.ReadHeader(message.EncodedHeaderTag);
        int manufacturerKeyType = FdoInitializationFields.GetKeyType(header.ManufacturerKey);
        FdoDeviceHmacAlgorithm expected = FdoInitializationFields.SelectHmac(_deviceKeyType, manufacturerKeyType);
        if (algorithm != expected)
        {
            throw new CryptographicException("The Device and manufacturer key sizes require a different HMAC algorithm.");
        }

        FdoHashValue manufacturerHash = FdoHashValue.ComputeDigest(
            FdoInitializationFields.DigestAlgorithm(expected), header.ManufacturerKey.Span);
        var credential = new FdoDeviceInitializeCredential(
            RunId, header, message.EncodedHeaderTag, manufacturerHash, algorithm, secret);
        cancellationToken.ThrowIfCancellationRequested();
        StagingStarted = true;
        await _handler.StageAsync(credential, cancellationToken).ConfigureAwait(false);
        CredentialStaged = true;
        cancellationToken.ThrowIfCancellationRequested();
        FdoInitializationFields.ValidateHmacSecretHandle(secret, algorithm);
        ReadOnlyMemory<byte> mac = await secret.ComputeAsync(
            header.Contents.ToArray(), cancellationToken).ConfigureAwait(false);
        var hmac = new FdoHashValue(hmacAlgorithm, mac.Span);
        ReadOnlyMemory<byte> setHmac = _codec.EncodeSetHmac(hmac);
        RequireBodySize(setHmac);
        cancellationToken.ThrowIfCancellationRequested();
        SetHmacSendStarted = true;
        response = await transport.SendAsync(
            200, FdoDeviceInitializeMessageType.SetHmac, setHmac, cancellationToken).ConfigureAwait(false);
        body = RequireResponse(response, FdoDeviceInitializeMessageType.Done);
        _codec.DecodeDone(body);
        DoneReceived = true;
        cancellationToken.ThrowIfCancellationRequested();
        InstallationStarted = true;
        await _handler.InstallAsync(credential, cancellationToken).ConfigureAwait(false);
        InstalledCredential = credential;
        return credential;
    }

    private ReadOnlyMemory<byte> RequireResponse(
        FdoDeviceInitializeResponse response,
        FdoDeviceInitializeMessageType expected)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.ProtocolVersion != 200 || response.MessageType != expected)
        {
            throw new CborContentException("The Device Initialize response version or message type is unexpected.");
        }

        ReadOnlyMemory<byte> body = response.EncodedBody;
        RequireBodySize(body);
        return _cbor.ValidateAndCopy(body);
    }

    private void RequireBodySize(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty || body.Length > _maxMessageSize)
        {
            throw new CborContentException("The Device Initialize message exceeds the Device limit or is empty.");
        }
    }
}
