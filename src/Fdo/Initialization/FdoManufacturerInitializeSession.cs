// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Serialization;

namespace Fdo.Initialization;

/// <summary>Untrusted lookup metadata received from a Device.</summary>
public sealed class FdoManufacturerInitializeRequest
{
    private readonly byte[]? _manufacturingInfo;
    private readonly byte[] _capabilityFlags;

    internal FdoManufacturerInitializeRequest(Guid runId, FdoDeviceInitializeCodec.AppStart message)
    {
        RunId = runId;
        _manufacturingInfo = message.EncodedDeviceMfgInfo?.ToArray();
        _capabilityFlags = message.CapabilityFlags.ToArray();
        var vendors = new string[message.VendorCapabilities.Count];
        for (int i = 0; i < vendors.Length; i++)
        {
            vendors[i] = message.VendorCapabilities[i];
        }

        VendorCapabilities = Array.AsReadOnly(vendors);
    }

    /// <summary>The local identifier for this manufacturing run.</summary>
    public Guid RunId { get; }

    /// <summary>The Device's advertised capability flags.</summary>
    public ReadOnlyMemory<byte> CapabilityFlags => (byte[])_capabilityFlags.Clone();

    /// <summary>The Device's advertised vendor capabilities.</summary>
    public IReadOnlyList<string> VendorCapabilities { get; }

    /// <summary>
    /// The optional encoded CBOR manufacturing information. It is lookup
    /// metadata, not authenticated Device identity.
    /// </summary>
    public ReadOnlyMemory<byte>? EncodedDeviceMfgInfo =>
        _manufacturingInfo is null ? (ReadOnlyMemory<byte>?)null : (byte[])_manufacturingInfo.Clone();
}

/// <summary>A proposed voucher header and Device certificate chain.</summary>
/// <remarks>
/// Creation generates a new random FDO GUID. The host must authorize and
/// reserve the Device before creating a proposal and retain that proposal
/// before returning it to the session. Do not create another proposal for an
/// active Device or an unresolved attempt.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoManufacturerInitializeProposal
{
    private readonly byte[] _headerTag;
    private readonly byte[] _chain;

    private FdoManufacturerInitializeProposal(ReadOnlyMemory<byte> headerTag, ReadOnlyMemory<byte> chain)
    {
        _headerTag = headerTag.ToArray();
        _chain = chain.ToArray();
    }

    /// <summary>The encoded voucher header, including its byte-string wrapper.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_headerTag.Clone();

    /// <summary>The encoded x5chain of Device attestation certificates.</summary>
    public ReadOnlyMemory<byte> EncodedDeviceCertificateChain => (byte[])_chain.Clone();

    /// <summary>
    /// Creates a proposal with a random GUID and a certificate-chain hash.
    /// The host must validate the chain, authorize the Device and verify its
    /// relationship to the certificate independently of DI.
    /// </summary>
    /// <param name="deviceInfo">Manufacturer-supplied Device information.</param>
    /// <param name="manufacturerPublicKey">The initial Owner public key, P-256 or P-384.</param>
    /// <param name="deviceCertificates">DER Device certificates in x5chain order.</param>
    /// <param name="encodedRendezvousInfo">
    /// Encoded RendezvousInfo containing a Device-applicable rvserver.local
    /// entry, or null to use a single local DNS directive.
    /// </param>
    public static FdoManufacturerInitializeProposal Create(
        string deviceInfo,
        ECDsa manufacturerPublicKey,
        IReadOnlyList<ReadOnlyMemory<byte>> deviceCertificates,
        ReadOnlyMemory<byte>? encodedRendezvousInfo = null)
    {
        (ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> chain) = FdoInitializationFields.CreateProposal(
            deviceInfo, manufacturerPublicKey, deviceCertificates, encodedRendezvousInfo);
        return new FdoManufacturerInitializeProposal(header, chain);
    }

    /// <summary>
    /// Creates a proposal with an RSA initial Owner key. The host must
    /// independently validate and authorize the Device and its certificates.
    /// </summary>
    /// <param name="deviceInfo">Manufacturer-supplied Device information.</param>
    /// <param name="manufacturerPublicKey">The initial Owner RSA public key.</param>
    /// <param name="deviceCertificates">DER Device certificates in x5chain order.</param>
    /// <param name="restricted">
    /// Selects RSA2048RESTR; otherwise the key is encoded as RSAPKCS.
    /// </param>
    /// <param name="encodedRendezvousInfo">
    /// Encoded RendezvousInfo containing a Device-applicable rvserver.local
    /// entry, or null to use a single local DNS directive.
    /// </param>
    public static FdoManufacturerInitializeProposal CreateRsa(
        string deviceInfo,
        RSA manufacturerPublicKey,
        IReadOnlyList<ReadOnlyMemory<byte>> deviceCertificates,
        bool restricted = false,
        ReadOnlyMemory<byte>? encodedRendezvousInfo = null)
    {
        (ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> chain) = FdoInitializationFields.CreateProposal(
            deviceInfo, manufacturerPublicKey, deviceCertificates, encodedRendezvousInfo, restricted);
        return new FdoManufacturerInitializeProposal(header, chain);
    }
}

/// <summary>The exact zero-entry voucher the manufacturer must retain.</summary>
public sealed class FdoManufacturerInitializeVoucher
{
    private readonly byte[] _guid;
    private readonly byte[] _headerTag;
    private readonly byte[] _headerHmac;
    private readonly byte[] _chain;
    private readonly byte[] _voucher;

    internal FdoManufacturerInitializeVoucher(
        Guid runId,
        FdoOwnershipVoucherHeader header,
        ReadOnlyMemory<byte> headerTag,
        FdoHashValue hmac,
        ReadOnlyMemory<byte> chain,
        ReadOnlyMemory<byte> voucher)
    {
        RunId = runId;
        _guid = header.Guid.ToArray();
        _headerTag = headerTag.ToArray();
        _headerHmac = hmac.Encode().ToArray();
        _chain = chain.ToArray();
        _voucher = voucher.ToArray();
    }

    /// <summary>The local identifier for this manufacturing run.</summary>
    public Guid RunId { get; }

    /// <summary>The 16-byte FDO GUID in wire order.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_guid.Clone();

    /// <summary>The voucher header, including its byte-string wrapper.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_headerTag.Clone();

    /// <summary>The Device-supplied encoded voucher header HMAC.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderHmac => (byte[])_headerHmac.Clone();

    /// <summary>The encoded x5chain of Device attestation certificates.</summary>
    public ReadOnlyMemory<byte> EncodedDeviceCertificateChain => (byte[])_chain.Clone();

    /// <summary>The complete encoded FDO 2.0 Ownership Voucher with no entries.</summary>
    public ReadOnlyMemory<byte> EncodedVoucher => (byte[])_voucher.Clone();
}

/// <summary>Authorizes the manufacturing relationship and persists its voucher.</summary>
/// <remarks>
/// The handler is bound by the host to the actual station and Device context.
/// It must authorize that relationship independently of DeviceMfgInfo, prevent
/// initialization of an active Device or unresolved prior attempt, validate
/// the Device certificate and its relationship to the Device, and durably
/// retain the selected proposal before returning it. PersistVoucherAsync must
/// durably retain the matching voucher before it returns. A throwing or
/// canceled callback can have an unknown durable outcome and requires
/// reconciliation; the session does not regenerate or retry a voucher.
/// </remarks>
public interface IFdoManufacturerInitializeHandler
{
    /// <summary>Authorizes and reserves the Device, then retains and returns one proposal.</summary>
    ValueTask<FdoManufacturerInitializeProposal> AuthorizeAndPrepareAsync(
        FdoManufacturerInitializeRequest request,
        CancellationToken cancellationToken);

    /// <summary>Durably retains the complete zero-entry voucher.</summary>
    ValueTask PersistVoucherAsync(
        FdoManufacturerInitializeVoucher voucher,
        CancellationToken cancellationToken);
}

/// <summary>Configuration for one manufacturing station session.</summary>
public sealed class FdoManufacturerInitializeOptions
{
    /// <summary>Host authorization and voucher persistence callbacks.</summary>
    public required IFdoManufacturerInitializeHandler Handler { get; init; }

    /// <summary>The maximum encoded message body accepted or sent by the station.</summary>
    public ushort MaxMessageSize { get; init; } = ushort.MaxValue;

    /// <summary>Selects the same provisional voucher-header HMAC convention as the Device.</summary>
    public required bool UseVoucherHeaderHmac { get; init; }
}

/// <summary>Processes one manufacturing side of Device Initialize.</summary>
/// <remarks>
/// The host binds requests to this session and confirms each response handoff.
/// A failed or uncertain handoff ends the run; confirmation does not prove
/// Device receipt. DI does not authenticate the Device or protect the channel.
/// The received HMAC cannot be verified without the Device's secret.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoManufacturerInitializeSession : IDisposable
{
    private readonly FdoDeviceInitializeCodec _codec = new();
    private readonly IFdoManufacturerInitializeHandler _handler;
    private readonly ushort _maxMessageSize;
    private FdoOwnershipVoucherHeader? _header;
    private ReadOnlyMemory<byte> _headerTag;
    private ReadOnlyMemory<byte> _chain;
    private FdoDeviceHmacAlgorithm _expectedHmac;
    private FdoDeviceInitializeMessageType _pendingResponse;
    private bool _awaitingHandoff;
    private Phase _phase;
    private int _busy;

    /// <summary>Creates a single-use manufacturing station session.</summary>
    public FdoManufacturerInitializeSession(FdoManufacturerInitializeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Handler);
        if (!options.UseVoucherHeaderHmac)
        {
            throw new InvalidOperationException("The selected Device Initialize HMAC convention requires explicit opt-in.");
        }

        ArgumentOutOfRangeException.ThrowIfZero(options.MaxMessageSize);
        _handler = options.Handler;
        _maxMessageSize = options.MaxMessageSize;
        RunId = Guid.NewGuid();
    }

    /// <summary>The local identifier for this manufacturing run.</summary>
    public Guid RunId { get; }

    /// <summary>Whether the authorization and reservation callback started.</summary>
    public bool PreparationStarted { get; private set; }

    /// <summary>The proposal returned by the host, or null if no return was observed.</summary>
    public FdoManufacturerInitializeProposal? PreparedProposal { get; private set; }

    /// <summary>Whether the voucher persistence callback started.</summary>
    public bool VoucherPersistenceStarted { get; private set; }

    /// <summary>The voucher whose persistence callback returned successfully.</summary>
    public FdoManufacturerInitializeVoucher? PersistedVoucher { get; private set; }

    /// <summary>Whether the station returned DI.Done.</summary>
    public bool DoneProduced { get; private set; }

    /// <summary>Whether the host confirmed its DI.Done response handoff.</summary>
    public bool DoneHandoffConfirmed { get; private set; }

    /// <summary>Processes one request. A processing failure ends this session.</summary>
    public async ValueTask<FdoDeviceInitializeResponse> ProcessAsync(
        ushort protocolVersion,
        FdoDeviceInitializeMessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The manufacturing session is already processing a request.");
        }

        bool completed = false;
        try
        {
            RequireUsable();
            if (_awaitingHandoff)
            {
                throw new InvalidOperationException("Confirm the previous response handoff before another request.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            FdoDeviceInitializeMessageType expected = _phase == Phase.AppStart
                ? FdoDeviceInitializeMessageType.AppStart
                : FdoDeviceInitializeMessageType.SetHmac;
            if (protocolVersion != 200 || messageType != expected)
            {
                throw new CborContentException("The Device Initialize request version or message type is unexpected.");
            }

            RequireBodySize(encodedBody);
            byte[] body = encodedBody.ToArray();
            FdoDeviceInitializeResponse response = _phase == Phase.AppStart
                ? await ProcessAppStartAsync(body, cancellationToken).ConfigureAwait(false)
                : await ProcessSetHmacAsync(body, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RequireBodySize(response.EncodedBody);
            _pendingResponse = response.MessageType;
            _awaitingHandoff = true;
            if (response.MessageType == FdoDeviceInitializeMessageType.Done)
            {
                DoneProduced = true;
            }

            completed = true;
            return response;
        }
        finally
        {
            if (!completed && _phase is not (Phase.Complete or Phase.Disposed))
            {
                _phase = Phase.Failed;
            }

            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>Records a successful response handoff, not Device receipt.</summary>
    public void ConfirmResponseSent()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The manufacturing session is already processing a request.");
        }

        try
        {
            if (_phase is Phase.Failed or Phase.Disposed || !_awaitingHandoff)
            {
                throw new InvalidOperationException("No manufacturing response is awaiting handoff.");
            }

            _awaitingHandoff = false;
            if (_pendingResponse == FdoDeviceInitializeMessageType.Done)
            {
                DoneHandoffConfirmed = true;
            }
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>Ends the session without changing host storage.</summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The manufacturing session is already processing a request.");
        }

        try
        {
            _phase = Phase.Disposed;
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private async ValueTask<FdoDeviceInitializeResponse> ProcessAppStartAsync(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        FdoDeviceInitializeCodec.AppStart message = _codec.DecodeAppStart(body);
        FdoInitializationFields.RequireFdo20(message.CapabilityFlags);
        var request = new FdoManufacturerInitializeRequest(RunId, message);
        PreparationStarted = true;
        FdoManufacturerInitializeProposal proposal = await _handler.AuthorizeAndPrepareAsync(
            request, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The manufacturing handler returned no proposal.");
        PreparedProposal = proposal;
        cancellationToken.ThrowIfCancellationRequested();

        _headerTag = proposal.EncodedVoucherHeaderTag;
        _chain = proposal.EncodedDeviceCertificateChain;
        _header = FdoInitializationFields.ReadHeader(_headerTag);
        int manufacturerKeyType = FdoInitializationFields.GetKeyType(_header.ManufacturerKey);
        int deviceKeyType = FdoInitializationFields.GetDeviceKeyType(_chain);
        _expectedHmac = FdoInitializationFields.SelectHmac(deviceKeyType, manufacturerKeyType);
        FdoHashAlgorithm digest = _header.CertificateChainHash.Algorithm;
        if (!new FdoCertificateChainHash().Verify(digest, _chain, _header.CertificateChainHash))
        {
            throw new CryptographicException("The Device certificate chain does not match the voucher header.");
        }

        ReadOnlyMemory<byte> encoded = _codec.EncodeSetCredentials(new FdoDeviceInitializeCodec.SetCredentials(
            new byte[] { (byte)FdoKnownCapabilities.Fdo20 }, Array.Empty<string>(), _headerTag));
        _phase = Phase.SetHmac;
        return new FdoDeviceInitializeResponse(200, FdoDeviceInitializeMessageType.SetCredentials, encoded);
    }

    private async ValueTask<FdoDeviceInitializeResponse> ProcessSetHmacAsync(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        FdoHashValue hmac = _codec.DecodeSetHmac(body);
        if (hmac.Algorithm != FdoInitializationFields.HmacAlgorithm(_expectedHmac))
        {
            throw new CryptographicException("The Device supplied an unexpected voucher HMAC algorithm.");
        }

        ReadOnlyMemory<byte> encoded = FdoInitializationFields.CreateVoucher(_headerTag, hmac, _chain);
        var voucher = new FdoManufacturerInitializeVoucher(
            RunId, _header!, _headerTag, hmac, _chain, encoded);
        VoucherPersistenceStarted = true;
        await _handler.PersistVoucherAsync(voucher, cancellationToken).ConfigureAwait(false);
        PersistedVoucher = voucher;
        cancellationToken.ThrowIfCancellationRequested();
        _phase = Phase.Complete;
        return new FdoDeviceInitializeResponse(200, FdoDeviceInitializeMessageType.Done, _codec.EncodeDone());
    }

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_phase == Phase.Disposed, this);
        if (_phase is Phase.Complete or Phase.Failed)
        {
            throw new InvalidOperationException("The manufacturing session has ended.");
        }
    }

    private void RequireBodySize(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty || body.Length > _maxMessageSize)
        {
            throw new CborContentException("The Device Initialize message exceeds the station limit or is empty.");
        }
    }

    private enum Phase
    {
        AppStart = 0,
        SetHmac = 1,
        Complete = 2,
        Failed = 3,
        Disposed = 4,
    }
}
