// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Enrollment;

/// <summary>
/// Processes one paired FDO 2.0 Owner run. The host supplies transport, binds
/// each request to this session, bounds incoming bodies, and confirms each
/// response handoff before the next request.
/// </summary>
/// <remarks>
/// The supported profile uses explicit bypass or paired rendezvous, credential
/// reuse or explicitly selected replacement, a devmod inventory that may span
/// several ServiceInfo rounds at complete-entry boundaries, and provisional
/// paired wire choices. With explicit opt-in on both peers, a configured
/// Delegate signs the Owner proof and the credential-reuse SetupDevice; Owner2
/// still signs a replacement. The Owner verifies its Delegate chain and the
/// permission for the configured disposition at construction. It does not
/// implement delegated rendezvous, FDO disable,
/// retries, recovery, or general FDO interoperability. Dispose the
/// session after any failed or ambiguous response handoff. A confirmed handoff
/// is not evidence that the Device received the response.
/// <para>
/// After key exchange, when an authenticated request fails its semantic or
/// local processing, the Owner returns one FDO Error sealed on the live
/// channel instead of a response, then ends the run. It sends no Error when
/// the request does not authenticate, after a response was sealed, or before
/// key exchange. It accepts a Device Error only when the Error authenticates
/// on the live channel and names the last Owner response, answers it with an
/// empty Error response, and never answers it with another Error.
/// </para>
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoOwnerSession : IDisposable
{
    private readonly FdoCborCodec _cbor = new();
    private readonly FdoTo2InitialCodec _initial = new();
    private readonly FdoTo2ServiceInfoCodec _info = new();
    private readonly ReadOnlyMemory<byte> _header;
    private readonly ReadOnlyMemory<byte> _headerHmac;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _entries;
    private readonly ReadOnlyMemory<byte> _certificateChain;
    private readonly AsymmetricAlgorithm _signingKey;
    private readonly IFdoOwnerDeviceTrustPolicy _trustPolicy;
    private readonly IFdoOwnerEnrollmentHandler _handler;
    private readonly IFdoOwnerCaCertificatesHandler? _caCertificatesHandler;
    private readonly IFdoOwnerCsrAttributesHandler? _csrAttributesHandler;
    private readonly IFdoOwnerReenrollmentHandler? _reenrollmentHandler;
    private readonly IFdoOwnerServerKeygenHandler? _serverKeygenHandler;
    private readonly IFdoOwnerReplacementHandler? _replacementHandler;
    private readonly AsymmetricAlgorithm? _replacementSigningKey;
    private readonly ReadOnlyMemory<byte> _replacementRendezvous;
    private readonly AsymmetricAlgorithm? _delegateSigningKey;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>>? _delegateChain;
    private readonly TimeProvider? _delegateTime;
    private readonly FdoDelegateOfflineRevocationPolicy? _delegateOfflineRevocation;
    private readonly ReadOnlyMemory<byte> _delegateKey;
    private readonly FdoKeyExchangeSuite _exchange;
    private readonly FdoKeyExchangeSuite? _additionalExchange;
    private readonly long[] _cipherOffers;
    private readonly ushort _maxMessageSize;
    private readonly ushort _maxDeviceServiceInfoSize;
    private readonly FdoServiceInfoBatches.Assembler _deviceAssembly = new();
    private FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice? _authenticatedDevice;
    private IReadOnlyList<ReadOnlyMemory<byte>>? _checkedEntries;
    private IFdoTo2PairedChannel? _channel;
    private FdoTo2ServiceInfoState? _serviceInfo;
    private Queue<IReadOnlyList<Entry>>? _ownerQueue;
    private bool _ownerQueueIsDone;
    private FdoEnrollmentRequest? _enrollment;
    private byte[]? _issuedCertificate;
    private FdoCsrAttributes? _csrAttributes;
    private byte[]? _doneNonce;
    private byte[]? _setupNonce;
    private byte[]? _replacementGuid;
    private ReadOnlyMemory<byte> _replacementHeader;
    private FdoHashAlgorithm? _replacementHmacAlgorithm;
    private ReadOnlyMemory<byte> _probe;
    private ReadOnlyMemory<byte> _acknowledgement;
    private int _deviceMessageLimit;
    private int _ownerServiceInfoLimit;
    private int _nextEntry;
    private int _busy;
    private bool _awaitingHandoff;
    private bool _requestAuthenticated;
    private bool _responseSealed;
    private FdoTo2MessageType _pendingResponseType;
    private Phase _phase;

    /// <summary>
    /// Creates a single-use Owner session and snapshots the voucher and trust
    /// material. The signing key and enrollment handler remain caller-owned.
    /// </summary>
    /// <param name="options">The configuration for this operation.</param>
    public FdoOwnerSession(FdoOwnerSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.EncodedVoucherEntries);
        ArgumentNullException.ThrowIfNull(options.OwnerSigningKey);
        ArgumentNullException.ThrowIfNull(options.EnrollmentHandler);
        if ((!options.AllowRendezvousBypass && !options.AllowRendezvous) ||
            (!options.AllowCredentialReuse && options.Replacement is null) ||
            !options.UseProvisionalPairedProfile)
        {
            throw new InvalidOperationException(
                "The paired Owner requires an explicit rendezvous route, disposition, and paired-profile opt-in.");
        }

        if (options.MaxMessageSize == 0 || options.MaxDeviceServiceInfoSize == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The paired profile requires nonzero message limits.");
        }

        if (options.EncodedVoucherEntries.Count is < 1 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Paired onboarding requires between 1 and 255 voucher entries.");
        }

        _exchange = FdoPairedProtocol.MapKeyExchangeSuite(options.KeyExchangeSuite);
        FdoPairedProtocol.RequireExchangeOptIn(
            _exchange, options.UseProvisionalPairedDh, options.UseProvisionalPairedAsymkex);
        if (options.AdditionalKeyExchangeSuite is { } additional)
        {
            FdoKeyExchangeSuite second = FdoPairedProtocol.MapKeyExchangeSuite(additional);
            if (options.UseDelegatedOwnerProof || !IsDirectRsaExchangePair(_exchange, second))
            {
                throw new ArgumentException("Only a direct Owner may pair size-matched DH and ASYMKEX offers.", nameof(options));
            }

            FdoPairedProtocol.RequireExchangeOptIn(second, options.UseProvisionalPairedDh, options.UseProvisionalPairedAsymkex);
            _additionalExchange = second;
        }

        _cipherOffers = SnapshotCipherOffers(options);

        _header = CopyBounded(options.EncodedVoucherHeaderTag);
        _headerHmac = CopyBounded(options.EncodedVoucherHeaderHmac);
        _certificateChain = CopyBounded(options.EncodedDeviceCertificateChain);
        var entries = new ReadOnlyMemory<byte>[options.EncodedVoucherEntries.Count];
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i] = CopyBounded(options.EncodedVoucherEntries[i]);
        }

        _entries = Array.AsReadOnly(entries);
        _trustPolicy = new FdoPinnedDeviceTrustPolicy(
            CopyBounded(options.TrustedManufacturerKey),
            CopyBounded(options.DeviceTrustAnchor),
            options.DeviceRevocationMode);
        _signingKey = options.OwnerSigningKey;
        if (_additionalExchange is { } secondExchange)
        {
            var voucher = FdoTo2OwnerDeviceAuthenticator.CheckLocalVoucher(
                _header, _headerHmac, _entries, _certificateChain, _signingKey, _cbor);
            using FdoPublicKeyCodec.DecodedKey key = new FdoPublicKeyCodec().Decode(voucher.OwnerKey);
            FdoTo2OwnerProofCodec.RequireOwnerSuite(_exchange, key);
            FdoTo2OwnerProofCodec.RequireOwnerSuite(secondExchange, key);
        }
        _handler = options.EnrollmentHandler;
        _caCertificatesHandler = options.CaCertificatesHandler;
        _csrAttributesHandler = options.CsrAttributesHandler;
        _reenrollmentHandler = options.ReenrollmentHandler;
        _serverKeygenHandler = options.ServerKeygenHandler;
        if (options.Replacement is FdoOwnerReplacementOptions replacement)
        {
            ArgumentNullException.ThrowIfNull(replacement.Owner2SigningKey);
            ArgumentNullException.ThrowIfNull(replacement.Handler);
            _replacementSigningKey = replacement.Owner2SigningKey;
            _replacementHandler = replacement.Handler;
            _replacementRendezvous = CopyBounded(replacement.EncodedRendezvousInfo);
        }
        _maxMessageSize = options.MaxMessageSize;
        _maxDeviceServiceInfoSize = options.MaxDeviceServiceInfoSize;
        if (options.UseDelegatedOwnerProof)
        {
            ArgumentNullException.ThrowIfNull(options.DelegateSigningKey);
            ArgumentNullException.ThrowIfNull(options.DelegateCertificateChain);
            ArgumentNullException.ThrowIfNull(options.DelegateTimeProvider);
            var chain = new ReadOnlyMemory<byte>[options.DelegateCertificateChain.Count];
            for (int i = 0; i < chain.Length; i++)
            {
                chain[i] = CopyBounded(options.DelegateCertificateChain[i]);
            }

            _delegateChain = Array.AsReadOnly(chain);
            _delegateSigningKey = options.DelegateSigningKey;
            _delegateTime = options.DelegateTimeProvider;
            _delegateOfflineRevocation = options.DelegateOfflineRevocation;
            FdoVerifiedDelegateChain verified = new FdoTo2OwnerProofCodec().VerifyDelegateSigner(
                _header, _signingKey, _exchange, NewDelegateSigner());
            verified.Require(_replacementSigningKey is null
                ? FdoDelegatePermissions.OnboardReuseCredentials
                : FdoDelegatePermissions.OnboardNewCredentials);
            _delegateKey = verified.DelegateKey;
        }
        else if (options.DelegateSigningKey is not null || options.DelegateCertificateChain is not null ||
            options.DelegateTimeProvider is not null || options.DelegateOfflineRevocation is not null)
        {
            throw new ArgumentException(
                "Delegate settings can only be configured with a delegated Owner proof.", nameof(options));
        }

        RunId = Guid.NewGuid();
    }

    /// <summary>The local identifier for this Owner run.</summary>
    public Guid RunId { get; }

    /// <summary>
    /// The enrollment whose durable commit callback returned successfully, or
    /// null if no successful return was observed. A throwing callback can have
    /// an unknown durable outcome.
    /// </summary>
    public FdoEnrollmentCommit? CommittedEnrollment { get; private set; }

    /// <summary>Whether the Owner invoked the replacement voucher commit callback.</summary>
    public bool ReplacementCommitStarted { get; private set; }

    /// <summary>
    /// The replacement whose commit returned successfully, or null when no
    /// successful return was observed. A throwing callback can have an
    /// unknown durable outcome.
    /// </summary>
    public FdoOwnerReplacementCommit? CommittedReplacement { get; private set; }

    /// <summary>Whether the Owner invoked the separate enrollment commit callback.</summary>
    public bool EnrollmentCommitStarted { get; private set; }

    /// <summary>Whether the Owner returned a protected DoneAck20 response.</summary>
    public bool DoneAckProduced { get; private set; }

    /// <summary>
    /// Whether the host confirmed its DoneAck20 response handoff. This does
    /// not establish that the Device received or accepted it.
    /// </summary>
    public bool DoneAckHandoffConfirmed { get; private set; }

    /// <summary>
    /// The FDO Error code that the Owner sealed in its last response, or null.
    /// The host sends that response once with HTTP 500 and must not confirm it.
    /// </summary>
    public ushort? SentErrorCode { get; private set; }

    /// <summary>
    /// The code of an authenticated Device Error that ended this run, or null.
    /// The Device's description text is not retained.
    /// </summary>
    public ushort? ReceivedErrorCode { get; private set; }

    /// <summary>
    /// Processes the next request and returns its response. The body is copied
    /// before processing. Any processing failure ends this session.
    /// </summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <exception cref="InvalidOperationException">
    /// Confirm the previous response handoff before another request. The Owner session cannot accept another request.
    /// The Owner session is already processing a request.
    /// </exception>
    /// <exception cref="CborContentException">
    /// The FDO request body exceeds the Owner message limit or is empty. The FDO request version or message type is
    /// unexpected. The FDO response exceeds the Device's message limit.
    /// </exception>
    public async ValueTask<FdoOwnerResponse> ProcessAsync(
        ushort protocolVersion,
        FdoTo2MessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Owner session is already processing a request.");
        }

        bool completed = false;
        _requestAuthenticated = false;
        _responseSealed = false;
        try
        {
            RequireUsable();
            if (_awaitingHandoff)
            {
                throw new InvalidOperationException("Confirm the previous response handoff before another request.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (messageType == FdoTo2MessageType.Error)
            {
                return AcceptDeviceError(protocolVersion, encodedBody);
            }

            if (protocolVersion != 200 || !IsExpectedRequest(messageType))
            {
                throw new CborContentException("The FDO request version or message type is unexpected.");
            }

            if (encodedBody.IsEmpty || encodedBody.Length > _maxMessageSize)
            {
                throw new CborContentException("The FDO request body exceeds the Owner message limit or is empty.");
            }

            byte[] body = encodedBody.ToArray();
            FdoOwnerResponse response = _phase switch
            {
                Phase.Probe => ProcessProbe(body),
                Phase.DeviceProof => ProcessDeviceProof(body),
                Phase.Entries => ProcessEntry(body),
                Phase.Ready => ProcessReady(body),
                Phase.Done when messageType == FdoTo2MessageType.Done20 =>
                    await ProcessDoneAsync(body, cancellationToken).ConfigureAwait(false),
                Phase.Inventory or Phase.Enrollment or Phase.EnrollmentAfterCa or
                    Phase.EnrollmentAfterAttributes or Phase.Done =>
                    await ProcessServiceInfoAsync(body, cancellationToken).ConfigureAwait(false),
                _ => throw new InvalidOperationException("The Owner session cannot accept another request."),
            };
            cancellationToken.ThrowIfCancellationRequested();
            if (response.EncodedBody.Length > _deviceMessageLimit)
            {
                throw new CborContentException("The FDO response exceeds the Device's message limit.");
            }

            _pendingResponseType = response.MessageType;
            _awaitingHandoff = true;
            if (response.MessageType == FdoTo2MessageType.DoneAck20)
            {
                DoneAckProduced = true;
            }

            completed = true;
            return response;
        }
        catch (Exception ex) when (
            messageType != FdoTo2MessageType.Error &&
            _requestAuthenticated && !_responseSealed && _channel is not null &&
            ex is not OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            // The request authenticated on the live channel, so the Device can
            // authenticate a sealed Error that names it. The session still ends.
            FdoOwnerResponse? error = TrySealError(FdoErrorCodes.Classify(ex), (byte)messageType);
            if (error is null)
            {
                throw;
            }

            return error;
        }
        finally
        {
            if (!completed)
            {
                Fail();
            }

            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>
    /// Records that the host handed off the last response. If the handoff
    /// failed or its outcome is ambiguous, dispose the session instead.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No Owner response is awaiting handoff. The Owner session is already processing a request.
    /// </exception>
    public void ConfirmResponseSent()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Owner session is already processing a request.");
        }

        try
        {
            RequireUsable();
            if (!_awaitingHandoff)
            {
                throw new InvalidOperationException("No Owner response is awaiting handoff.");
            }

            _awaitingHandoff = false;
            if (_pendingResponseType == FdoTo2MessageType.DoneAck20)
            {
                DoneAckHandoffConfirmed = true;
            }
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>Ends the run and clears its protected-channel key.</summary>
    /// <exception cref="InvalidOperationException">The Owner session is already processing a request.</exception>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Owner session is already processing a request.");
        }

        try
        {
            _channel?.Dispose();
            _channel = null;
            _deviceAssembly.Clear();
            _ownerQueue = null;
            _phase = Phase.Disposed;
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private FdoOwnerResponse ProcessProbe(ReadOnlyMemory<byte> body)
    {
        FdoTo2InitialCodec.Probe probe = _initial.DecodeProbe(body);
        if (probe.MaxDeviceMessageSize == 0)
        {
            throw new NotSupportedException("The paired profile requires an explicit Device message limit.");
        }

        byte capabilities = (byte)FdoKnownCapabilities.Fdo20;
        if (_delegateChain is not null)
        {
            if (probe.CapabilityFlags.IsEmpty ||
                (probe.CapabilityFlags.Span[0] & (byte)FdoKnownCapabilities.Delegation) == 0)
            {
                throw new NotSupportedException("The Device did not advertise the delegation capability.");
            }

            capabilities |= (byte)FdoKnownCapabilities.Delegation;
        }

        _deviceMessageLimit = probe.MaxDeviceMessageSize;
        _probe = body;
        _doneNonce = RandomNumberGenerator.GetBytes(16);
        string exchangeName = FdoKeyExchangeSuites.GetName(_exchange);
        string[] exchanges = _additionalExchange is { } additional
            ? [exchangeName, FdoKeyExchangeSuites.GetName(additional)] : [exchangeName];
        _acknowledgement = _initial.EncodeAcknowledgement(new FdoTo2InitialCodec.Acknowledgement(
            new byte[] { capabilities }, Array.Empty<string>(), probe.Guid,
            _maxMessageSize, exchanges, _cipherOffers, _doneNonce,
            _initial.ComputeProbeHash(FdoHashAlgorithm.Sha256, body)));
        _phase = Phase.DeviceProof;
        return new FdoOwnerResponse(FdoTo2MessageType.HelloDeviceAck20, _acknowledgement);
    }

    private FdoOwnerResponse ProcessDeviceProof(ReadOnlyMemory<byte> body)
    {
        var verifier = new FdoTo2OwnerDeviceAuthenticator(
            _header, _headerHmac, _entries, _certificateChain, _signingKey,
            _probe, _acknowledgement, _trustPolicy);
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated = verifier.Verify(body);
        FdoTo2DeviceProofCodec.DeviceProof proof = authenticated.DeviceProof;
        using IFdoPairedKeyExchange exchange = FdoPairedProtocol.CreateOwnerExchange(proof.Exchange, _signingKey);
        ReadOnlyMemory<byte> ownerProof = new FdoTo2OwnerProofCodec().Sign(
            authenticated.Header, authenticated.HeaderHmac, authenticated.Entries.Count,
            proof.OwnerNonce, proof.Exchange, exchange.ExportParameter(), _maxMessageSize, _signingKey,
            _delegateChain is null ? null : NewDelegateSigner(), authenticated.OwnerKey);
        byte[] key = FdoPairedProtocol.DeriveSessionKey(exchange, proof.DeviceParameter, proof.Cipher);
        try
        {
            _channel = FdoTo2PairedChannels.Create(FdoTo2PairedRole.Owner, proof.Cipher, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        _authenticatedDevice = authenticated;
        _checkedEntries = authenticated.Entries;
        _phase = Phase.Entries;
        return new FdoOwnerResponse(FdoTo2MessageType.ProveOVHdr20, ownerProof);
    }

    private FdoOwnerResponse ProcessEntry(ReadOnlyMemory<byte> body)
    {
        IReadOnlyList<ReadOnlyMemory<byte>> entries = Require(_checkedEntries);
        int index = FdoPairedProtocol.DecodeEntryRequest(_cbor, body);
        if (index != _nextEntry || index >= entries.Count)
        {
            throw new CborContentException("The voucher entry request is out of order.");
        }

        ReadOnlyMemory<byte> response = FdoPairedProtocol.EncodeEntryResponse(index, entries[index]);
        _nextEntry++;
        if (_nextEntry == entries.Count)
        {
            _phase = Phase.Ready;
        }

        return new FdoOwnerResponse(FdoTo2MessageType.OVNextEntry20, response);
    }

    private FdoOwnerResponse ProcessReady(ReadOnlyMemory<byte> body)
    {
        IFdoTo2PairedChannel channel = Require(_channel);
        byte[] plaintext = OpenRequest(channel, body);
        FdoTo2ServiceInfoCodec.DeviceServiceInfoReady ready;
        try
        {
            ready = _info.DecodeDeviceReady(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        _ownerServiceInfoLimit = ready.MaxOwnerServiceInfoSize ?? 1300;
        if (_ownerServiceInfoLimit == 0)
        {
            throw new CborContentException("The paired profile requires a nonzero Owner ServiceInfo limit.");
        }

        _setupNonce = ready.Nonce.ToArray();
        _serviceInfo = new FdoTo2ServiceInfoState(
            Require(_doneNonce), _maxDeviceServiceInfoSize, _ownerServiceInfoLimit);
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated = Require(_authenticatedDevice);
        var setup = new FdoTo2SetupDeviceCodec();
        ReadOnlyMemory<byte> signed;
        if (_replacementSigningKey is AsymmetricAlgorithm owner2)
        {
            byte[] guid;
            do
            {
                guid = RandomNumberGenerator.GetBytes(16);
            }
            while (CryptographicOperations.FixedTimeEquals(guid, authenticated.Voucher.Guid.Span));
            signed = setup.SignReplacement(
                authenticated, owner2, _replacementRendezvous, guid, ready.Nonce,
                _maxDeviceServiceInfoSize);
            using FdoPublicKeyCodec.DecodedKey current = new FdoPublicKeyCodec().Decode(authenticated.OwnerKey);
            ReadOnlyMemory<byte> ownerKey = new FdoPublicKeyCodec().EncodeOwnerKey(owner2, current.KeyType);
            _replacementHeader = FdoInitializationFields.CreateReplacementHeader(
                _header, guid, _replacementRendezvous, ownerKey);
            _replacementGuid = guid;
            FdoDeviceHmacAlgorithm hmac = FdoInitializationFields.SelectHmac(
                FdoInitializationFields.GetDeviceKeyType(_certificateChain),
                FdoInitializationFields.GetKeyType(ownerKey));
            _replacementHmacAlgorithm = FdoInitializationFields.HmacAlgorithm(hmac);
        }
        else
        {
            signed = setup.Sign(
                authenticated, _delegateSigningKey ?? _signingKey, true, _maxDeviceServiceInfoSize,
                _delegateChain is null ? default : _delegateKey);
        }
        ReadOnlyMemory<byte> response = SealResponse(channel, signed);
        _phase = Phase.Inventory;
        return new FdoOwnerResponse(FdoTo2MessageType.SetupDevice20, response);
    }

    private async ValueTask<FdoOwnerResponse> ProcessServiceInfoAsync(
        ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        IFdoTo2PairedChannel channel = Require(_channel);
        FdoTo2ServiceInfoState state = Require(_serviceInfo);
        byte[] plaintext = OpenRequest(channel, body);
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message;
        try
        {
            // The state counts this round and enforces the round limit before
            // any module or handler runs.
            message = state.RecordDevice(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        if (_ownerQueue is not null)
        {
            return SendQueued();
        }

        if (_phase == Phase.Done)
        {
            QueueOwner([], true);
            return SendQueued();
        }

        _deviceAssembly.Append(message.ServiceInfo);
        if (message.IsMoreServiceInfo)
        {
            QueueOwner([], false);
            return SendQueued();
        }

        var assembled = new FdoTo2ServiceInfoCodec.DeviceServiceInfo(false, _deviceAssembly.Take());
        return _phase == Phase.Inventory
            ? ProcessInventory(assembled)
            : await ProcessEnrollmentAsync(assembled, cancellationToken).ConfigureAwait(false);
    }

    private FdoOwnerResponse ProcessInventory(FdoTo2ServiceInfoCodec.DeviceServiceInfo inventory)
    {
        FdoPairedProtocol.ValidateInventory(inventory);
        QueueOwner([new Entry("fdo.csr:active", new byte[] { 0xF5 })], false);
        _phase = Phase.Enrollment;
        return SendQueued();
    }

    private async ValueTask<FdoOwnerResponse> ProcessEnrollmentAsync(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message, CancellationToken cancellationToken)
    {
        bool includesActivation = _phase == Phase.Enrollment;
        if (includesActivation && FdoPairedProtocol.IsCaCertificatesRequest(message))
        {
            return await ProcessCaCertificatesRequestAsync(message, cancellationToken).ConfigureAwait(false);
        }

        if (_phase != Phase.EnrollmentAfterAttributes &&
            FdoPairedProtocol.IsCsrAttributesRequest(message, includesActivation))
        {
            return await ProcessCsrAttributesRequestAsync(message, includesActivation, cancellationToken)
                .ConfigureAwait(false);
        }

        (byte[] request, bool isReenrollment, bool isServerKeyGeneration) = FdoPairedProtocol.DecodeEnrollmentRequest(
            message, new FdoCsrBase64TextCodec(_maxDeviceServiceInfoSize), includesActivation);
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated = Require(_authenticatedDevice);
        var enrollment = new FdoEnrollmentRequest(
            RunId, authenticated.DeviceProof.Guid, authenticated.DeviceCertificate, request,
            isReenrollment, csrAttributes: _csrAttributes, isServerKeyGeneration: isServerKeyGeneration);
        if (isServerKeyGeneration)
        {
            return await ProcessServerKeygenAsync(enrollment, cancellationToken).ConfigureAwait(false);
        }

        if (isReenrollment)
        {
            IFdoOwnerReenrollmentHandler handler = _reenrollmentHandler ??
                throw new InvalidOperationException("The Owner has no re-enrollment handler configured.");
            ReadOnlyMemory<byte> priorCertificate = await handler.GetPriorCertificateAsync(enrollment, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            FdoReenrollmentDetails details = FdoCsrReenrollment.CheckRequest(request, priorCertificate);
            enrollment = new FdoEnrollmentRequest(
                RunId, authenticated.DeviceProof.Guid, authenticated.DeviceCertificate, request, true, details,
                _csrAttributes);
            if (details.IdentityChange is not null)
            {
                await handler.ApproveIdentityChangeAsync(enrollment, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        ReadOnlyMemory<byte> issued = await _handler.AuthorizeAndIssueAsync(
            enrollment, cancellationToken).ConfigureAwait(false);
        byte[] certificate = issued.ToArray();
        Entry entry = new FdoCsrBase64TextCodec(_ownerServiceInfoLimit)
            .EncodeResponse(request, certificate, isReenrollment);
        if (enrollment.Reenrollment is FdoReenrollmentDetails reenrollment)
        {
            FdoCsrReenrollment.CheckResponse(reenrollment, certificate);
        }
        QueueOwner([entry], true);
        _enrollment = enrollment;
        _issuedCertificate = certificate;
        _phase = Phase.Done;
        return SendQueued();
    }

    private async ValueTask<FdoOwnerResponse> ProcessServerKeygenAsync(
        FdoEnrollmentRequest enrollment, CancellationToken cancellationToken)
    {
        if (_serverKeygenHandler is null)
        {
            QueueOwner([new Entry("fdo.csr:error", new byte[] { 0x03 })], false);
            _phase = Phase.EnrollmentAfterAttributes;
            return SendQueued();
        }

        using FdoServerKeygenCredential credential = await _serverKeygenHandler
            .AuthorizeAndIssueAsync(enrollment, cancellationToken).ConfigureAwait(false);
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] certificate = credential.Certificate.ToArray();
        Entry entry = new FdoCsrServerKeygenCodec(_ownerServiceInfoLimit)
            .EncodeResponse(certificate, credential.PrivateKey);
        try
        {
            // One entry always forms one batch, so the private-key entry is
            // sealed here and never waits in the queue after it is cleared.
            QueueOwner([entry], true);
            _enrollment = enrollment;
            _issuedCertificate = certificate;
            _phase = Phase.Done;
            return SendQueued();
        }
        finally
        {
            FdoSecretBuffer.ClearOwned(entry.EncodedValue);
            _ownerQueue = null;
        }
    }

    private async ValueTask<FdoOwnerResponse> ProcessCsrAttributesRequestAsync(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message,
        bool includesActivation,
        CancellationToken cancellationToken)
    {
        FdoPairedProtocol.ValidateCsrAttributesRequest(message, includesActivation);
        Entry entry;
        if (_csrAttributesHandler is null)
        {
            entry = new Entry("fdo.csr:error", new byte[] { 0x03 });
        }
        else
        {
            FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated = Require(_authenticatedDevice);
            var request = new FdoCsrAttributesRequest(
                RunId, authenticated.DeviceProof.Guid, authenticated.DeviceCertificate);
            FdoCsrAttributes attributes = await _csrAttributesHandler
                .GetCsrAttributesAsync(request, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(attributes);
            entry = new FdoCsrBase64TextCodec(_ownerServiceInfoLimit).EncodeCsrAttributes(attributes);
            _csrAttributes = attributes;
        }

        QueueOwner([entry], false);
        _phase = Phase.EnrollmentAfterAttributes;
        return SendQueued();
    }

    private async ValueTask<FdoOwnerResponse> ProcessCaCertificatesRequestAsync(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message,
        CancellationToken cancellationToken)
    {
        ulong format = FdoPairedProtocol.DecodeCaCertificatesRequest(message);
        Entry entry;
        if (format != FdoCsrCaCertificatesCodec.CertsOnlyFormat)
        {
            entry = new Entry("fdo.csr:error", new byte[] { 0x05 });
        }
        else
        {
            IFdoOwnerCaCertificatesHandler handler = _caCertificatesHandler ??
                throw new InvalidOperationException("The Owner has no CA certificate handler configured.");
            FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated = Require(_authenticatedDevice);
            var request = new FdoCaCertificatesRequest(
                RunId, authenticated.DeviceProof.Guid, authenticated.DeviceCertificate, format);
            FdoCaCertificates certificates = await handler.GetCaCertificatesAsync(request, cancellationToken)
                .ConfigureAwait(false);
            ArgumentNullException.ThrowIfNull(certificates);
            entry = new FdoCsrBase64TextCodec(_ownerServiceInfoLimit).EncodeCaCertificates(certificates);
        }

        QueueOwner([entry], false);
        _phase = Phase.EnrollmentAfterCa;
        return SendQueued();
    }

    private async ValueTask<FdoOwnerResponse> ProcessDoneAsync(
        ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        IFdoTo2PairedChannel channel = Require(_channel);
        byte[] plaintext = OpenRequest(channel, body);
        FdoHashValue? replacementHmac;
        try
        {
            replacementHmac = Require(_serviceInfo).RecordDone(plaintext, _replacementHmacAlgorithm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        if (_replacementHandler is IFdoOwnerReplacementHandler replacementHandler)
        {
            FdoHashValue hmac = replacementHmac
                ?? throw new CborContentException("The replacement HMAC is missing.");
            ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
                _replacementHeader, hmac, _certificateChain);
            var replacement = new FdoOwnerReplacementCommit(
                RunId, Require(_authenticatedDevice).Voucher.Guid, Require(_replacementGuid),
                _replacementHeader, hmac.Encode(), voucher);
            cancellationToken.ThrowIfCancellationRequested();
            ReplacementCommitStarted = true;
            await replacementHandler.CommitAsync(replacement, cancellationToken).ConfigureAwait(false);
            CommittedReplacement = replacement;
            cancellationToken.ThrowIfCancellationRequested();
        }

        var commit = new FdoEnrollmentCommit(Require(_enrollment), Require(_issuedCertificate));
        EnrollmentCommitStarted = true;
        await _handler.CommitAsync(commit, cancellationToken).ConfigureAwait(false);
        CommittedEnrollment = commit;
        ReadOnlyMemory<byte> ack = FdoTo2CompletionCodec.EncodeDoneAck(Require(_setupNonce));
        ReadOnlyMemory<byte> response = SealResponse(channel, ack);
        _phase = Phase.Complete;
        return new FdoOwnerResponse(FdoTo2MessageType.DoneAck20, response);
    }

    private byte[] OpenRequest(IFdoTo2PairedChannel channel, ReadOnlyMemory<byte> body)
    {
        byte[] plaintext = channel.Open(body);
        _requestAuthenticated = true;
        return plaintext;
    }

    private ReadOnlyMemory<byte> SealResponse(IFdoTo2PairedChannel channel, ReadOnlyMemory<byte> plaintext)
    {
        // A started Seal can consume the next counter, so no Error may follow it.
        _responseSealed = true;
        return channel.Seal(plaintext);
    }

    private void QueueOwner(IReadOnlyList<Entry> entries, bool isDone)
    {
        IFdoTo2PairedChannel channel = Require(_channel);
        _ownerQueue = new Queue<IReadOnlyList<Entry>>(FdoServiceInfoBatches.Split(
            entries, _ownerServiceInfoLimit, channel.GetSealedLength, _deviceMessageLimit));
        _ownerQueueIsDone = isDone;
    }

    private FdoOwnerResponse SendQueued()
    {
        IFdoTo2PairedChannel channel = Require(_channel);
        FdoTo2ServiceInfoState state = Require(_serviceInfo);
        Queue<IReadOnlyList<Entry>> queue = Require(_ownerQueue);
        IReadOnlyList<Entry> batch = queue.Dequeue();
        bool last = queue.Count == 0;
        bool isDone = last && _ownerQueueIsDone;
        if (last)
        {
            _ownerQueue = null;
        }

        ReadOnlyMemory<byte> plaintext = _info.EncodeOwner(!last, isDone, batch);
        try
        {
            state.RecordOwner(plaintext);
            ReadOnlyMemory<byte> response = SealResponse(channel, plaintext);
            return new FdoOwnerResponse(FdoTo2MessageType.OwnerSvcInfo20, response);
        }
        finally
        {
            FdoSecretBuffer.ClearOwned(plaintext);
        }
    }

    private FdoOwnerResponse? TrySealError(ushort code, byte previousMessageId)
    {
        try
        {
            ReadOnlyMemory<byte> error = new FdoErrorMessageCodec().Encode(
                code, previousMessageId, FdoErrorCodes.NewCorrelationId());
            ReadOnlyMemory<byte> sealedError = Require(_channel).Seal(error);
            if (sealedError.Length > _deviceMessageLimit)
            {
                return null;
            }

            SentErrorCode = code;
            return new FdoOwnerResponse(FdoTo2MessageType.Error, sealedError);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private FdoOwnerResponse AcceptDeviceError(ushort protocolVersion, ReadOnlyMemory<byte> encodedBody)
    {
        // Only a Device Error sealed on the live channel and naming the last
        // Owner response is accepted. Anything else ends the run silently.
        if (protocolVersion != 200 ||
            _phase is not (Phase.Inventory or Phase.Enrollment or Phase.EnrollmentAfterCa
                or Phase.EnrollmentAfterAttributes or Phase.Done) ||
            encodedBody.IsEmpty || encodedBody.Length > _maxMessageSize)
        {
            throw new CborContentException("The FDO Error request is not acceptable in this phase.");
        }

        byte[] plaintext = Require(_channel).Open(encodedBody.ToArray());
        try
        {
            FdoErrorMessageCodec.ErrorMessage error = new FdoErrorMessageCodec(_maxMessageSize).Decode(plaintext);
            if (error.PreviousMessageId != (byte)_pendingResponseType)
            {
                throw new CborContentException("The FDO Error does not name the last Owner response.");
            }

            ReceivedErrorCode = error.ErrorCode;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        return new FdoOwnerResponse(FdoTo2MessageType.Error, ReadOnlyMemory<byte>.Empty);
    }

    private FdoTo2MessageType ExpectedRequest() => _phase switch
    {
        Phase.Probe => FdoTo2MessageType.HelloDeviceProbe,
        Phase.DeviceProof => FdoTo2MessageType.ProveDevice20,
        Phase.Entries => FdoTo2MessageType.GetOVNextEntry20,
        Phase.Ready => FdoTo2MessageType.DeviceServiceInfoRdy20,
        Phase.Inventory or Phase.Enrollment or Phase.EnrollmentAfterCa or Phase.EnrollmentAfterAttributes =>
            FdoTo2MessageType.DeviceSvcInfo20,
        Phase.Done => FdoTo2MessageType.Done20,
        _ => throw new InvalidOperationException("The Owner session cannot accept another request."),
    };

    private bool IsExpectedRequest(FdoTo2MessageType messageType) =>
        _phase == Phase.Done
            ? messageType is FdoTo2MessageType.DeviceSvcInfo20 or FdoTo2MessageType.Done20
            : messageType == ExpectedRequest();

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_phase == Phase.Disposed, this);
        if (_phase == Phase.Failed)
        {
            throw new InvalidOperationException("The Owner session has failed.");
        }
    }

    private void Fail()
    {
        _channel?.Dispose();
        _channel = null;
        _deviceAssembly.Clear();
        _ownerQueue = null;
        if (_phase != Phase.Disposed)
        {
            _phase = Phase.Failed;
        }
    }

    private static bool IsDirectRsaExchangePair(FdoKeyExchangeSuite first, FdoKeyExchangeSuite second) =>
        (first, second) is
            (FdoKeyExchangeSuite.DhkexId14, FdoKeyExchangeSuite.Asymkex2048) or
            (FdoKeyExchangeSuite.Asymkex2048, FdoKeyExchangeSuite.DhkexId14) or
            (FdoKeyExchangeSuite.DhkexId15, FdoKeyExchangeSuite.Asymkex3072) or
            (FdoKeyExchangeSuite.Asymkex3072, FdoKeyExchangeSuite.DhkexId15);

    private static long[] SnapshotCipherOffers(FdoOwnerSessionOptions options)
    {
        IReadOnlyList<FdoPairedCipherSuite>? additional = options.AdditionalCipherSuites;
        int count = additional?.Count ?? 0;
        if (count > 9)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "At most nine additional TO2 cipher suites can be offered.");
        }

        var offers = new long[count + 1];
        for (int i = 0; i < offers.Length; i++)
        {
            FdoCoseAeadAlgorithm suite = FdoPairedProtocol.MapCipherSuite(i == 0 ? options.CipherSuite : additional![i - 1]);
            if (!FdoTo2CipherSuites.IsSupported(suite))
            {
                throw new PlatformNotSupportedException($"The configured TO2 cipher suite {suite} is not available.");
            }

            if (offers.AsSpan(0, i).Contains((long)suite))
            {
                throw new ArgumentException("TO2 cipher offers cannot contain duplicates.", nameof(options));
            }

            offers[i] = (long)suite;
        }

        return offers;
    }

    private FdoTo2OwnerProofCodec.DelegateSigner NewDelegateSigner() =>
        new(Require(_delegateSigningKey), Require(_delegateChain), Require(_delegateTime).GetUtcNow(),
            _delegateOfflineRevocation);

    private static byte[] CopyBounded(ReadOnlyMemory<byte> value)
    {
        if (value.IsEmpty || value.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Voucher and trust material must fit in an FDO message.");
        }

        return value.ToArray();
    }

    private static T Require<T>(T? value) where T : class =>
        value ?? throw new InvalidOperationException("The Owner session is missing required state.");

    private enum Phase
    {
        Probe = 0,
        DeviceProof = 1,
        Entries = 2,
        Ready = 3,
        Inventory = 4,
        Enrollment = 5,
        EnrollmentAfterCa = 6,
        EnrollmentAfterAttributes = 7,
        Done = 8,
        Complete = 9,
        Failed = 10,
        Disposed = 11,
    }
}
