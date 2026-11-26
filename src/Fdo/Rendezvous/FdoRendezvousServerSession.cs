// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Serialization;
using Fdo.Transport;

namespace Fdo.Rendezvous;

/// <summary>Processes one paired TO0 or single-blob TO1 server exchange.</summary>
/// <remarks>
/// The host binds requests to this session and confirms each response handoff.
/// A failed or uncertain handoff ends the session. Registration storage and
/// replacement policy remain host-owned; an uncertain store callback requires
/// reconciliation. The server cannot verify the Device's voucher HMAC.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoRendezvousServerSession : IDisposable
{
    private readonly FdoRendezvousCodec _codec = new();
    private readonly FdoPinnedDeviceTrustPolicy _trustPolicy;
    private readonly IFdoRendezvousRegistrationStore? _store;
    private readonly IFdoAtomicRendezvousRegistrationStore? _atomicStore;
    private readonly IFdoRendezvousRegistrationAdmission? _admission;
    private readonly FdoDelegateOfflineRevocationPolicy? _delegateOfflineRevocation;
    private readonly TimeProvider _clock;
    private readonly uint _maxWaitSeconds;
    private readonly int _maxVoucherEntries;
    private readonly ushort _maxMessageSize;
    private readonly bool _allowMultipleRedirects;
    private FdoRendezvousRegistrationRecord[]? _lookupRecords;
    private int _nextBlobIndex;
    private ReadOnlyMemory<byte> _lastRvMore;
    private ReadOnlyMemory<byte> _lastRedirectPage;
    private bool _pageRepeated;
    private ReadOnlyMemory<byte> _nonce;
    private FdoRendezvousRegistration? _lookup;
    private Guid? _lookupRevision;
    private bool _delegated;
    private FdoRendezvousMessageType _pendingResponse;
    private Phase _phase;
    private int _busy;
    private bool _awaitingHandoff;

    /// <summary>Creates a single-use server session for the selected protocol.</summary>
    /// <param name="options">The configuration for this operation.</param>
    /// <param name="protocol">The selected FDO subprotocol.</param>
    public FdoRendezvousServerSession(FdoRendezvousServerOptions options, FdoRendezvousProtocol protocol)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.TimeProvider);
        if (!options.UseProvisionalPairedProfile)
        {
            throw new InvalidOperationException("The paired rendezvous wire choices require explicit opt-in.");
        }

        if (protocol is not (FdoRendezvousProtocol.OwnerRegistration or FdoRendezvousProtocol.DeviceLookup))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol));
        }

        if (options.MaxWaitSeconds == 0 || options.MaxMessageSize == 0 ||
            options.MaxVoucherEntries is < 1 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Rendezvous limits must be nonzero and within their wire bounds.");
        }

        if ((options.RegistrationStore is null) == (options.AtomicRegistrationStore is null) ||
            (options.AtomicRegistrationStore is null &&
             (options.RegistrationAdmission is not null || options.DelegateOfflineRevocation is not null)) ||
            (options.AtomicRegistrationStore is not null && protocol == FdoRendezvousProtocol.OwnerRegistration &&
             options.RegistrationAdmission is null))
        {
            throw new ArgumentException("Select exactly one store, and supply host admission for atomic TO0.", nameof(options));
        }

        _trustPolicy = new FdoPinnedDeviceTrustPolicy(
            options.TrustedManufacturerKey.ToArray(),
            options.DeviceTrustAnchor.ToArray(), options.DeviceRevocationMode);
        _store = options.RegistrationStore;
        _atomicStore = options.AtomicRegistrationStore;
        if (options.AllowMultipleDelegatedRedirects && _atomicStore is null)
        {
            throw new ArgumentException("Multiple delegated redirects require the atomic store.", nameof(options));
        }

        _allowMultipleRedirects = options.AllowMultipleDelegatedRedirects;
        _admission = options.RegistrationAdmission;
        _delegateOfflineRevocation = options.DelegateOfflineRevocation;
        _clock = options.TimeProvider;
        Protocol = protocol;
        _maxWaitSeconds = options.MaxWaitSeconds;
        _maxVoucherEntries = options.MaxVoucherEntries;
        _maxMessageSize = options.MaxMessageSize;
        RunId = Guid.NewGuid();
    }

    /// <summary>The local identifier for this server run.</summary>
    public Guid RunId { get; }

    /// <summary>The rendezvous protocol accepted by this session.</summary>
    public FdoRendezvousProtocol Protocol { get; }

    /// <summary>Whether the registration store callback started.</summary>
    public bool RegistrationWriteStarted { get; private set; }

    /// <summary>The registration whose store callback returned successfully.</summary>
    public FdoRendezvousRegistration? StoredRegistration { get; private set; }

    /// <summary>The exact attempted atomic write, for host reconciliation if its outcome is uncertain.</summary>
    public FdoRendezvousRegistrationMutation? AttemptedMutation { get; private set; }

    /// <summary>Whether the final response was handed off by the host.</summary>
    public bool FinalResponseHandoffConfirmed { get; private set; }

    internal bool CanRepeatLastRedirectPage =>
        _phase == Phase.Pages && !_lastRvMore.IsEmpty && !_pageRepeated;

    /// <summary>Processes one request. A processing failure ends the session.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    public ValueTask<FdoRendezvousResponse> ProcessAsync(
        ushort protocolVersion,
        FdoRendezvousMessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken = default) =>
        ProcessAsync(protocolVersion, messageType, encodedBody, null, cancellationToken);

    /// <summary>Processes a request with the host's observed submitter address.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="observedSource">The source address observed by the receiving host.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// Delegated TO0 requires the observed address of this OwnerSign request,
    /// resolved through the host's trusted proxy policy if applicable. An
    /// address from Hello, a forwarded header alone, or the signed TO2
    /// destination is not the observed submitter address.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Confirm the previous response handoff before another request. The Rendezvous Server session is already
    /// processing a request.
    /// </exception>
    /// <exception cref="CborContentException">The rendezvous request version or message type is unexpected.</exception>
    public async ValueTask<FdoRendezvousResponse> ProcessAsync(
        ushort protocolVersion, FdoRendezvousMessageType messageType, ReadOnlyMemory<byte> encodedBody,
        IPAddress? observedSource, CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Rendezvous Server session is already processing a request.");
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
            if (protocolVersion != 200 || messageType != ExpectedRequest())
            {
                throw new CborContentException("The rendezvous request version or message type is unexpected.");
            }

            RequireBodySize(encodedBody);
            byte[] body = encodedBody.ToArray();
            FdoRendezvousResponse response = _phase switch
            {
                Phase.Pages => await ProcessRvMoreAsync(body, cancellationToken).ConfigureAwait(false),
                Phase.Hello => await ProcessHelloAsync(body, cancellationToken).ConfigureAwait(false),
                _ when Protocol == FdoRendezvousProtocol.OwnerRegistration =>
                    await ProcessOwnerSignAsync(body, observedSource, cancellationToken).ConfigureAwait(false),
                _ => await ProcessDeviceProofAsync(body, cancellationToken).ConfigureAwait(false)
            };
            cancellationToken.ThrowIfCancellationRequested();
            RequireBodySize(response.EncodedBody);
            _pendingResponse = response.MessageType;
            _awaitingHandoff = true;
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

    /// <summary>Records a successful response handoff, not peer receipt.</summary>
    /// <exception cref="InvalidOperationException">
    /// No rendezvous response is awaiting handoff. The Rendezvous Server session is already processing a request.
    /// </exception>
    public void ConfirmResponseSent()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Rendezvous Server session is already processing a request.");
        }

        try
        {
            if (_phase is Phase.Failed or Phase.Disposed || !_awaitingHandoff)
            {
                throw new InvalidOperationException("No rendezvous response is awaiting handoff.");
            }

            _awaitingHandoff = false;
            if (_pendingResponse == FdoRendezvousMessageType.AcceptOwner ||
                (_pendingResponse == FdoRendezvousMessageType.Redirect &&
                 (_lookupRecords is null || _nextBlobIndex == _lookupRecords.Length)))
            {
                FinalResponseHandoffConfirmed = true;
            }
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>Ends the session without changing host storage.</summary>
    /// <exception cref="InvalidOperationException">
    /// The Rendezvous Server session is already processing a request.
    /// </exception>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The Rendezvous Server session is already processing a request.");
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

    private async ValueTask<FdoRendezvousResponse> ProcessHelloAsync(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        ushort request = Protocol == FdoRendezvousProtocol.OwnerRegistration
            ? FdoMessageTypes.TO0Hello : FdoMessageTypes.TO1HelloRV;
        FdoInitialMessageCodec.InitialMessage hello = _codec.ReadHello(request, body, _atomicStore is not null);
        _delegated = (hello.AdvertisedCapabilities & FdoKnownCapabilities.Delegation) != 0;
        if (Protocol == FdoRendezvousProtocol.DeviceLookup)
        {
            ReadOnlyMemory<byte> guid = hello.GuidOrNonce!.Value;
            if (_allowMultipleRedirects && _delegated)
            {
                (_lookupRecords, _lookupRevision) = await ReadLookupRecordsAsync(guid, cancellationToken)
                    .ConfigureAwait(false);
                ValidateLookupRecords(_lookupRecords, guid);
                _lookup = _lookupRecords[0].Registration;
            }
            else
            {
                (_lookup, _lookupRevision) = await FindCurrentAsync(guid, cancellationToken).ConfigureAwait(false);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        _nonce = RandomNumberGenerator.GetBytes(16);
        bool owner = Protocol == FdoRendezvousProtocol.OwnerRegistration;
        FdoRendezvousMessageType response = owner
            ? FdoRendezvousMessageType.OwnerHelloAck : FdoRendezvousMessageType.DeviceHelloAck;
        ushort responseType = owner ? FdoMessageTypes.TO0HelloAck : FdoMessageTypes.TO1HelloRVAck;
        ReadOnlyMemory<byte> encoded = _codec.EncodeInitial(responseType, _nonce, _delegated);
        _phase = Phase.Proof;
        return new FdoRendezvousResponse(200, response, encoded);
    }

    private async ValueTask<FdoRendezvousResponse> ProcessOwnerSignAsync(
        ReadOnlyMemory<byte> body,
        IPAddress? observedSource,
        CancellationToken cancellationToken)
    {
        FdoRendezvousCodec.OwnerSubmission submission = _codec.ReadOwnerSign(body, _maxVoucherEntries, _delegated);
        if (!CryptographicOperations.FixedTimeEquals(submission.Nonce.Span, _nonce.Span))
        {
            throw new CryptographicException("The TO0 registration nonce does not match this session.");
        }

        FdoRendezvousCodec.CheckedVoucher voucher = _codec.CheckVoucher(submission.Voucher, _trustPolicy);
        ReadOnlyMemory<byte> signingKey = voucher.OwnerKey;
        IPAddress? source = null;
        FdoVerifiedDelegateChain? verified = null;
        if (_delegated)
        {
            verified = _codec.AuthenticateDelegatedOwnerSign(submission, voucher, _clock.GetUtcNow(), _delegateOfflineRevocation);
            signingKey = verified.DelegateKey;
            source = observedSource is null
                ? throw new InvalidOperationException("Delegated TO0 requires the host-observed OwnerSign source address.")
                : new IPAddress(FdoRendezvousRegistrationRecord.NormalizeSource(observedSource));
        }
        else
        {
            _codec.VerifyRedirect(
                submission.SignedRedirect, voucher.OwnerKey, submission.To0Data, voucher.HashAlgorithm);
        }
        uint lifetime = Math.Min(submission.WaitSeconds, _maxWaitSeconds);
        RequireBodySize(_codec.EncodeAcceptOwner(lifetime));
        RequireBodySize(_codec.EncodeRedirect(submission.SignedRedirect));
        DateTimeOffset expiresAt = _clock.GetUtcNow().AddSeconds(lifetime);
        cancellationToken.ThrowIfCancellationRequested();
        if (verified is not null && (verified.Permissions & FdoDelegatePermissions.Redirect) == 0)
        {
            ReadOnlyMemory<byte> error = new FdoErrorMessageCodec().Encode(
                FdoErrorCodes.DelegateNotPermitted, (byte)FdoRendezvousMessageType.OwnerSign, FdoErrorCodes.NewCorrelationId());
            RequireBodySize(error);
            _phase = Phase.Complete;
            return new FdoRendezvousResponse(200, FdoRendezvousMessageType.Error, error);
        }

        var registration = new FdoRendezvousRegistration(
            Guid.NewGuid(), voucher.Guid, voucher.ManufacturerKey, voucher.OwnerKey,
            voucher.CertificateChain, submission.SignedRedirect, expiresAt);
        cancellationToken.ThrowIfCancellationRequested();
        if (_atomicStore is null)
        {
            RegistrationWriteStarted = true;
            await _store!.StoreAsync(registration, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            Guid deviceId = new(voucher.Guid.Span, bigEndian: true);
            FdoRendezvousRegistrationSnapshot current = await ReadSnapshotAsync(deviceId, cancellationToken)
                .ConfigureAwait(false);
            var evidence = new FdoRendezvousRegistrationEvidence(registration, signingKey, source, current);
            FdoRendezvousRegistrationGrant grant = await _admission!.AuthorizeAsync(evidence, cancellationToken)
                .ConfigureAwait(false) ?? throw new InvalidOperationException("The host did not admit the TO0 registration.");
            var record = new FdoRendezvousRegistrationRecord(registration, grant.AuthenticatedIdentity, source);
            var mutation = new FdoRendezvousRegistrationMutation(record, current.Revision, grant.AuthorizedReplacementOf);
            cancellationToken.ThrowIfCancellationRequested();
            AttemptedMutation = mutation;
            RegistrationWriteStarted = true;
            FdoRendezvousMutationResult written = await _atomicStore.TryWriteAsync(mutation, cancellationToken)
                .ConfigureAwait(false);
            if (written != FdoRendezvousMutationResult.Applied)
            {
                throw new InvalidOperationException($"The atomic TO0 registration was not applied: {written}.");
            }
        }

        StoredRegistration = registration;
        cancellationToken.ThrowIfCancellationRequested();

        double remaining = Math.Floor((expiresAt - _clock.GetUtcNow()).TotalSeconds);
        if (remaining < 1)
        {
            throw new InvalidOperationException("The registration has less than one whole second remaining after storage.");
        }

        uint accepted = (uint)Math.Min(lifetime, remaining);
        _phase = Phase.Complete;
        return new FdoRendezvousResponse(
            200, FdoRendezvousMessageType.AcceptOwner, _codec.EncodeAcceptOwner(accepted));
    }

    private async ValueTask<FdoRendezvousResponse> ProcessDeviceProofAsync(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        FdoRendezvousRegistration initial = _lookup
            ?? throw new InvalidOperationException("The Device lookup has no registration.");
        ReadOnlyMemory<byte> guid = initial.DeviceGuid;
        FdoRendezvousRegistration current;
        if (_lookupRecords is not null)
        {
            await RecheckLookupAsync(guid, cancellationToken).ConfigureAwait(false);
            current = initial;
        }
        else
        {
            Guid? revision;
            (current, revision) = await FindCurrentAsync(guid, cancellationToken).ConfigureAwait(false);
            if (revision != _lookupRevision || !SameRegistration(initial, current))
            {
                throw new InvalidOperationException("The rendezvous registration changed during the Device lookup.");
            }
        }

        IReadOnlyList<ReadOnlyMemory<byte>> certificates =
            new FdoX5ChainCodec().Decode(current.EncodedDeviceCertificateChain);
        using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(certificates[0]);
        FdoDerEncoding.RequireSigningKeyUsage(leaf);
        using ECDsa deviceKey = leaf.GetECDsaPublicKey()
            ?? throw new CryptographicException("The Device certificate must contain an ECDSA public key.");
        _codec.VerifyDeviceProof(body, guid, _nonce, deviceKey);
        cancellationToken.ThrowIfCancellationRequested();
        if (_clock.GetUtcNow() >= current.ExpiresAt)
        {
            throw new InvalidOperationException("The rendezvous registration expired during the Device lookup.");
        }

        if (_lookupRecords is { Length: > 1 })
        {
            RequireLookupLive();
            return NextRedirectPage();
        }

        ReadOnlyMemory<byte> redirect = _codec.EncodeRedirect(current.SignedRedirect);
        _phase = Phase.Complete;
        return new FdoRendezvousResponse(200, FdoRendezvousMessageType.Redirect, redirect);
    }

    private async ValueTask<(FdoRendezvousRegistrationRecord[] Records, Guid? Revision)> ReadLookupRecordsAsync(
        ReadOnlyMemory<byte> guid, CancellationToken cancellationToken)
    {
        var snapshot = await ReadSnapshotAsync(new Guid(guid.Span, bigEndian: true), cancellationToken)
            .ConfigureAwait(false);
        var records = new List<FdoRendezvousRegistrationRecord>();
        DateTimeOffset now = _clock.GetUtcNow();
        foreach (FdoRendezvousRegistrationRecord record in snapshot.Records)
        {
            if (record.Registration.ExpiresAt <= now)
            {
                continue;
            }

            if (records.Count == FdoRendezvousCodec.MaxRedirectBlobs)
            {
                throw new NotSupportedException("The delegated TO1 snapshot exceeds the paired blob limit.");
            }

            records.Add(record);
        }

        if (records.Count == 0)
        {
            throw new InvalidOperationException("No eligible rendezvous registration exists for the Device.");
        }

        records.Sort(static (left, right) => left.Registration.RegistrationId.CompareTo(right.Registration.RegistrationId));
        return (records.ToArray(), snapshot.Revision);
    }

    private void ValidateLookupRecords(FdoRendezvousRegistrationRecord[] records, ReadOnlyMemory<byte> guid)
    {
        ReadOnlyMemory<byte> chain = records[0].Registration.EncodedDeviceCertificateChain;
        foreach (FdoRendezvousRegistrationRecord record in records)
        {
            if (!record.Registration.EncodedDeviceCertificateChain.Span.SequenceEqual(chain.Span))
            {
                throw new InvalidOperationException("The TO1 snapshot contains inconsistent Device attestation chains.");
            }

            ValidateStoredRegistration(record.Registration, guid, record.DelegateSource is not null);
        }
    }

    private async ValueTask RecheckLookupAsync(ReadOnlyMemory<byte> guid, CancellationToken cancellationToken)
    {
        RequireLookupLive();
        (FdoRendezvousRegistrationRecord[] records, Guid? revision) =
            await ReadLookupRecordsAsync(guid, cancellationToken).ConfigureAwait(false);
        FdoRendezvousRegistrationRecord[] original = _lookupRecords!;
        if (revision != _lookupRevision || records.Length != original.Length)
        {
            throw new InvalidOperationException("The rendezvous snapshot changed during the Device lookup.");
        }

        for (int i = 0; i < original.Length; i++)
        {
            if (!SameRegistration(records[i].Registration, original[i].Registration) ||
                records[i].AuthenticatedIdentity != original[i].AuthenticatedIdentity ||
                !Equals(records[i].DelegateSource, original[i].DelegateSource))
            {
                throw new InvalidOperationException("The rendezvous snapshot changed during the Device lookup.");
            }
        }

        ValidateLookupRecords(original, guid);
        RequireLookupLive();
    }

    private void RequireLookupLive()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        foreach (FdoRendezvousRegistrationRecord record in _lookupRecords!)
        {
            if (record.Registration.ExpiresAt <= now)
            {
                throw new InvalidOperationException("The rendezvous snapshot expired during the Device lookup.");
            }
        }
    }

    private async ValueTask<FdoRendezvousResponse> ProcessRvMoreAsync(
        ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        int index = _codec.ReadRvMore(body);
        await RecheckLookupAsync(_lookup!.DeviceGuid, cancellationToken).ConfigureAwait(false);
        if (!_pageRepeated && !_lastRvMore.IsEmpty && body.Span.SequenceEqual(_lastRvMore.Span))
        {
            _pageRepeated = true;
            return new FdoRendezvousResponse(200, FdoRendezvousMessageType.Redirect, _lastRedirectPage);
        }

        if (index != _nextBlobIndex || index >= _lookupRecords!.Length)
        {
            throw new CborContentException("RVMore must request the next page or exactly repeat the last page request once.");
        }

        _lastRvMore = body;
        _pageRepeated = false;
        return NextRedirectPage();
    }

    private FdoRendezvousResponse NextRedirectPage()
    {
        FdoRendezvousRegistrationRecord[] records = _lookupRecords!;
        int index = _nextBlobIndex;
        int size = 4; // The array headers, total and index each fit in one byte.
        while (_nextBlobIndex < records.Length)
        {
            int blobSize = records[_nextBlobIndex].Registration.SignedRedirect.Length;
            if (size + blobSize > _maxMessageSize)
            {
                break;
            }

            size += blobSize;
            _nextBlobIndex++;
        }

        if (_nextBlobIndex == index)
        {
            throw new InvalidOperationException("The next rendezvous blob does not fit in a response.");
        }

        _lastRedirectPage = FdoRendezvousCodec.EncodeRedirectPage(records, index, _nextBlobIndex - index);
        _phase = _nextBlobIndex == records.Length && _lastRvMore.IsEmpty ? Phase.Complete : Phase.Pages;
        return new FdoRendezvousResponse(200, FdoRendezvousMessageType.Redirect, _lastRedirectPage);
    }

    private async ValueTask<(FdoRendezvousRegistration Registration, Guid? Revision)> FindCurrentAsync(
        ReadOnlyMemory<byte> guid,
        CancellationToken cancellationToken)
    {
        if (_atomicStore is null)
        {
            FdoRendezvousRegistration record = await _store!.FindAsync(guid.ToArray(), cancellationToken)
                .ConfigureAwait(false) ?? throw new InvalidOperationException("No rendezvous registration exists for the Device.");
            cancellationToken.ThrowIfCancellationRequested();
            ValidateStoredRegistration(record, guid);
            return (record, null);
        }

        Guid deviceId = new(guid.Span, bigEndian: true);
        FdoRendezvousRegistrationSnapshot snapshot = await ReadSnapshotAsync(deviceId, cancellationToken)
            .ConfigureAwait(false);
        FdoRendezvousRegistrationRecord? selected = null;
        DateTimeOffset now = _clock.GetUtcNow();
        foreach (FdoRendezvousRegistrationRecord record in snapshot.Records)
        {
            if (record.Registration.ExpiresAt <= now || (!_delegated && record.DelegateSource is not null))
            {
                continue;
            }

            if (selected is not null)
            {
                throw new NotSupportedException("The paired TO1 role cannot return multiple eligible Rendezvous blobs.");
            }

            selected = record;
        }

        if (selected is null)
        {
            throw new InvalidOperationException("No eligible rendezvous registration exists for the Device.");
        }

        ValidateStoredRegistration(selected.Registration, guid, selected.DelegateSource is not null);
        return (selected.Registration, snapshot.Revision);
    }

    private async ValueTask<FdoRendezvousRegistrationSnapshot> ReadSnapshotAsync(
        Guid deviceId, CancellationToken cancellationToken)
    {
        FdoRendezvousRegistrationSnapshot snapshot = await _atomicStore!.ReadAsync(deviceId, cancellationToken)
            .ConfigureAwait(false) ?? throw new InvalidOperationException("The atomic Rendezvous store returned no snapshot.");
        cancellationToken.ThrowIfCancellationRequested();
        foreach (FdoRendezvousRegistrationRecord record in snapshot.Records)
        {
            if (record.DeviceId != deviceId)
            {
                throw new InvalidOperationException("The atomic Rendezvous store returned a record for another Device.");
            }
        }

        return snapshot;
    }

    private void ValidateStoredRegistration(
        FdoRendezvousRegistration registration, ReadOnlyMemory<byte> guid, bool delegated = false)
    {
        if (!CryptographicOperations.FixedTimeEquals(registration.DeviceGuid.Span, guid.Span) ||
            _clock.GetUtcNow() >= registration.ExpiresAt)
        {
            throw new InvalidOperationException("The rendezvous registration is expired or belongs to another Device.");
        }

        IReadOnlyList<ReadOnlyMemory<byte>> certificates =
            new FdoX5ChainCodec().Decode(registration.EncodedDeviceCertificateChain);
        _trustPolicy.Validate(new FdoOwnerDeviceTrustEvidence(
            registration.DeviceGuid, registration.EncodedManufacturerKey, certificates));
        using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(certificates[0]);
        FdoDerEncoding.RequireSigningKeyUsage(leaf);
        if (delegated)
        {
            _codec.VerifyDelegatedRedirect(registration.SignedRedirect, registration.EncodedOwnerKey, _clock.GetUtcNow(),
                offlineRevocation: _delegateOfflineRevocation);
        }
        else
        {
            _codec.VerifyRedirect(registration.SignedRedirect, registration.EncodedOwnerKey);
        }
        RequireBodySize(_codec.EncodeRedirect(registration.SignedRedirect));
    }

    private FdoRendezvousMessageType ExpectedRequest() => (Protocol, _phase) switch
    {
        (FdoRendezvousProtocol.OwnerRegistration, Phase.Hello) => FdoRendezvousMessageType.OwnerHello,
        (FdoRendezvousProtocol.OwnerRegistration, Phase.Proof) => FdoRendezvousMessageType.OwnerSign,
        (FdoRendezvousProtocol.DeviceLookup, Phase.Hello) => FdoRendezvousMessageType.DeviceHello,
        (FdoRendezvousProtocol.DeviceLookup, Phase.Proof) => FdoRendezvousMessageType.ProveToRendezvous,
        (FdoRendezvousProtocol.DeviceLookup, Phase.Pages) => FdoRendezvousMessageType.ProveToRendezvous,
        _ => throw new InvalidOperationException("The Rendezvous Server session has ended."),
    };

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_phase == Phase.Disposed, this);
        if (_phase is Phase.Complete or Phase.Failed)
        {
            throw new InvalidOperationException("The Rendezvous Server session has ended.");
        }
    }

    private void RequireBodySize(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty || body.Length > _maxMessageSize)
        {
            throw new CborContentException("The rendezvous message exceeds the server limit or is empty.");
        }
    }

    private static bool SameRegistration(FdoRendezvousRegistration first, FdoRendezvousRegistration second) =>
        first.RegistrationId == second.RegistrationId && first.ExpiresAt == second.ExpiresAt &&
        first.DeviceGuid.Span.SequenceEqual(second.DeviceGuid.Span) &&
        first.EncodedManufacturerKey.Span.SequenceEqual(second.EncodedManufacturerKey.Span) &&
        first.EncodedOwnerKey.Span.SequenceEqual(second.EncodedOwnerKey.Span) &&
        first.EncodedDeviceCertificateChain.Span.SequenceEqual(second.EncodedDeviceCertificateChain.Span) &&
        first.SignedRedirect.Span.SequenceEqual(second.SignedRedirect.Span);

    private enum Phase
    {
        Hello = 0,
        Proof = 1,
        Pages = 2,
        Complete = 3,
        Failed = 4,
        Disposed = 5,
    }
}
