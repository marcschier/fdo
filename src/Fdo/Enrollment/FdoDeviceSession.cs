using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Rendezvous;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Fdo.Transport;
using Fdo.Transport.Http;

namespace Fdo.Enrollment;

/// <summary>
/// Runs one paired FDO 2.0 Device exchange over a host-supplied transport.
/// The issued certificate is installed only after the Device authenticates
/// DoneAck20.
/// </summary>
/// <remarks>
/// The supported profile uses explicit bypass or a paired TO1 result,
/// credential reuse or explicitly selected replacement, a devmod inventory
/// that may span several ServiceInfo rounds at complete-entry boundaries, and
/// provisional paired wire choices. With explicit opt-in, a Delegate of the
/// voucher's final Owner may sign the Owner proof and the reuse disposition,
/// and a separately accepted Delegate may sign a single TO1 redirect.
/// FDO disable is not implemented. The session does not
/// implement retries, recovery, or general FDO interoperability.
/// A failed or ambiguous exchange cannot be resumed.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoDeviceSession : IDisposable
{
    private const int Ready = 0;
    private const int Running = 1;
    private const int Finished = 2;
    private const int Disposed = 3;
    private readonly DeviceSettings _device;
    private readonly IFdoDeviceEnrollmentHandler _handler;
    private readonly IFdoDeviceReplacementHandler? _replacementHandler;
    private readonly byte[] _hmacSecret;
    private int _state;
    private ushort _authenticatedResponseType;

    /// <summary>
    /// Creates a single-use Device session and snapshots its credentials and
    /// request when supplied. The attestation key, opaque HMAC handle, and
    /// handlers remain caller-owned.
    /// </summary>
    public FdoDeviceSession(FdoDeviceSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.AttestationKey);
        ArgumentNullException.ThrowIfNull(options.Metadata);
        ArgumentNullException.ThrowIfNull(options.Metadata.Os);
        ArgumentNullException.ThrowIfNull(options.Metadata.Architecture);
        ArgumentNullException.ThrowIfNull(options.Metadata.Version);
        ArgumentNullException.ThrowIfNull(options.Metadata.Device);
        ArgumentNullException.ThrowIfNull(options.Metadata.Separator);
        ArgumentNullException.ThrowIfNull(options.Metadata.BinaryFormats);
        ArgumentNullException.ThrowIfNull(options.EnrollmentHandler);
        if (options.AllowRendezvousBypass == (options.RendezvousResult is not null) ||
            (!options.AllowCredentialReuse && options.ReplacementHandler is null) ||
            !options.UseProvisionalPairedProfile)
        {
            throw new InvalidOperationException(
                "The paired Device requires exactly one rendezvous route, an allowed disposition, and paired-profile opt-in.");
        }

        if (options.MaxMessageSize == 0 || options.MaxOwnerServiceInfoSize == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The paired profile requires nonzero message limits.");
        }

        FdoKeyExchangeSuite exchange = FdoPairedProtocol.MapKeyExchangeSuite(options.KeyExchangeSuite);
        FdoPairedProtocol.RequireExchangeOptIn(
            exchange, options.UseProvisionalPairedDh, options.UseProvisionalPairedAsymkex);
        if (options.UseDelegatedOwnerProof)
        {
            if (options.DelegateAcceptance is null || options.DelegateTimeProvider is null)
            {
                throw new ArgumentException(
                    "A delegated Owner proof requires host acceptance and a time provider.", nameof(options));
            }

            FdoTo2DelegatePolicy.RequireExchange(exchange);
        }
        else if (options.DelegateAcceptance is not null || options.DelegateTimeProvider is not null ||
                 options.DelegateOfflineRevocation is not null)
        {
            throw new ArgumentException(
                "Delegate acceptance and time can only be configured with a delegated Owner proof.", nameof(options));
        }

        if (options.AcceptDelegatedRendezvousRedirect)
        {
            if (options.RendezvousResult is null || options.RedirectDelegateAcceptance is null ||
                options.RedirectDelegateTimeProvider is null)
            {
                throw new ArgumentException(
                    "A delegated rendezvous redirect requires a TO1 result, host acceptance and a time provider.",
                    nameof(options));
            }
        }
        else if (options.RedirectDelegateAcceptance is not null || options.RedirectDelegateTimeProvider is not null ||
                 options.RedirectDelegateOfflineRevocation is not null)
        {
            throw new ArgumentException(
                "Redirect Delegate acceptance and time can only be configured with a delegated rendezvous redirect.",
                nameof(options));
        }
        else if (options.RendezvousResult is FdoDeviceRendezvousResult result &&
            new FdoRendezvousCodec().HasUntrustedDelegateChain(result.SignedRedirect))
        {
            throw new NotSupportedException("A delegated rendezvous redirect requires explicit opt-in.");
        }

        byte[] provisionedOwnerKey;
        if (FdoKeyExchangeSuites.IsAsym(exchange))
        {
            if (options.EncodedAsymkexOwnerPublicKey.IsEmpty)
            {
                throw new ArgumentException("Paired ASYMKEX requires an independently provisioned Owner public key.", nameof(options));
            }

            using FdoPublicKeyCodec.DecodedKey owner = new FdoPublicKeyCodec().Decode(options.EncodedAsymkexOwnerPublicKey);
            FdoTo2OwnerProofCodec.RequireOwnerSuite(exchange, owner);
            provisionedOwnerKey = owner.Encoded.ToArray();
        }
        else
        {
            if (!options.EncodedAsymkexOwnerPublicKey.IsEmpty)
            {
                throw new ArgumentException("An ASYMKEX Owner key can only be configured for ASYMKEX.", nameof(options));
            }

            provisionedOwnerKey = Array.Empty<byte>();
        }
        FdoCoseAeadAlgorithm cipher = FdoPairedProtocol.MapCipherSuite(options.CipherSuite);
        FdoHashAlgorithm hmacAlgorithm = options.VoucherHmacAlgorithm switch
        {
            FdoDeviceHmacAlgorithm.HmacSha256 => FdoHashAlgorithm.HmacSha256,
            FdoDeviceHmacAlgorithm.HmacSha384 => FdoHashAlgorithm.HmacSha384,
            _ => throw new ArgumentOutOfRangeException(nameof(options), "The voucher HMAC algorithm is not supported."),
        };
        if (!FdoTo2CipherSuites.IsSupported(cipher))
        {
            throw new PlatformNotSupportedException("The selected TO2 cipher suite is not available.");
        }

        if (options.DeviceGuid.Length != 16 || options.CertificateSigningRequest.Length > ushort.MaxValue)
        {
            throw new ArgumentException("The paired Device credentials exceed their required bounds.", nameof(options));
        }

        if ((options.VoucherHmacSecretHandle is null) == options.VoucherHmacSecret.IsEmpty)
        {
            throw new ArgumentException(
                "Configure either a software-held voucher HMAC secret or an opaque handle, but not both.", nameof(options));
        }

        if (options.VoucherHmacSecretHandle is IFdoDeviceInitializeHmacSecret secretHandle)
        {
            FdoInitializationFields.ValidateHmacSecretHandle(secretHandle, options.VoucherHmacAlgorithm);
        }
        else
        {
            FdoDeviceHmacSecretPolicy.ValidateLength(hmacAlgorithm, options.VoucherHmacSecret.Length);
        }

        if ((options.CsrAttributesHandler is null) == options.CertificateSigningRequest.IsEmpty)
        {
            throw new ArgumentException(
                "Configure either a PKCS#10 request or a CSR attributes handler, but not both.", nameof(options));
        }

        if (options.ServerKeygenHandler is not null && options.RequestReenrollment)
        {
            throw new ArgumentException(
                "Server key generation is separate from simple re-enrollment.", nameof(options));
        }

        FdoHashValue manufacturerHash = FdoHashValue.Decode(options.EncodedManufacturerKeyHash);
        if (manufacturerHash.IsHmac)
        {
            throw new ArgumentException("The provisioned manufacturer-key hash must be a digest.", nameof(options));
        }

        byte[] guid = options.DeviceGuid.ToArray();
        byte[] request = options.CertificateSigningRequest.ToArray();
        if (options.CsrAttributesHandler is null)
        {
            if (options.ServerKeygenHandler is null)
            {
                FdoCsrSimpleEnrollment.ValidateRequest(request);
            }
            else
            {
                FdoCsrServerKeygen.ValidateRequest(request);
            }
        }
        ReadOnlyMemory<byte>? redirect = null;
        MultiAddressSelection? selectedRoute = null;
        if (options.RendezvousResult is { CandidateAddresses.Count: > 1 } multi)
        {
            if (options.RendezvousAddressIndex is not int index || (uint)index >= (uint)multi.CandidateAddresses.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(options), "Select one candidate index from the delegated redirect.");
            }

            multi.RequireGuid(guid);
            selectedRoute = new MultiAddressSelection(multi, index, multi.CandidateAddresses[index]);
        }
        else
        {
            if (options.RendezvousAddressIndex is not null)
            {
                throw new ArgumentException("An address index is only valid for a multiple-address redirect.", nameof(options));
            }

            redirect = options.RendezvousResult?.Claim(guid);
        }
        RunId = Guid.NewGuid();
        _hmacSecret = options.VoucherHmacSecret.ToArray();
        _device = new DeviceSettings(
            guid, manufacturerHash, options.VoucherHmacAlgorithm, _hmacSecret,
            options.VoucherHmacSecretHandle, options.AttestationKey,
            request, exchange, provisionedOwnerKey, cipher, options.AllowCredentialReuse, options.MaxMessageSize,
            options.MaxOwnerServiceInfoSize, options.RequestCaCertificates, options.RequestReenrollment,
            options.CsrAttributesHandler, options.ServerKeygenHandler, options.Metadata, redirect,
            options.UseDelegatedOwnerProof ? options.DelegateAcceptance : null,
            options.UseDelegatedOwnerProof ? options.DelegateTimeProvider : null,
            options.AcceptDelegatedRendezvousRedirect ? options.RedirectDelegateAcceptance : null,
            options.AcceptDelegatedRendezvousRedirect ? options.RedirectDelegateTimeProvider : null,
            options.DelegateOfflineRevocation, options.RedirectDelegateOfflineRevocation, selectedRoute);
        _handler = options.EnrollmentHandler;
        _replacementHandler = options.ReplacementHandler;
    }

    /// <summary>The local identifier for this Device run.</summary>
    public Guid RunId { get; }

    /// <summary>Whether the Device authenticated DoneAck20 and its challenge.</summary>
    public bool DoneAckAuthenticated { get; private set; }

    /// <summary>The authenticated replacement proposal, or null if none was accepted.</summary>
    public FdoDeviceReplacementProposal? ReplacementProposal { get; private set; }

    /// <summary>Whether the Device invoked the replacement secret reservation callback.</summary>
    public bool ReplacementSecretReservationStarted { get; private set; }

    /// <summary>Whether the replacement secret reservation callback returned successfully.</summary>
    public bool ReplacementSecretReserved { get; private set; }

    /// <summary>Whether the Device invoked the replacement staging callback.</summary>
    public bool ReplacementStagingStarted { get; private set; }

    /// <summary>The replacement whose staging callback returned successfully.</summary>
    public FdoDeviceReplacementCredential? StagedReplacement { get; private set; }

    /// <summary>Whether the Device began sending Done20; delivery may be uncertain.</summary>
    public bool DoneSendStarted { get; private set; }

    /// <summary>Whether the Device invoked the replacement activation callback.</summary>
    public bool ReplacementActivationStarted { get; private set; }

    /// <summary>The replacement whose activation callback returned successfully.</summary>
    public FdoDeviceReplacementCredential? ActivatedReplacement { get; private set; }

    /// <summary>Whether the Device invoked the installation callback.</summary>
    public bool InstallationStarted { get; private set; }

    /// <summary>
    /// The enrollment whose installation callback returned successfully, or
    /// null if no successful return was observed. A throwing callback can have
    /// an unknown durable outcome.
    /// </summary>
    public FdoDeviceEnrollment? InstalledEnrollment { get; private set; }

    /// <summary>
    /// The FDO Error code that the Device sent through an
    /// <see cref="IFdoDeviceErrorTransport"/> after a local failure, or null.
    /// The original failure is still thrown from <see cref="RunAsync"/>.
    /// </summary>
    public ushort? SentErrorCode { get; private set; }

    /// <summary>
    /// Runs the exchange once. A successful result is returned only after the
    /// Device authenticates DoneAck20 and the installation callback succeeds.
    /// The caller must not run or dispose the session concurrently.
    /// </summary>
    public async ValueTask<FdoDeviceEnrollment> RunAsync(
        IFdoDeviceTransport transport,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        int previous = Interlocked.CompareExchange(ref _state, Running, Ready);
        ObjectDisposedException.ThrowIf(previous == Disposed, this);
        if (previous != Ready)
        {
            throw new InvalidOperationException("The Device session has already been started.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            DeviceSettings settings = _device;
            if (settings.SelectedRoute is { } route)
            {
                if (transport is not IFdoHttpPeer peer ||
                    !FdoDelegatedRendezvousRoutes.MatchesOrigin(route.Address, peer.BaseAddress))
                {
                    throw new InvalidOperationException("The transport origin does not match the selected delegated route.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                settings = settings with { SignedRendezvousRedirect = route.Result.Claim(settings.Guid.Span) };
            }

            return await RunSnapshotAsync(settings, transport, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(_hmacSecret);
            Volatile.Write(ref _state, Finished);
        }
    }

    /// <summary>Clears the voucher HMAC secret after no run is active.</summary>
    public void Dispose()
    {
        while (true)
        {
            int current = Volatile.Read(ref _state);
            if (current == Running)
            {
                throw new InvalidOperationException("The Device session is already processing a run.");
            }

            if (current == Disposed)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _state, Disposed, current) == current)
            {
                CryptographicOperations.ZeroMemory(_hmacSecret);
                return;
            }
        }
    }

    private async Task<FdoDeviceEnrollment> RunSnapshotAsync(
        DeviceSettings device,
        IFdoDeviceTransport transport,
        CancellationToken cancellationToken)
    {
        var initial = new FdoTo2InitialCodec();
        var proofs = new FdoTo2OwnerProofCodec();
        var cbor = new FdoCborCodec();
        bool delegated = device.DelegateAcceptance is not null;
        byte capabilities = delegated
            ? (byte)(FdoKnownCapabilities.Fdo20 | FdoKnownCapabilities.Delegation)
            : (byte)FdoKnownCapabilities.Fdo20;
        ReadOnlyMemory<byte> probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { capabilities }, Array.Empty<string>(), device.Guid,
            device.MaxMessageSize, new long[] { (long)FdoHashAlgorithm.Sha256 },
            RandomNumberGenerator.GetBytes(16)));
        ReadOnlyMemory<byte> ack = await ExchangeAsync(
            transport, FdoMessageTypes.TO2HelloDeviceProbe, probe,
            FdoMessageTypes.TO2HelloDeviceAck20, ushort.MaxValue, device.MaxMessageSize, cancellationToken)
            .ConfigureAwait(false);
        FdoTo2InitialCodec.CheckedAcknowledgement checkedAck = initial.CheckAcknowledgement(probe, ack);
        if (checkedAck.Message.MaxOwnerMessageSize == 0)
        {
            throw new NotSupportedException("The paired profile requires an explicit Owner message limit.");
        }

        if (delegated && !HasDelegationCapability(checkedAck.Message.CapabilityFlags))
        {
            throw new NotSupportedException("The Owner did not acknowledge the delegation capability.");
        }


        using IFdoPairedKeyExchange deviceExchange =
            FdoPairedProtocol.CreateDeviceExchange(device.Exchange, device.ProvisionedAsymOwnerKey);
        byte[] ownerNonce = RandomNumberGenerator.GetBytes(16);
        ReadOnlyMemory<byte> deviceProof = new FdoTo2DeviceProofCodec().Sign(
            probe, ack, device.Exchange, device.Cipher,
            deviceExchange.ExportParameter(), ownerNonce, device.AttestationKey);
        ReadOnlyMemory<byte> ownerProof = await ExchangeAsync(
            transport, FdoMessageTypes.TO2ProveDevice20, deviceProof,
            FdoMessageTypes.TO2ProveOVHdr20, checkedAck.Message.MaxOwnerMessageSize,
            device.MaxMessageSize, cancellationToken).ConfigureAwait(false);
        DateTimeOffset? delegateTime = delegated ? device.DelegateTimeProvider!.GetUtcNow() : null;
        FdoHashAlgorithm hmacAlgorithm = FdoInitializationFields.HmacAlgorithm(device.HmacAlgorithm);
        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = device.HmacSecretHandle is { } handle
            ? await proofs.BeginDeviceVerificationAsync(
                ownerProof, ownerNonce, device.Exchange, device.Guid,
                device.ManufacturerKeyHash, hmacAlgorithm,
                (header, token) => ComputeVoucherHmacAsync(handle, device.HmacAlgorithm, header, token),
                cancellationToken, delegateTime, device.DelegateOfflineRevocation is not null).ConfigureAwait(false)
            : proofs.BeginDeviceVerification(
                ownerProof, ownerNonce, device.Exchange, device.Guid.Span,
                device.ManufacturerKeyHash, hmacAlgorithm, device.HmacSecret.Span, delegateTime,
                device.DelegateOfflineRevocation is not null);
        CryptographicOperations.ZeroMemory(_hmacSecret);
        for (int i = 0; i < pending.EntryCount; i++)
        {
            ReadOnlyMemory<byte> entryResponse = await ExchangeAsync(
                transport, FdoMessageTypes.TO2GetOVNextEntry20, FdoPairedProtocol.EncodeEntryRequest(i),
                FdoMessageTypes.TO2OVNextEntry20, checkedAck.Message.MaxOwnerMessageSize,
                device.MaxMessageSize, cancellationToken).ConfigureAwait(false);
            pending.AppendEntry(i, FdoPairedProtocol.DecodeEntryResponse(cbor, entryResponse, i));
        }

        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner = pending.CompleteDeviceChecks();
        if (verifiedOwner.Delegate is { } verifiedDelegate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DateTimeOffset now = device.DelegateTimeProvider!.GetUtcNow();
            verifiedDelegate.RequireValidityAt(now);
            verifiedDelegate.RequireOfflineStatus(device.DelegateOfflineRevocation, now);
        }
        if (FdoKeyExchangeSuites.IsAsym(device.Exchange))
        {
            FdoPairedProtocol.RequireProvisionedAsymOwner(device.ProvisionedAsymOwnerKey, verifiedOwner.OwnerKey);
        }

        if (device.SignedRendezvousRedirect is ReadOnlyMemory<byte> signedRedirect)
        {
            var rendezvous = new FdoRendezvousCodec();
            if (device.RedirectDelegateAcceptance is IFdoDeviceRedirectDelegateAcceptance redirectAcceptance &&
                rendezvous.HasUntrustedDelegateChain(signedRedirect))
            {
                (IReadOnlyList<FdoRendezvousAddress> addresses, FdoVerifiedDelegateChain redirectDelegate) =
                    rendezvous.VerifyDelegatedRedirect(
                        signedRedirect, verifiedOwner.OwnerKey, device.RedirectDelegateTimeProvider!.GetUtcNow(),
                        offlineRevocation: device.RedirectDelegateOfflineRevocation);
                int index = device.SelectedRoute?.Index ?? 0;
                if (device.SelectedRoute is { } route
                    ? (uint)index >= (uint)addresses.Count ||
                      !FdoDelegatedRendezvousRoutes.SameSignedAddress(route.Address, addresses[index])
                    : addresses.Count != 1)
                {
                    throw new CryptographicException("The selected delegated route does not match the verified redirect.");
                }

                await AcceptRedirectDelegateAsync(
                    redirectAcceptance, redirectDelegate, verifiedOwner.OwnerKey, addresses[index], cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                rendezvous.VerifyRedirect(signedRedirect, verifiedOwner.OwnerKey);
            }
        }

        if (verifiedOwner.MaxOwnerMessageSize == 0)
        {
            throw new NotSupportedException("The paired profile requires a signed Owner message limit.");
        }

        if (delegated)
        {
            await AcceptDelegateAsync(device.DelegateAcceptance!, verifiedOwner, cancellationToken)
                .ConfigureAwait(false);
        }

        int ownerLimit = Math.Min(checkedAck.Message.MaxOwnerMessageSize, verifiedOwner.MaxOwnerMessageSize);
        byte[] key = FdoPairedProtocol.DeriveSessionKey(deviceExchange, verifiedOwner.OwnerParameter, device.Cipher);
        byte[]? privateKey = null;
        try
        {
            ProtectedEnrollment result;
            using (IFdoTo2PairedChannel channel = FdoTo2PairedChannels.Create(FdoTo2PairedRole.Device, device.Cipher, key))
            {
                CryptographicOperations.ZeroMemory(key);
                try
                {
                    result = await RunProtectedAsync(
                        device, transport, verifiedOwner, checkedAck.Message.NonceTo2ProveDv,
                        channel, ownerLimit, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    await TrySendErrorAsync(transport, channel, ex, ownerLimit, cancellationToken)
                        .ConfigureAwait(false);
                    throw;
                }

                privateKey = result.PrivateKey;
            }

            cancellationToken.ThrowIfCancellationRequested();
            InstallationStarted = true;
            if (device.ServerKeygenHandler is IFdoDeviceServerKeygenHandler serverKeygenHandler)
            {
                await serverKeygenHandler.InstallAsync(
                    result.Enrollment,
                    privateKey ?? throw new InvalidOperationException("The generated private key is missing."),
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await _handler.InstallAsync(result.Enrollment, cancellationToken).ConfigureAwait(false);
            }

            InstalledEnrollment = result.Enrollment;
            return result.Enrollment;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    private static bool HasDelegationCapability(ReadOnlyMemory<byte> flags) =>
        !flags.IsEmpty && (flags.Span[0] & (byte)FdoKnownCapabilities.Delegation) != 0;

    private static async ValueTask AcceptDelegateAsync(
        IFdoDeviceDelegateAcceptance acceptance,
        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner,
        CancellationToken cancellationToken)
    {
        // An opted-in Device that negotiated delegation does not fall back to
        // an Owner-signed proof within the same run.
        FdoVerifiedDelegateChain chain = verifiedOwner.Delegate ??
            throw new NotSupportedException("The Owner negotiated delegation but sent no Delegate chain.");
        FdoDelegatePermissions permissions = chain.Permissions;
        var evidence = new FdoDelegateEvidence(
            chain.LeafCertificate, chain.DelegateKey, verifiedOwner.OwnerKey,
            (permissions & FdoDelegatePermissions.Redirect) != 0,
            (permissions & FdoDelegatePermissions.OnboardNewCredentials) != 0,
            (permissions & FdoDelegatePermissions.OnboardReuseCredentials) != 0);
        cancellationToken.ThrowIfCancellationRequested();
        if (!await acceptance.AcceptAsync(evidence, cancellationToken).ConfigureAwait(false))
        {
            throw new FdoDelegateNotAcceptedException();
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private static async ValueTask AcceptRedirectDelegateAsync(
        IFdoDeviceRedirectDelegateAcceptance acceptance,
        FdoVerifiedDelegateChain redirectDelegate,
        ReadOnlyMemory<byte> ownerKey,
        FdoRendezvousAddress address,
        CancellationToken cancellationToken)
    {
        var evidence = new FdoRedirectDelegateEvidence(
            redirectDelegate.LeafCertificate, redirectDelegate.DelegateKey, ownerKey, address);
        cancellationToken.ThrowIfCancellationRequested();
        if (!await acceptance.AcceptAsync(evidence, cancellationToken).ConfigureAwait(false))
        {
            throw new FdoRedirectDelegateNotAcceptedException();
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private static ValueTask<ReadOnlyMemory<byte>> ComputeVoucherHmacAsync(
        IFdoDeviceInitializeHmacSecret secret,
        FdoDeviceHmacAlgorithm expectedAlgorithm,
        ReadOnlyMemory<byte> header,
        CancellationToken cancellationToken)
    {
        FdoInitializationFields.ValidateHmacSecretHandle(secret, expectedAlgorithm);
        cancellationToken.ThrowIfCancellationRequested();
        return secret.ComputeAsync(header, cancellationToken);
    }

    private async Task<ProtectedEnrollment> RunProtectedAsync(
        DeviceSettings device,
        IFdoDeviceTransport transport,
        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner,
        ReadOnlyMemory<byte> doneNonce,
        IFdoTo2PairedChannel channel,
        int ownerLimit,
        CancellationToken cancellationToken)
    {
        var info = new FdoTo2ServiceInfoCodec();
        var serviceInfo = new FdoServiceInfoCodec();
        var completion = new FdoTo2CompletionCodec();
        byte[] setupNonce = RandomNumberGenerator.GetBytes(16);
        ReadOnlyMemory<byte> ready = info.EncodeDeviceReady(device.MaxOwnerServiceInfoSize, setupNonce);
        byte[] receivedSetup = await ExchangeProtectedAsync(
            transport, FdoMessageTypes.TO2DeviceServiceInfoRdy20, ready,
            FdoMessageTypes.TO2SetupDevice20, channel, ownerLimit, device.MaxMessageSize, cancellationToken)
            .ConfigureAwait(false);
        ushort? maxDeviceInfo;
        FdoTo2SetupDeviceCodec.Replacement? replacement = null;
        try
        {
            var setup = new FdoTo2SetupDeviceCodec();
            ulong disposition = setup.ReadUntrustedDisposition(receivedSetup);
            if (disposition == 1)
            {
                if (_replacementHandler is null)
                {
                    throw new InvalidOperationException("Credential replacement was not explicitly enabled.");
                }
                replacement = setup.VerifyReplacement(verifiedOwner, receivedSetup, setupNonce);
                verifiedOwner.Delegate?.Require(FdoDelegatePermissions.OnboardNewCredentials);
                maxDeviceInfo = replacement.MaxDeviceServiceInfoSize;
            }
            else if (!device.AllowCredentialReuse)
            {
                // Authenticate the reuse disposition before denying it with Error 102.
                setup.Verify(verifiedOwner, receivedSetup, true);
                verifiedOwner.Delegate?.Require(FdoDelegatePermissions.OnboardReuseCredentials);
                throw new FdoCredentialReuseDeniedException();
            }
            else
            {
                maxDeviceInfo = setup.Verify(verifiedOwner, receivedSetup, true);
                verifiedOwner.Delegate?.Require(FdoDelegatePermissions.OnboardReuseCredentials);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(receivedSetup);
        }

        int deviceLimit = maxDeviceInfo ?? 1300;
        var state = new FdoTo2ServiceInfoState(doneNonce, deviceLimit, device.MaxOwnerServiceInfoSize);
        using var module = new FdoCsrDeviceModule(
            device.CertificateSigningRequest, deviceLimit, device.MaxOwnerServiceInfoSize,
            device.RequestCaCertificates, device.RequestReenrollment, device.CsrAttributesHandler is not null,
            device.ServerKeygenHandler is not null);
        var processor = new FdoDeviceServiceInfoProcessor([module], FdoServiceInfoBatches.MaxAssembledBytes);
        var exchange = new ServiceInfoExchange(
            this, transport, channel, state, info, deviceLimit, ownerLimit, device.MaxMessageSize);

        FdoTo2ServiceInfoCodec.OwnerServiceInfo activation = await exchange.RunAsync(
            FdoPairedProtocol.EncodeInventory(device.Metadata), cancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> produced = await processor.ProcessAsync(
            serviceInfo.Encode(activation.ServiceInfo), cancellationToken).ConfigureAwait(false);
        int requests = 1 + (device.RequestCaCertificates ? 1 : 0) +
            (device.CsrAttributesHandler is not null ? 1 : 0);
        for (int i = 0; i < requests; i++)
        {
            FdoTo2ServiceInfoCodec.OwnerServiceInfo response = await exchange.RunAsync(
                serviceInfo.Decode(produced), cancellationToken).ConfigureAwait(false);
            module.MarkRequestSent();

            if (device.ServerKeygenHandler is not null && i == requests - 1)
            {
                try
                {
                    if (response.ServiceInfo.Count != 1)
                    {
                        throw new CborContentException("A server-key response must contain one item.");
                    }

                    FdoServiceInfoCodec.Entry entry = response.ServiceInfo[0];
                    string messageName = entry.Key switch
                    {
                        "fdo.csr:serverkeygen-res" => "serverkeygen-res",
                        "fdo.csr:error" => "error",
                        _ => throw new CborContentException("The Owner sent an unexpected server-key response."),
                    };
                    if (messageName == "serverkeygen-res" && !response.IsDone)
                    {
                        throw new CborContentException("A server-key response must complete ServiceInfo.");
                    }

                    if ((await module.ReceiveAsync(messageName, entry.EncodedValue, cancellationToken)
                        .ConfigureAwait(false)).Count != 0)
                    {
                        throw new CborContentException("The server-key response produced unexpected ServiceInfo.");
                    }

                    produced = serviceInfo.Encode([]);
                }
                finally
                {
                    foreach (FdoServiceInfoCodec.Entry entry in response.ServiceInfo)
                    {
                        if (entry.Key == "fdo.csr:serverkeygen-res")
                        {
                            FdoSecretBuffer.ClearOwned(entry.EncodedValue);
                        }
                    }
                }
            }
            else
            {
                produced = await processor.ProcessAsync(
                    serviceInfo.Encode(response.ServiceInfo), cancellationToken).ConfigureAwait(false);
            }
            if (device.CsrAttributesHandler is IFdoDeviceCsrAttributesHandler attributesHandler &&
                i == (device.RequestCaCertificates ? 1 : 0))
            {
                if (response.IsDone || response.IsMoreServiceInfo || serviceInfo.Decode(produced).Count != 0)
                {
                    throw new CborContentException("The CSR attributes response cannot finish or fragment ServiceInfo.");
                }

                var attributesRequest = new FdoDeviceCsrAttributesRequest(
                    RunId, device.Guid, module.CopyPendingCsrAttributes(),
                    device.RequestCaCertificates ? module.CopyPendingCaCertificates() : null,
                    device.RequestReenrollment, device.ServerKeygenHandler is not null);
                ReadOnlyMemory<byte> selectedRequest = await attributesHandler
                    .CreateCertificateSigningRequestAsync(attributesRequest, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                produced = serviceInfo.Encode([module.PrepareEnrollmentRequest(selectedRequest)]);
            }
        }

        if (serviceInfo.Decode(produced).Count != 0)
        {
            throw new CborContentException("The completed enrollment produced unexpected Device ServiceInfo.");
        }

        byte[] pendingCertificate = module.CopyPendingCertificate().ToArray();
        var enrollmentEvidence = new FdoDeviceEnrollment(
            RunId, device.Guid, module.CopyEnrollmentRequest(), pendingCertificate,
            device.RequestCaCertificates ? module.CopyPendingCaCertificates() : null,
            device.RequestReenrollment,
            device.CsrAttributesHandler is not null ? module.CopyPendingCsrAttributes() : null,
            device.ServerKeygenHandler is not null);
        await _handler.ValidateCertificateAsync(enrollmentEvidence, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        FdoHashValue? replacementHmac = null;
        FdoDeviceReplacementCredential? replacementCredential = null;
        if (replacement is not null)
        {
            IFdoDeviceReplacementHandler handler = _replacementHandler
                ?? throw new InvalidOperationException("Credential replacement was not explicitly enabled.");
            ReadOnlyMemory<byte> headerTag = FdoInitializationFields.CreateReplacementHeader(
                verifiedOwner.HeaderTag, replacement.Guid, replacement.RendezvousInfo, replacement.OwnerKey);
            FdoOwnershipVoucherHeader header = FdoInitializationFields.ReadHeader(headerTag);
            FdoDeviceHmacAlgorithm algorithm = FdoInitializationFields.SelectHmac(
                FdoInitializationFields.GetKeyType(device.AttestationKey),
                FdoInitializationFields.GetKeyType(replacement.OwnerKey));
            FdoHashValue ownerHash = FdoHashValue.ComputeDigest(
                FdoInitializationFields.DigestAlgorithm(algorithm), replacement.OwnerKey.Span);
            var proposal = new FdoDeviceReplacementProposal(
                RunId, device.Guid, replacement.Guid, headerTag, replacement.RendezvousInfo,
                replacement.OwnerKey, ownerHash.Encode(), algorithm);
            ReplacementProposal = proposal;
            cancellationToken.ThrowIfCancellationRequested();
            ReplacementSecretReservationStarted = true;
            IFdoDeviceInitializeHmacSecret secret = await handler.ReserveSecretAsync(proposal, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException("The replacement handler returned no HMAC secret handle.");
            ReplacementSecretReserved = true;
            if (ReferenceEquals(secret, device.HmacSecretHandle))
            {
                throw new CryptographicException("The replacement must use a fresh Device HMAC secret.");
            }
            FdoInitializationFields.ValidateHmacSecretHandle(secret, algorithm);
            replacementCredential = new FdoDeviceReplacementCredential(proposal, secret);
            cancellationToken.ThrowIfCancellationRequested();
            ReplacementStagingStarted = true;
            await handler.StageAsync(replacementCredential, cancellationToken).ConfigureAwait(false);
            StagedReplacement = replacementCredential;
            cancellationToken.ThrowIfCancellationRequested();
            FdoInitializationFields.ValidateHmacSecretHandle(secret, algorithm);
            ReadOnlyMemory<byte> hmac = await secret.ComputeAsync(header.Contents.ToArray(), cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            replacementHmac = new FdoHashValue(FdoInitializationFields.HmacAlgorithm(algorithm), hmac.Span);
        }

        ReadOnlyMemory<byte> done = completion.EncodeDone(doneNonce, replacementHmac);
        state.RecordDone(done, replacementHmac?.Algorithm);
        cancellationToken.ThrowIfCancellationRequested();
        DoneSendStarted = true;
        byte[] receivedDoneAck = await ExchangeProtectedAsync(
            transport, FdoMessageTypes.TO2Done20, done,
            FdoMessageTypes.TO2DoneAck20, channel, ownerLimit, device.MaxMessageSize, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            ReadOnlyMemory<byte> receivedNonce = completion.DecodeDoneAck(receivedDoneAck);
            if (!CryptographicOperations.FixedTimeEquals(setupNonce, receivedNonce.Span))
            {
                throw new CryptographicException("The DoneAck20 nonce does not match the Device challenge.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(receivedDoneAck);
        }

        DoneAckAuthenticated = true;
        if (replacementCredential is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReplacementActivationStarted = true;
            await _replacementHandler!.ActivateAsync(replacementCredential, cancellationToken).ConfigureAwait(false);
            ActivatedReplacement = replacementCredential;
        }
        return new ProtectedEnrollment(
            enrollmentEvidence, device.ServerKeygenHandler is not null ? module.TakePendingPrivateKey() : null);
    }

    /// <summary>
    /// Sends one logical Device ServiceInfo transfer in as many rounds as the
    /// limits require, then polls with empty messages while the Owner reports
    /// more, and returns the Owner entries assembled into one message.
    /// </summary>
    private sealed class ServiceInfoExchange(
        FdoDeviceSession session,
        IFdoDeviceTransport transport,
        IFdoTo2PairedChannel channel,
        FdoTo2ServiceInfoState state,
        FdoTo2ServiceInfoCodec info,
        int deviceServiceInfoLimit,
        int ownerMessageLimit,
        int deviceMessageLimit)
    {
        public async Task<FdoTo2ServiceInfoCodec.OwnerServiceInfo> RunAsync(
            IReadOnlyList<FdoServiceInfoCodec.Entry> entries, CancellationToken cancellationToken)
        {
            IReadOnlyList<IReadOnlyList<FdoServiceInfoCodec.Entry>> batches = FdoServiceInfoBatches.Split(
                entries, deviceServiceInfoLimit, channel.GetSealedLength, ownerMessageLimit);
            var assembler = new FdoServiceInfoBatches.Assembler();
            try
            {
                FdoTo2ServiceInfoCodec.OwnerServiceInfo owner;
                int next = 0;
                do
                {
                    IReadOnlyList<FdoServiceInfoCodec.Entry> batch =
                        next < batches.Count ? batches[next] : Array.Empty<FdoServiceInfoCodec.Entry>();
                    bool isMore = next < batches.Count - 1;
                    next++;
                    ReadOnlyMemory<byte> request = info.EncodeDevice(isMore, batch);
                    state.RecordDevice(request);
                    byte[] received = await session.ExchangeProtectedAsync(
                        transport, FdoMessageTypes.TO2DeviceSvcInfo20, request,
                        FdoMessageTypes.TO2OwnerSvcInfo20, channel, ownerMessageLimit, deviceMessageLimit,
                        cancellationToken).ConfigureAwait(false);
                    try
                    {
                        owner = state.RecordOwner(received);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(received);
                    }

                    assembler.Append(owner.ServiceInfo);
                }
                while (next < batches.Count || owner.IsMoreServiceInfo);

                return new FdoTo2ServiceInfoCodec.OwnerServiceInfo(false, owner.IsDone, assembler.Take());
            }
            catch
            {
                assembler.Clear();
                throw;
            }
        }
    }

    private async Task<byte[]> ExchangeProtectedAsync(
        IFdoDeviceTransport transport,
        ushort requestType,
        ReadOnlyMemory<byte> plaintext,
        ushort responseType,
        IFdoTo2PairedChannel channel,
        int ownerLimit,
        int deviceLimit,
        CancellationToken cancellationToken)
    {
        _authenticatedResponseType = 0;
        ReadOnlyMemory<byte> encrypted = channel.Seal(plaintext);
        ReadOnlyMemory<byte> response = await ExchangeAsync(
            transport, requestType, encrypted, responseType, ownerLimit, deviceLimit, cancellationToken, channel)
            .ConfigureAwait(false);
        byte[] opened = channel.Open(response);
        _authenticatedResponseType = responseType;
        return opened;
    }

    private static async Task<ReadOnlyMemory<byte>> ExchangeAsync(
        IFdoDeviceTransport transport,
        ushort requestType,
        ReadOnlyMemory<byte> requestBody,
        ushort responseType,
        int ownerLimit,
        int deviceLimit,
        CancellationToken cancellationToken,
        IFdoTo2PairedChannel? channel = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requestBody.IsEmpty || requestBody.Length > ownerLimit)
        {
            throw new CborContentException("The FDO request exceeds the Owner message limit or is empty.");
        }

        FdoOwnerResponse response = await transport.SendAsync(
            200, (FdoTo2MessageType)requestType, requestBody.ToArray(), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(response);
        if (channel is not null && response.ProtocolVersion == 200 &&
            response.MessageType == FdoTo2MessageType.Error)
        {
            ThrowPeerError(channel, response.EncodedBody, requestType, deviceLimit);
        }

        if (response.ProtocolVersion != 200 || (ushort)response.MessageType != responseType)
        {
            throw new CborContentException("The Owner response version or type is unexpected.");
        }

        ReadOnlyMemory<byte> body = response.EncodedBody;
        if (body.IsEmpty || body.Length > deviceLimit)
        {
            throw new CborContentException("The Owner response exceeds the Device message limit or is empty.");
        }

        return body;
    }

    private static void ThrowPeerError(
        IFdoTo2PairedChannel channel,
        ReadOnlyMemory<byte> body,
        ushort requestType,
        int deviceLimit)
    {
        // The Error is authenticated on the live channel before its fields are
        // read. Its description text is untrusted and never surfaced.
        if (body.IsEmpty || body.Length > deviceLimit)
        {
            throw new CborContentException("The Owner response exceeds the Device message limit or is empty.");
        }

        byte[] opened = channel.Open(body);
        FdoErrorMessageCodec.ErrorMessage error;
        try
        {
            error = new FdoErrorMessageCodec(deviceLimit).Decode(opened);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(opened);
        }

        if (error.PreviousMessageId != requestType)
        {
            throw new CborContentException("The Owner Error does not name the Device request.");
        }

        throw new FdoPeerErrorException(error.ErrorCode, (FdoTo2MessageType)requestType);
    }

    private async ValueTask TrySendErrorAsync(
        IFdoDeviceTransport transport,
        IFdoTo2PairedChannel channel,
        Exception failure,
        int ownerLimit,
        CancellationToken cancellationToken)
    {
        // Send once, only after an authenticated Owner response whose local
        // processing failed. Transport, cancellation and peer Errors stay silent.
        ushort previous = _authenticatedResponseType;
        _authenticatedResponseType = 0;
        if (previous is not (FdoMessageTypes.TO2SetupDevice20 or FdoMessageTypes.TO2OwnerSvcInfo20) ||
            failure is OperationCanceledException or FdoPeerErrorException ||
            cancellationToken.IsCancellationRequested ||
            transport is not IFdoDeviceErrorTransport errorTransport)
        {
            return;
        }

        try
        {
            ushort code = FdoErrorCodes.Classify(failure);
            ReadOnlyMemory<byte> sealedError = channel.Seal(
                new FdoErrorMessageCodec().Encode(code, (byte)previous, FdoErrorCodes.NewCorrelationId()));
            if (sealedError.IsEmpty || sealedError.Length > ownerLimit)
            {
                return;
            }

            await errorTransport.SendErrorAsync(200, sealedError.ToArray(), cancellationToken).ConfigureAwait(false);
            SentErrorCode = code;
        }
        catch (Exception)
        {
            // The original failure is reported; Error delivery is never retried.
        }
    }

    private sealed record DeviceSettings(
        ReadOnlyMemory<byte> Guid,
        FdoHashValue ManufacturerKeyHash,
        FdoDeviceHmacAlgorithm HmacAlgorithm,
        ReadOnlyMemory<byte> HmacSecret,
        IFdoDeviceInitializeHmacSecret? HmacSecretHandle,
        ECDsa AttestationKey,
        ReadOnlyMemory<byte> CertificateSigningRequest,
        FdoKeyExchangeSuite Exchange,
        ReadOnlyMemory<byte> ProvisionedAsymOwnerKey,
        FdoCoseAeadAlgorithm Cipher,
        bool AllowCredentialReuse,
        ushort MaxMessageSize,
        ushort MaxOwnerServiceInfoSize,
        bool RequestCaCertificates,
        bool RequestReenrollment,
        IFdoDeviceCsrAttributesHandler? CsrAttributesHandler,
        IFdoDeviceServerKeygenHandler? ServerKeygenHandler,
        FdoDeviceMetadata Metadata,
        ReadOnlyMemory<byte>? SignedRendezvousRedirect,
        IFdoDeviceDelegateAcceptance? DelegateAcceptance,
        TimeProvider? DelegateTimeProvider,
        IFdoDeviceRedirectDelegateAcceptance? RedirectDelegateAcceptance,
        TimeProvider? RedirectDelegateTimeProvider,
        FdoDelegateOfflineRevocationPolicy? DelegateOfflineRevocation,
        FdoDelegateOfflineRevocationPolicy? RedirectDelegateOfflineRevocation,
        MultiAddressSelection? SelectedRoute);

    private sealed record MultiAddressSelection(
        FdoDeviceRendezvousResult Result, int Index, FdoRendezvousAddress Address);

    private sealed record ProtectedEnrollment(FdoDeviceEnrollment Enrollment, byte[]? PrivateKey);
}
