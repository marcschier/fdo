using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Rendezvous;
using Fdo.Serialization;
using Fdo.Transport.Http;

namespace Fdo.Tests.Transport;

internal sealed record RecordedRequest(
    HttpMethod Method,
    Uri? Uri,
    string? Authorization,
    string? ContentType,
    byte[] Body);

[UnsupportedOSPlatform("browser")]
internal static partial class Program
{
    private const ushort MaxMessageSize = 8192;

    public static async Task<int> Main(string[] args)
    {
        if (!TryParseArguments(args, out SmokeScenario? scenario, out bool requireNativeAot, out string? error))
        {
            Console.Error.WriteLine(error);
            Console.Error.WriteLine("Usage: Fdo.AotSmoke --scenario <name> [--require-native-aot]");
            Console.Error.WriteLine("Scenarios: " + string.Join(", ", Scenarios.Select(item => item.Name)));
            return 2;
        }

        if ((scenario!.RequiresLinux && !OperatingSystem.IsLinux()) ||
            (scenario.ExpectPlatformRejection && OperatingSystem.IsLinux()))
        {
            Console.Error.WriteLine(scenario.RequiresLinux
                ? $"Scenario '{scenario.Name}' requires Linux and was not run."
                : $"Scenario '{scenario.Name}' asserts the non-Linux rejection and was not run on Linux.");
            return 2;
        }

        if (requireNativeAot && RuntimeFeature.IsDynamicCodeSupported)
        {
            Console.Error.WriteLine("--require-native-aot was set, but dynamic code is supported (not a NativeAOT image).");
            return 2;
        }

        try
        {
            string outcome = await RunAsync(scenario);
            Console.WriteLine(
                $"FDO AOT smoke passed: scenario={scenario.Name} {outcome} " +
                $"runtime={RuntimeInformation.FrameworkDescription} os={RuntimeInformation.OSDescription} " +
                $"arch={RuntimeInformation.ProcessArchitecture} dynamicCode={RuntimeFeature.IsDynamicCodeSupported}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"FDO AOT smoke failed: scenario={scenario.Name} {exception.GetType().FullName}: {exception.Message}");
            return 1;
        }
    }

    private static readonly SmokeScenario[] Scenarios =
    [
        new("ecdh256-a128gcm", FdoPairedKeyExchangeSuite.Ecdh256, FdoPairedCipherSuite.A128Gcm, OwnerKeyKind.P256),
        new("ecdh256-ctr128", FdoPairedKeyExchangeSuite.Ecdh256, FdoPairedCipherSuite.AesCtr128HmacSha256, OwnerKeyKind.P256),
        new("ecdh384-ctr256", FdoPairedKeyExchangeSuite.Ecdh384, FdoPairedCipherSuite.AesCtr256HmacSha384, OwnerKeyKind.P384),
        new("ecdh256-cbc128", FdoPairedKeyExchangeSuite.Ecdh256, FdoPairedCipherSuite.AesCbc128HmacSha256, OwnerKeyKind.P256),
        new("ecdh384-cbc256", FdoPairedKeyExchangeSuite.Ecdh384, FdoPairedCipherSuite.AesCbc256HmacSha384, OwnerKeyKind.P384),
        new("asym2048-cbc128", FdoPairedKeyExchangeSuite.Asymkex2048, FdoPairedCipherSuite.AesCbc128HmacSha256, OwnerKeyKind.Rsa2048),
        new("asym3072-cbc256", FdoPairedKeyExchangeSuite.Asymkex3072, FdoPairedCipherSuite.AesCbc256HmacSha384, OwnerKeyKind.Rsa3072),
        new("dh14-cbc128", FdoPairedKeyExchangeSuite.DhkexId14, FdoPairedCipherSuite.AesCbc128HmacSha256, OwnerKeyKind.Rsa2048, RequiresLinux: true),
        new("dh15-ctr256", FdoPairedKeyExchangeSuite.DhkexId15, FdoPairedCipherSuite.AesCtr256HmacSha384, OwnerKeyKind.Rsa3072, RequiresLinux: true),
        new("dh14-rejected", FdoPairedKeyExchangeSuite.DhkexId14, FdoPairedCipherSuite.AesCbc128HmacSha256, OwnerKeyKind.Rsa2048, ExpectPlatformRejection: true),
        new("dh15-rejected", FdoPairedKeyExchangeSuite.DhkexId15, FdoPairedCipherSuite.AesCtr256HmacSha384, OwnerKeyKind.Rsa3072, ExpectPlatformRejection: true),
        new("delegated-replacement", FdoPairedKeyExchangeSuite.Ecdh256, FdoPairedCipherSuite.A128Gcm, OwnerKeyKind.P256, DelegatedReplacement: true),
        new("direct-rsa-combined-offers", FdoPairedKeyExchangeSuite.DhkexId14, FdoPairedCipherSuite.AesCbc128HmacSha256,
            OwnerKeyKind.Rsa2048, RequiresLinux: true, CombinedOffers: true),
    ];

    private static bool TryParseArguments(
        string[] args, out SmokeScenario? scenario, out bool requireNativeAot, out string? error)
    {
        scenario = null;
        requireNativeAot = false;
        error = null;
        for (int index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--scenario" when index + 1 < args.Length && scenario is null:
                    string name = args[++index];
                    scenario = Scenarios.FirstOrDefault(item => item.Name == name);
                    if (scenario is null)
                    {
                        error = $"Unknown scenario '{name}'.";
                        return false;
                    }

                    break;
                case "--require-native-aot" when !requireNativeAot:
                    requireNativeAot = true;
                    break;
                default:
                    error = $"Unexpected or repeated argument '{args[index]}'.";
                    return false;
            }
        }

        if (scenario is null)
        {
            error = "Exactly one --scenario is required; there is no default scenario.";
            return false;
        }

        return true;
    }

    private static async Task<string> RunAsync(SmokeScenario scenario)
    {
        using var host = new SmokeHost(scenario);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var lookupListener = new LoopbackHttpServer();
        using var manufacturingListener = new LoopbackHttpServer();
        host.ManufacturingAddress = manufacturingListener.Address;
        host.RendezvousInfo = EncodeRendezvousInfo((ushort)lookupListener.Address.Port);

        using var manufacturer = new FdoManufacturerInitializeSession(new FdoManufacturerInitializeOptions
        {
            Handler = host,
            MaxMessageSize = MaxMessageSize,
            UseVoucherHeaderHmac = true,
        });
        var initializingDevice = new FdoDeviceInitializeSession(new FdoDeviceInitializeOptions
        {
            AttestationKey = host.DeviceKey,
            Handler = host,
            MaxMessageSize = MaxMessageSize,
            UseVoucherHeaderHmac = true,
        });
        using var manufacturingBinding = FdoHttpServerSession.ForManufacturer(manufacturer, MaxMessageSize);
        Task<IReadOnlyList<RecordedRequest>> manufacturingServing =
            manufacturingListener.ServeSessionAsync(manufacturingBinding, timeout.Token);
        FdoDeviceInitializeCredential credential = await FdoHttp.RunDeviceInitializeAsync(
            initializingDevice, manufacturingListener.Address, MaxMessageSize, timeout.Token);
        RequirePaths(await manufacturingServing, "/fdo/200/msg/10", "/fdo/200/msg/12");
        Require(ReferenceEquals(host.InstalledCredential, credential), "DI credential was not installed.");
        Require(manufacturer.DoneHandoffConfirmed && initializingDevice.DoneReceived, "DI did not complete.");

        FdoManufacturerInitializeVoucher voucher = host.Voucher
            ?? throw new InvalidOperationException("The manufacturer did not retain the voucher.");
        using ReplacementSmoke? replacement = scenario.DelegatedReplacement
            ? new ReplacementSmoke((ECDsa)host.OwnerKey, credential.DeviceGuid, host.RendezvousInfo) : null;
        FdoTransferredOwnershipVoucher transferred = replacement is null
            ? host.TransferVoucher(voucher.EncodedVoucher)
            : FdoOwnershipVoucherTransfer.ExtendWithCertificateChain(
                voucher.EncodedVoucher, (ECDsa)host.ManufacturerKey, [replacement.OwnerCertificate]);
        Require(transferred.EncodedVoucherEntries.Count == 1, "Voucher transfer did not add one entry.");
        Require(transferred.EncodedVoucherHeaderTag.Span.SequenceEqual(voucher.EncodedVoucherHeaderTag.Span),
            "Voucher transfer changed the header.");

        IReadOnlyList<FdoRendezvousServerCandidate> ownerCandidates = FdoRendezvousInfo.ParseVoucherHeader(
            transferred.EncodedVoucherHeaderTag, FdoRendezvousProtocol.OwnerRegistration);
        IReadOnlyList<FdoRendezvousServerCandidate> deviceCandidates = FdoRendezvousInfo.Parse(
            credential.EncodedRendezvousInfo, FdoRendezvousProtocol.DeviceLookup);
        Require(ownerCandidates.Count == 1 && ownerCandidates[0].BaseAddress.AbsoluteUri == "https://rvserver.local/",
            "The voucher did not expose the expected Owner rendezvous candidate.");
        Require(deviceCandidates.Count == 2 && deviceCandidates[1].BaseAddress == lookupListener.Address,
            "The credential did not expose the selected Device rendezvous candidate.");

        byte[] trustedManufacturerKey = host.EncodeManufacturerKey();
        using var ownerListener = new LoopbackHttpServer();
        var ownerAddress = new FdoRendezvousAddress(
            new byte[] { 127, 0, 0, 1 }, null, (ushort)ownerListener.Address.Port,
            FdoRendezvousTransportProtocol.Http);
        var registrationOwner = new FdoOwnerRendezvousSession(new FdoOwnerRendezvousOptions
        {
            EncodedVoucherHeaderTag = transferred.EncodedVoucherHeaderTag,
            EncodedVoucherHeaderHmac = transferred.EncodedVoucherHeaderHmac,
            EncodedVoucherEntries = transferred.EncodedVoucherEntries,
            EncodedDeviceCertificateChain = transferred.EncodedDeviceCertificateChain,
            TrustedManufacturerKey = trustedManufacturerKey,
            DeviceTrustAnchor = host.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = host.OwnerKey,
            OwnerAddress = ownerAddress,
            WaitSeconds = 300,
            MaxMessageSize = MaxMessageSize,
            UseProvisionalPairedProfile = true,
        });

        using var registrationListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession registrationServer = CreateRendezvousServer(
            host, trustedManufacturerKey, FdoRendezvousProtocol.OwnerRegistration);
        using var registrationBinding = FdoHttpServerSession.ForRendezvous(registrationServer, MaxMessageSize);
        Task<IReadOnlyList<RecordedRequest>> registrationServing =
            registrationListener.ServeSessionAsync(registrationBinding, timeout.Token);
        uint accepted = await FdoHttp.RunOwnerRendezvousAsync(
            registrationOwner, registrationListener.Address, MaxMessageSize, timeout.Token);
        RequirePaths(await registrationServing, "/fdo/200/msg/20", "/fdo/200/msg/22");
        Require(accepted > 0 && registrationServer.FinalResponseHandoffConfirmed,
            "TO0 registration did not complete.");
        FdoRendezvousRegistration registration = host.Registration
            ?? throw new InvalidOperationException("The rendezvous registration was not stored.");

        var lookupDevice = new FdoDeviceRendezvousSession(new FdoDeviceRendezvousOptions
        {
            DeviceGuid = credential.DeviceGuid,
            AttestationKey = host.DeviceKey,
            MaxMessageSize = MaxMessageSize,
            UseProvisionalPairedProfile = true,
        });
        using FdoRendezvousServerSession lookupServer = CreateRendezvousServer(
            host, trustedManufacturerKey, FdoRendezvousProtocol.DeviceLookup);
        using var lookupBinding = FdoHttpServerSession.ForRendezvous(lookupServer, MaxMessageSize);
        Task<IReadOnlyList<RecordedRequest>> lookupServing =
            lookupListener.ServeSessionAsync(lookupBinding, timeout.Token);
        FdoDeviceRendezvousResult lookup = await FdoHttp.RunDeviceRendezvousAsync(
            lookupDevice, deviceCandidates[1].BaseAddress, MaxMessageSize, timeout.Token);
        RequirePaths(await lookupServing, "/fdo/200/msg/30", "/fdo/200/msg/32");
        Require(lookup.SignedRedirect.Span.SequenceEqual(registration.SignedRedirect.Span),
            "TO1 did not return the stored signed redirect.");
        ReadOnlyMemory<byte> ownerIp = lookup.CandidateAddress.IpAddress
            ?? throw new InvalidOperationException("The TO1 Owner candidate has no IP address.");
        Require(lookup.CandidateAddress.Protocol == FdoRendezvousTransportProtocol.Http,
            "The TO1 Owner candidate has the wrong protocol.");
        var selectedOwner = new UriBuilder(
            Uri.UriSchemeHttp, new IPAddress(ownerIp.Span).ToString(), lookup.CandidateAddress.Port).Uri;
        Require(selectedOwner == ownerListener.Address, "The TO1 Owner candidate was not authorized.");

        bool dh = scenario.Exchange is FdoPairedKeyExchangeSuite.DhkexId14 or FdoPairedKeyExchangeSuite.DhkexId15;
        bool asym = scenario.Exchange is FdoPairedKeyExchangeSuite.Asymkex2048 or FdoPairedKeyExchangeSuite.Asymkex3072;
        var ownerOptions = new FdoOwnerSessionOptions
        {
            EncodedVoucherHeaderTag = transferred.EncodedVoucherHeaderTag,
            EncodedVoucherHeaderHmac = transferred.EncodedVoucherHeaderHmac,
            EncodedVoucherEntries = transferred.EncodedVoucherEntries,
            EncodedDeviceCertificateChain = transferred.EncodedDeviceCertificateChain,
            TrustedManufacturerKey = trustedManufacturerKey,
            DeviceTrustAnchor = host.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = host.OwnerKey,
            EnrollmentHandler = host,
            KeyExchangeSuite = scenario.CombinedOffers ? FdoPairedKeyExchangeSuite.Asymkex2048 : scenario.Exchange,
            AdditionalKeyExchangeSuite = scenario.CombinedOffers ? scenario.Exchange : null,
            UseProvisionalPairedDh = dh,
            UseProvisionalPairedAsymkex = asym || scenario.CombinedOffers,
            CipherSuite = scenario.CombinedOffers ? FdoPairedCipherSuite.A128Gcm : scenario.Cipher,
            AdditionalCipherSuites = scenario.CombinedOffers ? [scenario.Cipher] : null,
            AllowRendezvousBypass = false,
            AllowRendezvous = true,
            AllowCredentialReuse = replacement is null,
            Replacement = replacement?.OwnerOptions,
            UseDelegatedOwnerProof = replacement is not null,
            DelegateSigningKey = replacement?.DelegateKey,
            DelegateCertificateChain = replacement?.DelegateChain,
            DelegateTimeProvider = replacement is null ? null : TimeProvider.System,
            DelegateOfflineRevocation = replacement?.OfflinePolicy,
            UseProvisionalPairedProfile = true,
            MaxMessageSize = MaxMessageSize,
            MaxDeviceServiceInfoSize = 4096,
        };
        var deviceOptions = new FdoDeviceSessionOptions
        {
            DeviceGuid = credential.DeviceGuid,
            EncodedManufacturerKeyHash = credential.EncodedManufacturerKeyHash,
            VoucherHmacAlgorithm = credential.VoucherHmacAlgorithm,
            VoucherHmacSecretHandle = credential.VoucherHmacSecret,
            AttestationKey = host.DeviceKey,
            CertificateSigningRequest = host.CertificateSigningRequest,
            KeyExchangeSuite = scenario.Exchange,
            UseProvisionalPairedDh = dh,
            UseProvisionalPairedAsymkex = asym,
            EncodedAsymkexOwnerPublicKey = asym ? host.EncodeOwnerKey() : ReadOnlyMemory<byte>.Empty,
            CipherSuite = scenario.Cipher,
            AllowRendezvousBypass = false,
            RendezvousResult = lookup,
            AllowCredentialReuse = replacement is null,
            ReplacementHandler = replacement,
            UseDelegatedOwnerProof = replacement is not null,
            DelegateAcceptance = replacement,
            DelegateTimeProvider = replacement is null ? null : TimeProvider.System,
            DelegateOfflineRevocation = replacement?.OfflinePolicy,
            UseProvisionalPairedProfile = true,
            MaxMessageSize = MaxMessageSize,
            MaxOwnerServiceInfoSize = 4096,
            Metadata = new FdoDeviceMetadata("smoke-os", "smoke-arch", "1", "smoke-device", ":", "smoke-arch"),
            EnrollmentHandler = host,
        };
        if (scenario.ExpectPlatformRejection)
        {
            Require(ThrowsExactly<PlatformNotSupportedException>(() => new FdoOwnerSession(ownerOptions).Dispose()),
                "The Owner did not reject paired DH as unsupported on this platform.");
            Require(ThrowsExactly<PlatformNotSupportedException>(() => new FdoDeviceSession(deviceOptions).Dispose()),
                "The Device did not reject paired DH as unsupported on this platform.");
            Require(host.IssueCount == 0 && host.CommitCount == 0 &&
                host.ValidationCount == 0 && host.InstallCount == 0,
                "Enrollment callbacks ran although TO2 was rejected.");
            return "outcome=platform-rejected path=DI->transfer->TO0->TO1->TO2-rejected-before-HelloDevice";
        }

        using var owner = new FdoOwnerSession(ownerOptions);
        using var device = new FdoDeviceSession(deviceOptions);
        host.DeviceSession = device;
        if (replacement is not null)
        {
            replacement.DeviceSession = device;
        }
        using var ownerBinding = FdoHttpServerSession.ForOwner(owner, MaxMessageSize);
        bool offersVerified = false;
        Task<IReadOnlyList<RecordedRequest>> ownerServing =
            ownerListener.ServeSessionAsync(ownerBinding, timeout.Token,
                transformResponse: scenario.CombinedOffers ? CheckCombinedOffers : null);
        FdoDeviceEnrollment enrollment = await FdoHttp.RunDeviceAsync(
            device, selectedOwner, MaxMessageSize, timeout.Token);
        IReadOnlyList<RecordedRequest> ownerRequests = await ownerServing;
        RequirePaths(ownerRequests, "/fdo/200/msg/80", "/fdo/200/msg/82", "/fdo/200/msg/84",
            "/fdo/200/msg/86", "/fdo/200/msg/88", "/fdo/200/msg/88", "/fdo/200/msg/90");
        byte protectedTag = scenario.Cipher is FdoPairedCipherSuite.A128Gcm ? (byte)0xD0 : (byte)0xD1;
        Require(ownerRequests.Skip(3).All(request => request.Body.Length > 0 && request.Body[0] == protectedTag),
            "TO2 ServiceInfo or completion was not protected with the selected cipher suite.");
        if (scenario.CombinedOffers)
        {
            Require(offersVerified, "The combined offer acknowledgement was not observed.");
            RequireCombinedSelection(ownerRequests[1].Body);
        }
        Require(enrollment.Certificate.Span.SequenceEqual(host.IssuedCertificate.RawData),
            "The Device received the wrong enrollment certificate.");
        Require(owner.DoneAckHandoffConfirmed && device.DoneAckAuthenticated,
            "The TO2 completion handoff and Device authentication did not both occur.");
        Require(host.IssueCount == 1 && host.CommitCount == 1 &&
            host.ValidationCount == 1 && host.InstallCount == 1,
            "The enrollment callbacks did not complete exactly once.");
        replacement?.RequireCompleted();

        return $"outcome=enrolled exchange={scenario.Exchange} cipher={scenario.Cipher} " +
            "path=DI->transfer->TO0->TO1->protected-TO2->DoneAck" +
            (replacement is null ? string.Empty : " voucherKey=x5chain delegated=verified offlineStatus=verified replacement=activated") +
            (scenario.CombinedOffers ? " combinedOffers=verified selection=non-primary channel=cbc-etm" : string.Empty);

        ReadOnlyMemory<byte> CheckCombinedOffers(FdoHttpServerResponse response)
        {
            ReadOnlyMemory<byte> body = response.EncodedBody;
            if (response.MessageType == 81)
            {
                var reader = new CborReader(body);
                Require(reader.ReadStartArray() == 8, "Unexpected combined offer acknowledgement.");
                for (int i = 0; i < 4; i++)
                {
                    reader.SkipValue();
                }

                Require(reader.ReadStartArray() == 2 && reader.ReadTextString() == "ASYMKEX2048" &&
                    reader.ReadTextString() == "DHKEXid14", "The Owner did not offer the ordered RSA exchange pair.");
                reader.ReadEndArray();
                Require(reader.ReadStartArray() == 2 && reader.ReadInt32() == 1 && reader.ReadInt32() == Cbc128Suite,
                    "The Owner did not offer GCM followed by CBC-EtM.");
                offersVerified = true;
            }

            return body;
        }
    }

    private const int Cbc128Suite = -17760703;

    private static void RequireCombinedSelection(ReadOnlyMemory<byte> proof)
    {
        var cose = new CborReader(proof);
        Require(cose.ReadTag() == (CborTag)18 && cose.ReadStartArray() == 4, "Unexpected Device proof envelope.");
        cose.SkipValue();
        cose.SkipValue();
        var payload = new CborReader(cose.ReadDefiniteLengthByteString());
        Require(payload.ReadStartMap() == 3, "Unexpected Device proof claims.");
        for (int i = 0; i < 3; i++)
        {
            if (payload.ReadInt32() != -257)
            {
                payload.SkipValue();
                continue;
            }

            Require(payload.ReadStartArray() == 5 && payload.ReadTextString() == "DHKEXid14" &&
                payload.ReadInt32() == Cbc128Suite, "The authenticated Device proof did not select both non-primary suites.");
            return;
        }

        throw new InvalidOperationException("The authenticated Device proof did not contain a suite selection.");
    }

    private static bool ThrowsExactly<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (Exception exception)
        {
            return exception.GetType() == typeof(TException);
        }
    }

    private static FdoRendezvousServerSession CreateRendezvousServer(
        SmokeHost host, ReadOnlyMemory<byte> trustedManufacturerKey, FdoRendezvousProtocol protocol) =>
        new(new FdoRendezvousServerOptions
        {
            TrustedManufacturerKey = trustedManufacturerKey,
            DeviceTrustAnchor = host.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            RegistrationStore = host,
            MaxWaitSeconds = 120,
            MaxMessageSize = MaxMessageSize,
            UseProvisionalPairedProfile = true,
        }, protocol);

    private static byte[] EncodeRendezvousInfo(ushort port)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteStartArray(1);
        WriteInstruction(5, value => value.WriteTextString("rvserver.local"));
        writer.WriteEndArray();
        writer.WriteStartArray(4);
        WriteInstruction(0, value => value.WriteNull());
        WriteInstruction(2, value => value.WriteByteString(new byte[] { 127, 0, 0, 1 }));
        WriteInstruction(3, value => value.WriteUInt32(port));
        WriteInstruction(12, value => value.WriteUInt32(1));
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();

        void WriteInstruction(int variable, Action<CborWriter> writeValue)
        {
            var value = new CborWriter(CborConformanceMode.Canonical);
            writeValue(value);
            writer.WriteStartArray(2);
            writer.WriteInt32(variable);
            writer.WriteByteString(value.Encode());
            writer.WriteEndArray();
        }
    }

    private static void RequirePaths(IReadOnlyList<RecordedRequest> requests, params string[] expected)
    {
        Require(requests.Select(request => request.Uri?.AbsolutePath).SequenceEqual(expected),
            "The HTTP request sequence did not match the paired protocol.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class SmokeHost :
        IFdoDeviceInitializeHandler,
        IFdoManufacturerInitializeHandler,
        IFdoDeviceInitializeHmacSecret,
        IFdoRendezvousRegistrationStore,
        IFdoOwnerEnrollmentHandler,
        IFdoDeviceEnrollmentHandler,
        IDisposable
    {
        private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly byte[] _voucherSecret;
        private FdoManufacturerInitializeProposal? _proposal;
        private FdoDeviceInitializeCredential? _stagedCredential;
        private bool _reserved;

        public SmokeHost(SmokeScenario scenario)
        {
            ManufacturerKey = CreateOwnerKey(scenario.Key);
            OwnerKey = CreateOwnerKey(scenario.Key);
            Algorithm = scenario.Key is OwnerKeyKind.P384
                ? FdoDeviceHmacAlgorithm.HmacSha384 : FdoDeviceHmacAlgorithm.HmacSha256;
            _voucherSecret = RandomNumberGenerator.GetBytes(
                Algorithm == FdoDeviceHmacAlgorithm.HmacSha384 ? 64 : 32);
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            DateTimeOffset notAfter = notBefore.AddDays(1);
            var rootRequest = new CertificateRequest("CN=FDO smoke CA", _rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            RootCertificate = rootRequest.CreateSelfSigned(notBefore, notAfter);

            var deviceRequest = new CertificateRequest("CN=FDO smoke device", DeviceKey, HashAlgorithmName.SHA256);
            deviceRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            deviceRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            DeviceCertificate = deviceRequest.Create(
                RootCertificate, notBefore.AddMinutes(1), notAfter.AddMinutes(-1), new byte[] { 1, 2, 3, 4 });

            var enrollmentRequest = new CertificateRequest(
                "CN=FDO smoke enrollment", _enrollmentKey, HashAlgorithmName.SHA256);
            CertificateSigningRequest = enrollmentRequest.CreateSigningRequest();
            IssuedCertificate = enrollmentRequest.Create(
                RootCertificate, notBefore.AddMinutes(1), notAfter.AddMinutes(-1), new byte[] { 1, 2, 3, 5 });
        }

        public ECDsa DeviceKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public AsymmetricAlgorithm ManufacturerKey { get; }
        public AsymmetricAlgorithm OwnerKey { get; }
        public X509Certificate2 RootCertificate { get; }
        public X509Certificate2 DeviceCertificate { get; }
        public X509Certificate2 IssuedCertificate { get; }
        public byte[] CertificateSigningRequest { get; }
        public Uri? ManufacturingAddress { get; set; }
        public ReadOnlyMemory<byte> RendezvousInfo { get; set; }
        public FdoManufacturerInitializeVoucher? Voucher { get; private set; }
        public FdoDeviceInitializeCredential? InstalledCredential { get; private set; }
        public FdoRendezvousRegistration? Registration { get; private set; }
        public FdoDeviceSession? DeviceSession { get; set; }
        public int IssueCount { get; private set; }
        public int CommitCount { get; private set; }
        public int ValidationCount { get; private set; }
        public int InstallCount { get; private set; }
        public FdoDeviceHmacAlgorithm Algorithm { get; }
        public int KeySizeInBytes => _voucherSecret.Length;

        public FdoTransferredOwnershipVoucher TransferVoucher(ReadOnlyMemory<byte> encodedVoucher)
        {
            if (OwnerKey is RSA rsaOwner)
            {
                using RSA approved = RSA.Create(rsaOwner.ExportParameters(false));
                return FdoOwnershipVoucherTransfer.ExtendRsa(encodedVoucher, (RSA)ManufacturerKey, approved);
            }

            using ECDsa approvedOwner = ECDsa.Create(((ECDsa)OwnerKey).ExportParameters(false));
            return FdoOwnershipVoucherTransfer.Extend(encodedVoucher, (ECDsa)ManufacturerKey, approvedOwner);
        }

        public byte[] EncodeManufacturerKey() => EncodeKey(ManufacturerKey);

        public byte[] EncodeOwnerKey() => EncodeKey(OwnerKey);

        private static byte[] EncodeKey(AsymmetricAlgorithm key) => key is RSA rsa
            ? new FdoPublicKeyCodec().EncodeRsa(rsa).ToArray()
            : new FdoPublicKeyCodec().Encode((ECDsa)key).ToArray();

        private static AsymmetricAlgorithm CreateOwnerKey(OwnerKeyKind kind) => kind switch
        {
            OwnerKeyKind.P256 => ECDsa.Create(ECCurve.NamedCurves.nistP256),
            OwnerKeyKind.P384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            OwnerKeyKind.Rsa2048 => RSA.Create(2048),
            OwnerKeyKind.Rsa3072 => RSA.Create(3072),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        public ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
            Guid runId, IFdoDeviceInitializeTransport transport, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(!_reserved && transport is IFdoHttpPeer peer && peer.BaseAddress == ManufacturingAddress,
                "The manufacturing station was not authorized or the Device was already reserved.");
            _reserved = true;
            return ValueTask.FromResult<IFdoDeviceInitializeHmacSecret>(this);
        }

        public ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(_reserved && _stagedCredential is null && credential.DeviceInfo == "fdo-aot-smoke",
                "The initialization proposal was not authorized.");
            _stagedCredential = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(ReferenceEquals(_stagedCredential, credential) && InstalledCredential is null,
                "The staged initialization credential does not match.");
            InstalledCredential = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask<FdoManufacturerInitializeProposal> AuthorizeAndPrepareAsync(
            FdoManufacturerInitializeRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(_proposal is null, "A manufacturer proposal already exists.");
            var certificates = new ReadOnlyMemory<byte>[] { DeviceCertificate.RawData, RootCertificate.RawData };
            FdoManufacturerInitializeProposal proposal = ManufacturerKey is RSA rsaManufacturer
                ? FdoManufacturerInitializeProposal.CreateRsa(
                    "fdo-aot-smoke", rsaManufacturer, certificates, encodedRendezvousInfo: RendezvousInfo)
                : FdoManufacturerInitializeProposal.Create(
                    "fdo-aot-smoke", (ECDsa)ManufacturerKey, certificates, RendezvousInfo);
            _proposal = proposal;
            return ValueTask.FromResult(proposal);
        }

        public ValueTask PersistVoucherAsync(FdoManufacturerInitializeVoucher voucher, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(_proposal is not null &&
                _proposal.EncodedVoucherHeaderTag.Span.SequenceEqual(voucher.EncodedVoucherHeaderTag.Span),
                "The retained voucher does not match the manufacturer proposal.");
            Voucher = voucher;
            return ValueTask.CompletedTask;
        }

        public ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
            ReadOnlyMemory<byte> encodedHeaderContents, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(Algorithm == FdoDeviceHmacAlgorithm.HmacSha384
                ? HMACSHA384.HashData(_voucherSecret, encodedHeaderContents.Span)
                : HMACSHA256.HashData(_voucherSecret, encodedHeaderContents.Span));
        }

        public ValueTask StoreAsync(FdoRendezvousRegistration registration, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(InstalledCredential is not null &&
                registration.DeviceGuid.Span.SequenceEqual(InstalledCredential.DeviceGuid.Span),
                "The registration belongs to another Device.");
            Registration = registration;
            return ValueTask.CompletedTask;
        }

        public ValueTask<FdoRendezvousRegistration?> FindAsync(
            ReadOnlyMemory<byte> deviceGuid, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FdoRendezvousRegistration? registration = Registration;
            return ValueTask.FromResult(
                registration is not null && registration.DeviceGuid.Span.SequenceEqual(deviceGuid.Span)
                    ? registration : null);
        }

        public ValueTask<ReadOnlyMemory<byte>> AuthorizeAndIssueAsync(
            FdoEnrollmentRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(InstalledCredential is not null &&
                request.DeviceGuid.Span.SequenceEqual(InstalledCredential.DeviceGuid.Span) &&
                request.DeviceAttestationCertificate.Span.SequenceEqual(DeviceCertificate.RawData) &&
                request.CertificateSigningRequest.Span.SequenceEqual(CertificateSigningRequest),
                "The authenticated enrollment request was not authorized.");
            IssueCount++;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(IssuedCertificate.RawData);
        }

        public ValueTask CommitAsync(FdoEnrollmentCommit enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(IssueCount == 1 && enrollment.Certificate.Span.SequenceEqual(IssuedCertificate.RawData),
                "The committed enrollment does not match the issued certificate.");
            CommitCount++;
            return ValueTask.CompletedTask;
        }

        public ValueTask ValidateCertificateAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(enrollment.Certificate.Span.SequenceEqual(IssuedCertificate.RawData) &&
                enrollment.CertificateSigningRequest.Span.SequenceEqual(CertificateSigningRequest),
                "The enrollment certificate or request is unexpected.");
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(enrollment.Certificate.Span);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(RootCertificate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            Require(chain.Build(certificate), "The enrollment certificate was not trusted.");
            ValidationCount++;
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(DeviceSession?.DoneAckAuthenticated == true && ValidationCount == 1 &&
                enrollment.Certificate.Span.SequenceEqual(IssuedCertificate.RawData),
                "The enrollment was installed before authentication and validation.");
            InstallCount++;
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_voucherSecret);
            IssuedCertificate.Dispose();
            DeviceCertificate.Dispose();
            RootCertificate.Dispose();
            OwnerKey.Dispose();
            ManufacturerKey.Dispose();
            DeviceKey.Dispose();
            _enrollmentKey.Dispose();
            _rootKey.Dispose();
        }
    }

    private enum OwnerKeyKind
    {
        P256,
        P384,
        Rsa2048,
        Rsa3072,
    }

    private sealed record SmokeScenario(
        string Name,
        FdoPairedKeyExchangeSuite Exchange,
        FdoPairedCipherSuite Cipher,
        OwnerKeyKind Key,
        bool RequiresLinux = false,
        bool ExpectPlatformRejection = false,
        bool DelegatedReplacement = false,
        bool CombinedOffers = false);
}
