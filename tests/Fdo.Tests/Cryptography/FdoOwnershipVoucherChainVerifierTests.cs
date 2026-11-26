// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Cryptography;

public sealed class FdoOwnershipVoucherChainVerifierTests
{
    [Test]
    [Arguments(256, 5, -16, -43)]
    [Arguments(384, 6, -43, -16)]
    public async Task ValidatesDeviceAnchorsAndOrderedEntriesWithDistinctHashAlgorithms(
        int curveSize, int hmacAlgorithm, int previousAlgorithm, int headerInfoAlgorithm)
    {
        using var fixture = new VoucherFixture(
            curveSize, (FdoHashAlgorithm)hmacAlgorithm,
            (FdoHashAlgorithm)previousAlgorithm, (FdoHashAlgorithm)headerInfoAlgorithm);
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();

        verifier.CheckDeviceCredentials(
            fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret);
        verifier.AppendEntry(0, fixture.FirstEntry);
        verifier.AppendEntry(1, fixture.SecondEntry);
        verifier.CompleteDeviceChecks(fixture.FinalOwnerKey);

        await Assert.That(Throws<ObjectDisposedException>(() =>
            verifier.AppendEntry(2, fixture.SecondEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsChangedGuidManufacturerHashSecretAndHmacAlgorithm()
    {
        using var fixture = new VoucherFixture();
        byte[] wrongGuid = (byte[])fixture.Guid.Clone();
        wrongGuid[0] ^= 0x01;
        byte[] wrongSecret = (byte[])fixture.Secret.Clone();
        wrongSecret[0] ^= 0x01;
        byte[] wrongHashBytes = fixture.ManufacturerHash.Value;
        wrongHashBytes[0] ^= 0x01;
        var wrongHash = new FdoHashValue(fixture.ManufacturerHash.Algorithm, wrongHashBytes);

        await Assert.That(RejectsCredentials(
            fixture, wrongGuid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret)).IsTrue();
        await Assert.That(RejectsCredentials(
            fixture, fixture.Guid, wrongHash, fixture.HmacAlgorithm, fixture.Secret)).IsTrue();
        await Assert.That(RejectsCredentials(
            fixture, fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, wrongSecret)).IsTrue();
        await Assert.That(RejectsCredentials(
            fixture, fixture.Guid, fixture.ManufacturerHash, FdoHashAlgorithm.HmacSha384, new byte[64])).IsTrue();
    }

    [Test]
    [Arguments("guid")]
    [Arguments("manufacturer")]
    [Arguments("algorithm")]
    public async Task RejectsInvalidAnchorsBeforeCallingAnOpaqueHmacHandle(string scenario)
    {
        using var fixture = new VoucherFixture();
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();
        byte[] guid = (byte[])fixture.Guid.Clone();
        byte[] manufacturerHash = fixture.ManufacturerHash.Value;
        if (scenario == "guid")
        {
            guid[0] ^= 1;
        }
        else if (scenario == "manufacturer")
        {
            manufacturerHash[0] ^= 1;
        }

        var hash = new FdoHashValue(fixture.ManufacturerHash.Algorithm, manufacturerHash);
        FdoHashAlgorithm algorithm = scenario == "algorithm"
            ? FdoHashAlgorithm.HmacSha384 : fixture.HmacAlgorithm;
        int calls = 0;
        async ValueTask<ReadOnlyMemory<byte>> Compute(ReadOnlyMemory<byte> header, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            calls++;
            await Task.Yield();
            return FdoHashValue.ComputeHmac(fixture.HmacAlgorithm, fixture.Secret, header.Span).Value;
        }

        bool rejected = false;
        try
        {
            await verifier.CheckDeviceCredentialsAsync(guid, hash, algorithm, Compute, CancellationToken.None);
        }
        catch (CryptographicException)
        {
            rejected = true;
        }

        await Assert.That(rejected).IsTrue();
        await Assert.That(calls).IsEqualTo(0);
        await Assert.That(Throws<ObjectDisposedException>(() =>
            verifier.AppendEntry(0, fixture.FirstEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsChangedHeaderAndHeaderHmac()
    {
        using var fixture = new VoucherFixture();
        byte[] changedHeader = fixture.CreateHeaderTag(deviceInfo: "changed device");
        byte[] changedHmacBytes = fixture.HeaderHmac.Value;
        changedHmacBytes[^1] ^= 0x01;
        byte[] changedHmac = new FdoHashValue(
            fixture.HmacAlgorithm, changedHmacBytes).Encode().ToArray();
        using var withChangedHeader = new FdoOwnershipVoucherChainVerifier(
            changedHeader, fixture.EncodedHeaderHmac, 2);
        using var withChangedHmac = new FdoOwnershipVoucherChainVerifier(
            fixture.HeaderTag, changedHmac, 2);

        await Assert.That(Throws<CryptographicException>(() => withChangedHeader.CheckDeviceCredentials(
            fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => withChangedHmac.CheckDeviceCredentials(
            fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            withChangedHeader.AppendEntry(0, fixture.FirstEntry))).IsTrue();
    }

    [Test]
    public async Task RequiresDeviceCredentialsAndAllEntriesBeforeDeviceCompletion()
    {
        using var fixture = new VoucherFixture();
        using FdoOwnershipVoucherChainVerifier unanchored = fixture.CreateVerifier();
        unanchored.AppendEntry(0, fixture.FirstEntry);
        unanchored.AppendEntry(1, fixture.SecondEntry);
        using FdoOwnershipVoucherChainVerifier incomplete = fixture.CreateVerifier();
        incomplete.CheckDeviceCredentials(
            fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret);
        incomplete.AppendEntry(0, fixture.FirstEntry);

        await Assert.That(Throws<InvalidOperationException>(() =>
            unanchored.CompleteDeviceChecks(fixture.FinalOwnerKey))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            incomplete.CompleteDeviceChecks(fixture.FinalOwnerKey))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            incomplete.AppendEntry(1, fixture.SecondEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsReorderedModifiedAndWrongDomainEntries()
    {
        using var fixture = new VoucherFixture();
        byte[] modified = (byte[])fixture.FirstEntry.Clone();
        modified[^1] ^= 0x01;
        byte[] wrongDomain = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer, fixture.FirstOwnerKey,
            operation: FdoSignatureOperation.TO0OwnerSign).Entry;

        await Assert.That(RejectsFirstEntry(fixture, fixture.SecondEntry)).IsTrue();
        await Assert.That(RejectsFirstEntry(fixture, modified)).IsTrue();
        await Assert.That(RejectsFirstEntry(fixture, wrongDomain)).IsTrue();

        using FdoOwnershipVoucherChainVerifier outOfSequence = fixture.CreateVerifier();
        await Assert.That(Throws<InvalidOperationException>(() =>
            outOfSequence.AppendEntry(1, fixture.FirstEntry))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            outOfSequence.AppendEntry(0, fixture.FirstEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsWrongHeaderInfoPayloadOnlyHashAndChangedPreviousHashAlgorithm()
    {
        using var fixture = new VoucherFixture();
        byte[] wrongHeaderInfo = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer, fixture.FirstOwnerKey,
            headerInfo: new byte[16]).Entry;
        byte[] payloadOnly = fixture.CreateEntry(
            fixture.FirstPayload, fixture.FirstOwner, fixture.FinalOwnerKey).Entry;
        byte[] changedAlgorithm = fixture.CreateEntry(
            fixture.FirstEntry, fixture.FirstOwner, fixture.FinalOwnerKey,
            previousAlgorithm: FdoHashAlgorithm.Sha384).Entry;

        await Assert.That(RejectsFirstEntry(fixture, wrongHeaderInfo)).IsTrue();
        await Assert.That(RejectsSecondEntry(fixture, payloadOnly)).IsTrue();
        await Assert.That(RejectsSecondEntry(fixture, changedAlgorithm)).IsTrue();
    }

    [Test]
    public async Task RejectsChangedOwnerKeyTypeAndWrongAdvertisedOwner()
    {
        using var fixture = new VoucherFixture();
        using ECDsa otherCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        byte[] differentType = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer,
            new FdoPublicKeyCodec().Encode(otherCurve)).Entry;
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();
        verifier.AppendEntry(0, fixture.FirstEntry);
        verifier.AppendEntry(1, fixture.SecondEntry);

        await Assert.That(RejectsFirstEntry(fixture, differentType)).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            verifier.CompleteInternalConsistency(fixture.FirstOwnerKey))).IsTrue();
    }

    [Test]
    [Arguments(2048, false)]
    [Arguments(2048, true)]
    [Arguments(3072, false)]
    public async Task VerifiesRsaVoucherEntriesWithConsistentAlgorithms(int keySize, bool restricted)
    {
        using var fixture = new VoucherFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA firstOwner = RSA.Create(keySize);
        using RSA finalOwner = RSA.Create(keySize);
        var keys = new FdoPublicKeyCodec();
        byte[] header = fixture.CreateHeaderTag(manufacturerKey: keys.EncodeRsa(manufacturer, restricted));
        ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
        byte[] hmac = FdoHashValue.ComputeHmac(
            fixture.HmacAlgorithm, fixture.Secret, headerContents.Span).Encode().ToArray();
        byte[] firstKey = keys.EncodeRsa(firstOwner, restricted).ToArray();
        byte[] finalKey = keys.EncodeRsa(finalOwner, restricted).ToArray();
        byte[] initialInput = [.. headerContents.Span, .. hmac];
        byte[] first = fixture.CreateEntry(initialInput, manufacturer, firstKey).Entry;
        byte[] second = fixture.CreateEntry(first, firstOwner, finalKey).Entry;
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 2);

        verifier.AppendEntry(0, first);
        verifier.AppendEntry(1, second);
        verifier.CompleteInternalConsistency(finalKey);

        await Assert.That(Throws<ObjectDisposedException>(() => verifier.AppendEntry(2, second))).IsTrue();
    }

    [Test]
    [Arguments(2048, 3072)]
    [Arguments(3072, 2048)]
    public async Task RejectsRsaSizeChangesEvenWhenTheFdoKeyTypeIsUnchanged(int currentSize, int nextSize)
    {
        using var fixture = new VoucherFixture();
        using RSA manufacturer = RSA.Create(currentSize);
        using RSA nextOwner = RSA.Create(nextSize);
        var keys = new FdoPublicKeyCodec();
        byte[] header = fixture.CreateHeaderTag(manufacturerKey: keys.EncodeRsa(manufacturer));
        ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
        byte[] hmac = FdoHashValue.ComputeHmac(
            fixture.HmacAlgorithm, fixture.Secret, headerContents.Span).Encode().ToArray();
        byte[] initialInput = [.. headerContents.Span, .. hmac];
        byte[] entry = fixture.CreateEntry(initialInput, manufacturer, keys.EncodeRsa(nextOwner)).Entry;
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 1);

        await Assert.That(Throws<CryptographicException>(() => verifier.AppendEntry(0, entry))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => verifier.AppendEntry(0, entry))).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectsAChangeBetweenRestrictedAndUnrestrictedRsaTypes(bool manufacturerRestricted)
    {
        using var fixture = new VoucherFixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA nextOwner = RSA.Create(2048);
        var keys = new FdoPublicKeyCodec();
        byte[] header = fixture.CreateHeaderTag(
            manufacturerKey: keys.EncodeRsa(manufacturer, manufacturerRestricted));
        ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
        byte[] hmac = FdoHashValue.ComputeHmac(
            fixture.HmacAlgorithm, fixture.Secret, headerContents.Span).Encode().ToArray();
        byte[] initialInput = [.. headerContents.Span, .. hmac];
        byte[] entry = fixture.CreateEntry(
            initialInput, manufacturer, keys.EncodeRsa(nextOwner, !manufacturerRestricted)).Entry;
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 1);

        await Assert.That(Throws<CryptographicException>(() => verifier.AppendEntry(0, entry))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => verifier.AppendEntry(0, entry))).IsTrue();
    }

    [Test]
    public async Task RejectsAnRsaEntrySignedWithTheWrongAlgorithm()
    {
        using var fixture = new VoucherFixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA wrongSigner = RSA.Create(3072);
        var keys = new FdoPublicKeyCodec();
        byte[] header = fixture.CreateHeaderTag(manufacturerKey: keys.EncodeRsa(manufacturer));
        ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
        byte[] hmac = FdoHashValue.ComputeHmac(
            fixture.HmacAlgorithm, fixture.Secret, headerContents.Span).Encode().ToArray();
        byte[] initialInput = [.. headerContents.Span, .. hmac];
        byte[] entry = fixture.CreateEntry(initialInput, wrongSigner, keys.EncodeRsa(manufacturer)).Entry;
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 1);

        await Assert.That(Throws<CborContentException>(() => verifier.AppendEntry(0, entry))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => verifier.AppendEntry(0, entry))).IsTrue();
    }

    [Test]
    public async Task AcceptsAValidExtraMapAndRejectsAnInvalidEmbeddedExtra()
    {
        using var fixture = new VoucherFixture();
        byte[] valid = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer, fixture.FirstOwnerKey,
            extra: [0xA1, 0x01, 0x41, 0xAA]).Entry;
        byte[] invalid = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer, fixture.FirstOwnerKey,
            extra: [0x80]).Entry;
        using var accepted = new FdoOwnershipVoucherChainVerifier(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 1);
        using var rejected = new FdoOwnershipVoucherChainVerifier(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 1);
        accepted.AppendEntry(0, valid);
        accepted.CompleteInternalConsistency(fixture.FirstOwnerKey);

        await Assert.That(Throws<CborContentException>(() => rejected.AppendEntry(0, invalid))).IsTrue();
    }

    [Test]
    public async Task MatchesTheDeviceCertificateContentsAndOwnsTheCheckedEncoding()
    {
        using var fixture = new VoucherFixture();
        byte[] supplied = (byte[])fixture.EncodedCertificateChain.Clone();
        string expected = Convert.ToHexString(supplied);
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();

        ReadOnlyMemory<byte> checkedChain = verifier.CheckDeviceCertificateChain(supplied);
        Array.Fill(supplied, (byte)0);
        verifier.AppendEntry(0, fixture.FirstEntry);
        verifier.AppendEntry(1, fixture.SecondEntry);
        verifier.CompleteInternalConsistency(fixture.FinalOwnerKey);

        await Assert.That(Convert.ToHexString(checkedChain.Span)).IsEqualTo(expected);
    }

    [Test]
    public async Task RejectsChangedReorderedAndMalformedDeviceCertificateChains()
    {
        using var fixture = new VoucherFixture();
        using FdoOwnershipVoucherChainVerifier changed = fixture.CreateVerifier();
        using FdoOwnershipVoucherChainVerifier reordered = fixture.CreateVerifier();
        using FdoOwnershipVoucherChainVerifier malformed = fixture.CreateVerifier();
        byte[] changedChain = (byte[])fixture.EncodedCertificateChain.Clone();
        changedChain[^1] ^= 0x01;

        await Assert.That(Throws<CryptographicException>(() =>
            changed.CheckDeviceCertificateChain(changedChain))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            reordered.CheckDeviceCertificateChain(Convert.FromHexString("8241024101")))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            malformed.CheckDeviceCertificateChain(Convert.FromHexString("F6")))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            changed.AppendEntry(0, fixture.FirstEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsNonV200HeadersAndInvalidEntryCounts()
    {
        using var fixture = new VoucherFixture();

        await Assert.That(Throws<CborContentException>(() => _ = new FdoOwnershipVoucherChainVerifier(
            fixture.CreateHeaderTag(version: 100), fixture.EncodedHeaderHmac, 2))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => _ = new FdoOwnershipVoucherChainVerifier(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, -1))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => _ = new FdoOwnershipVoucherChainVerifier(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 256))).IsTrue();
    }

    [Test]
    public async Task OwnsTheHeaderAndEntriesWhileCheckingTheChain()
    {
        using var fixture = new VoucherFixture();
        byte[] header = (byte[])fixture.HeaderTag.Clone();
        byte[] hmac = (byte[])fixture.EncodedHeaderHmac.Clone();
        byte[] firstEntry = (byte[])fixture.FirstEntry.Clone();
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 2);
        Array.Fill(header, (byte)0);
        Array.Fill(hmac, (byte)0);
        verifier.CheckDeviceCredentials(
            fixture.Guid, fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret);
        verifier.AppendEntry(0, firstEntry);
        Array.Fill(firstEntry, (byte)0);
        verifier.AppendEntry(1, fixture.SecondEntry);
        verifier.CompleteDeviceChecks(fixture.FinalOwnerKey);

        await Assert.That(Throws<ObjectDisposedException>(() =>
            verifier.CompleteDeviceChecks(fixture.FinalOwnerKey))).IsTrue();
    }

    [Test]
    public async Task VerifiesAnIndependentlySignedVoucherWithoutEstablishingDeviceTrust()
    {
        byte[] header = Convert.FromBase64String(
            "WMmGGMhQAAECAwQFBgcICQoLDA0OD4GBggVPbnJ2c2VydmVyLmxvY2FseBtJbmRlcGVuZGVudCBGRE8gMi4wIGZpeHR1cmWDCgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM7X7f98vUcP4MWsmt1amPdONRgjGqKaTP8awqoajAMVFp6nSs7M4SdNB6kbgu3YMFPXiSR4QN+9zV919bJUlN+CL1ggDk+pWq7FaDid8XtkmZt+OWuIRZAOKObowrLXz2muvR8=");
        byte[] hmac = Convert.FromBase64String(
            "ggVYIGwqgl9dIPCzZcQNIHDAGPHY1+bU2nlVoHDscD+I3Jb3");
        byte[] first = Convert.FromBase64String(
            "0oRDoQEmoFiqhIIvWCCdo7g7aseqrk/uwcdZWByV80bbxZq+7AQikD34hlsOV4IvWCAWTOmWwNJeVV42qkyHjkcSy+DnoGcM8DS0/+0bmcqkKfaDCgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABId0kjAnxvXjB4z7U6r/zUulwEZsxxOn2tpriMa2tS0wK1or8v0s71wPgCTnuij6q9EtITz9/Fz1QUu2MAV5qu9YQHWirrKXwh1kLdVCGiVNv3yhjpYEpuAL8HxRXHFOAAsXk0wcl/4qLxtceRjgugsSYCw3XD/7eoeMq3H3gCGhCwQ=");
        byte[] second = Convert.FromBase64String(
            "0oRDoQEmoFiqhIIvWCDZjxD9Aw9bdoZr5TXrAbcyCXllwbmcVFeXhnLqNLec6YIvWCAWTOmWwNJeVV42qkyHjkcSy+DnoGcM8DS0/+0bmcqkKfaDCgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHnlJKf4pu+2Wd6Gqt7K2gxUqqPTbNRLE81rASzoLsYWWM/Ob//b6Jf0ofbrqjBPizuEgpN874DQ2oQB3JCU7BRYQN7lZ25RRulfhobanCnkTFm+wMgbROdwDdxa1yuLx0pQnnrl2h0r4KQKajlH2VkENM2B4+fuUoonXEVU4X1r41Q=");
        byte[] owner = Convert.FromBase64String(
            "gwoBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR55SSn+KbvtlnehqreytoMVKqj02zUSxPNawEs6C7GFljPzm//2+iX9KH266owT4s7hIKTfO+A0NqEAdyQlOwU");
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac, 2);
        verifier.AppendEntry(0, first);
        verifier.AppendEntry(1, second);
        verifier.CompleteInternalConsistency(owner);

        await Assert.That(Throws<ObjectDisposedException>(() => verifier.AppendEntry(2, second))).IsTrue();
    }

    private static bool RejectsCredentials(
        VoucherFixture fixture, byte[] guid, FdoHashValue manufacturerHash,
        FdoHashAlgorithm hmacAlgorithm, byte[] secret)
    {
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();
        return Throws<CryptographicException>(() => verifier.CheckDeviceCredentials(
            guid, manufacturerHash, hmacAlgorithm, secret))
            && Throws<ObjectDisposedException>(() => verifier.AppendEntry(0, fixture.FirstEntry));
    }

    private static bool RejectsFirstEntry(VoucherFixture fixture, byte[] entry)
    {
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();
        return Throws<CryptographicException>(() => verifier.AppendEntry(0, entry))
            && Throws<ObjectDisposedException>(() => verifier.AppendEntry(0, fixture.FirstEntry));
    }

    private static bool RejectsSecondEntry(VoucherFixture fixture, byte[] entry)
    {
        using FdoOwnershipVoucherChainVerifier verifier = fixture.CreateVerifier();
        verifier.AppendEntry(0, fixture.FirstEntry);
        return Throws<CryptographicException>(() => verifier.AppendEntry(1, entry))
            && Throws<ObjectDisposedException>(() => verifier.AppendEntry(1, fixture.SecondEntry));
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    internal sealed class VoucherFixture : IDisposable
    {
        private readonly FdoPublicKeyCodec _keys = new();
        private readonly FdoCoseSign1Codec _signatures = new();
        private readonly FdoHashAlgorithm _previousAlgorithm;
        private readonly FdoHashAlgorithm _headerInfoAlgorithm;

        public VoucherFixture(
            int curveSize = 256,
            FdoHashAlgorithm hmacAlgorithm = FdoHashAlgorithm.HmacSha256,
            FdoHashAlgorithm previousAlgorithm = FdoHashAlgorithm.Sha256,
            FdoHashAlgorithm headerInfoAlgorithm = FdoHashAlgorithm.Sha384,
            ReadOnlyMemory<byte>? encodedCertificateChain = null)
        {
            ECCurve curve = curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384;
            Manufacturer = ECDsa.Create(curve);
            FirstOwner = ECDsa.Create(curve);
            FinalOwner = ECDsa.Create(curve);
            HmacAlgorithm = hmacAlgorithm;
            _previousAlgorithm = previousAlgorithm;
            _headerInfoAlgorithm = headerInfoAlgorithm;
            Guid = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
            Secret = new byte[FdoDeviceHmacSecretPolicy.GetRequiredLength(hmacAlgorithm)];
            for (int i = 0; i < Secret.Length; i++)
            {
                Secret[i] = (byte)(i + 1);
            }

            ManufacturerKey = _keys.Encode(Manufacturer).ToArray();
            FirstOwnerKey = _keys.Encode(FirstOwner).ToArray();
            FinalOwnerKey = _keys.Encode(FinalOwner).ToArray();
            ManufacturerHash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, ManufacturerKey);
            EncodedCertificateChain = encodedCertificateChain is ReadOnlyMemory<byte> suppliedChain
                ? suppliedChain.ToArray()
                : Convert.FromHexString("8241014102");
            Header = CreateHeader();
            HeaderTag = Wrap(Header);
            HeaderHmac = FdoHashValue.ComputeHmac(HmacAlgorithm, Secret, Header);
            EncodedHeaderHmac = HeaderHmac.Encode().ToArray();
            InitialHashInput = Combine(Header, EncodedHeaderHmac);
            (FirstEntry, FirstPayload) = CreateEntry(InitialHashInput, Manufacturer, FirstOwnerKey);
            (SecondEntry, _) = CreateEntry(FirstEntry, FirstOwner, FinalOwnerKey);
        }

        public ECDsa Manufacturer { get; }
        public ECDsa FirstOwner { get; }
        public ECDsa FinalOwner { get; }
        public byte[] Guid { get; }
        public byte[] Secret { get; }
        public FdoHashAlgorithm HmacAlgorithm { get; }
        public byte[] ManufacturerKey { get; }
        public byte[] FirstOwnerKey { get; }
        public byte[] FinalOwnerKey { get; }
        public FdoHashValue ManufacturerHash { get; }
        public byte[] EncodedCertificateChain { get; }
        public byte[] Header { get; }
        public byte[] HeaderTag { get; }
        public FdoHashValue HeaderHmac { get; }
        public byte[] EncodedHeaderHmac { get; }
        public byte[] InitialHashInput { get; }
        public byte[] FirstEntry { get; }
        public byte[] FirstPayload { get; }
        public byte[] SecondEntry { get; }

        public FdoOwnershipVoucherChainVerifier CreateVerifier() =>
            new(HeaderTag, EncodedHeaderHmac, 2);

        public byte[] CreateHeaderTag(
            int version = 200,
            string deviceInfo = "device-ä",
            ReadOnlyMemory<byte>? manufacturerKey = null) =>
            Wrap(CreateHeader(version, deviceInfo, manufacturerKey));

        public (byte[] Entry, byte[] Payload) CreateEntry(
            ReadOnlyMemory<byte> previousInput,
            AsymmetricAlgorithm signer,
            ReadOnlyMemory<byte> nextKey,
            FdoSignatureOperation operation = FdoSignatureOperation.OVEntry,
            FdoHashAlgorithm? previousAlgorithm = null,
            byte[]? headerInfo = null,
            byte[]? extra = null)
        {
            byte[] info = headerInfo ?? Combine(Guid, Encoding.UTF8.GetBytes("device-ä"));
            FdoHashValue previous = FdoHashValue.ComputeDigest(
                previousAlgorithm ?? _previousAlgorithm, previousInput.Span);
            FdoHashValue headerHash = FdoHashValue.ComputeDigest(_headerInfoAlgorithm, info);
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteStartArray(4);
            writer.WriteEncodedValue(previous.Encode().Span);
            writer.WriteEncodedValue(headerHash.Encode().Span);
            if (extra is null)
            {
                writer.WriteNull();
            }
            else
            {
                writer.WriteByteString(extra);
            }

            writer.WriteEncodedValue(nextKey.Span);
            writer.WriteEndArray();
            byte[] payload = writer.Encode();
            FdoCoseSignatureAlgorithm algorithm = signer switch
            {
                ECDsa { KeySize: 256 } => FdoCoseSignatureAlgorithm.ES256,
                ECDsa { KeySize: 384 } => FdoCoseSignatureAlgorithm.ES384,
                RSA { KeySize: 2048 } => FdoCoseSignatureAlgorithm.RS256,
                RSA { KeySize: 3072 } => FdoCoseSignatureAlgorithm.RS384,
                _ => throw new ArgumentException("Unsupported fixture signing key.", nameof(signer)),
            };
            return (_signatures.Sign(operation, algorithm, signer, payload).ToArray(), payload);
        }

        public void Dispose()
        {
            Manufacturer.Dispose();
            FirstOwner.Dispose();
            FinalOwner.Dispose();
            CryptographicOperations.ZeroMemory(Secret);
        }

        private byte[] CreateHeader(
            int version = 200,
            string deviceInfo = "device-ä",
            ReadOnlyMemory<byte>? manufacturerKey = null)
        {
            var dns = new CborWriter(CborConformanceMode.Canonical);
            dns.WriteTextString("rvserver.local");
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteStartArray(6);
            writer.WriteInt32(version);
            writer.WriteByteString(Guid);
            writer.WriteStartArray(1);
            writer.WriteStartArray(1);
            writer.WriteStartArray(2);
            writer.WriteInt32(5);
            writer.WriteByteString(dns.Encode());
            writer.WriteEndArray();
            writer.WriteEndArray();
            writer.WriteEndArray();
            writer.WriteTextString(deviceInfo);
            writer.WriteEncodedValue((manufacturerKey ?? ManufacturerKey).Span);
            writer.WriteEncodedValue(new FdoCertificateChainHash().Compute(
                FdoHashAlgorithm.Sha256, EncodedCertificateChain).Encode().Span);
            writer.WriteEndArray();
            return writer.Encode();
        }

        private static byte[] Wrap(ReadOnlySpan<byte> payload)
        {
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteByteString(payload);
            return writer.Encode();
        }

        private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
        {
            byte[] result = new byte[first.Length + second.Length];
            first.CopyTo(result);
            second.CopyTo(result.AsSpan(first.Length));
            return result;
        }
    }
}
