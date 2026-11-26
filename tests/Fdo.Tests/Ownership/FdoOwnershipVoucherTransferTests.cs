using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Serialization;
using Fdo.Tests.Cryptography;
using TUnit.Core;

namespace Fdo.Tests.Ownership;

public sealed class FdoOwnershipVoucherTransferTests
{
    [Test]
    [Arguments(256)]
    [Arguments(384)]
    public async Task ExtendsAZeroEntryVoucherWithoutChangingItsEncodedFields(int curveSize)
    {
        FdoHashAlgorithm hmacAlgorithm = curveSize == 256
            ? FdoHashAlgorithm.HmacSha256 : FdoHashAlgorithm.HmacSha384;
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(curveSize, hmacAlgorithm);
        using ECDsa approvedPublicKey = ECDsa.Create(fixture.FinalOwner.ExportParameters(false));
        byte[] source = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain).ToArray();
        byte[] original = (byte[])source.Clone();

        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(
            source, fixture.Manufacturer, approvedPublicKey);

        byte[] extended = result.EncodedVoucher.ToArray();
        ReadOnlyMemory<byte> entry = result.EncodedVoucherEntries[0];
        await Assert.That(source.AsSpan().SequenceEqual(original)).IsTrue();
        await Assert.That(original[^1]).IsEqualTo((byte)0x80);
        await Assert.That(extended.Length).IsEqualTo(original.Length + entry.Length);
        await Assert.That(extended.AsSpan(0, original.Length - 1)
            .SequenceEqual(original.AsSpan(0, original.Length - 1))).IsTrue();
        await Assert.That(extended[original.Length - 1]).IsEqualTo((byte)0x81);
        await Assert.That(extended.AsSpan(original.Length).SequenceEqual(entry.Span)).IsTrue();
        await Assert.That(result.EncodedVoucherHeaderTag.Span.SequenceEqual(fixture.HeaderTag)).IsTrue();
        await Assert.That(result.EncodedVoucherHeaderHmac.Span.SequenceEqual(fixture.EncodedHeaderHmac)).IsTrue();
        await Assert.That(result.EncodedDeviceCertificateChain.Span.SequenceEqual(fixture.EncodedCertificateChain)).IsTrue();

        FdoCoseSignatureAlgorithm signatureAlgorithm = curveSize == 256
            ? FdoCoseSignatureAlgorithm.ES256 : FdoCoseSignatureAlgorithm.ES384;
        ReadOnlyMemory<byte> payload = new FdoCoseSign1Codec().Verify(
            FdoSignatureOperation.OVEntry, signatureAlgorithm, fixture.Manufacturer, entry);
        var reader = new CborReader(payload, CborConformanceMode.Canonical);
        await Assert.That(reader.ReadStartArray()).IsEqualTo(4);
        FdoHashValue previousHash = FdoHashValue.Decode(reader.ReadEncodedValue());
        FdoHashValue headerInfoHash = FdoHashValue.Decode(reader.ReadEncodedValue());
        reader.ReadNull();
        ReadOnlyMemory<byte> nextKey = reader.ReadEncodedValue();
        reader.ReadEndArray();

        byte[] headerInfo = new byte[fixture.Guid.Length + Encoding.UTF8.GetByteCount("device-\u00e4")];
        fixture.Guid.CopyTo(headerInfo, 0);
        Encoding.UTF8.GetBytes("device-\u00e4", headerInfo.AsSpan(fixture.Guid.Length));
        FdoHashAlgorithm digest = curveSize == 256 ? FdoHashAlgorithm.Sha256 : FdoHashAlgorithm.Sha384;
        byte[] expectedPreviousHash = curveSize == 256
            ? SHA256.HashData(fixture.InitialHashInput) : SHA384.HashData(fixture.InitialHashInput);
        byte[] expectedHeaderInfoHash = curveSize == 256
            ? SHA256.HashData(headerInfo) : SHA384.HashData(headerInfo);
        await Assert.That(previousHash.Algorithm).IsEqualTo(digest);
        await Assert.That(previousHash.Value.AsSpan().SequenceEqual(expectedPreviousHash)).IsTrue();
        await Assert.That(headerInfoHash.Algorithm).IsEqualTo(digest);
        await Assert.That(headerInfoHash.Value.AsSpan().SequenceEqual(expectedHeaderInfoHash)).IsTrue();
        await Assert.That(nextKey.Span.SequenceEqual(fixture.FinalOwnerKey)).IsTrue();

        source.AsSpan().Clear();
        ClearExposedMemory(result.EncodedVoucher);
        ClearExposedMemory(result.EncodedVoucherHeaderTag);
        ClearExposedMemory(result.EncodedVoucherHeaderHmac);
        ClearExposedMemory(result.EncodedDeviceCertificateChain);
        ClearExposedMemory(result.EncodedVoucherEntries[0]);
        await Assert.That(result.EncodedVoucher.Span.SequenceEqual(extended)).IsTrue();
        await Assert.That(result.EncodedVoucherHeaderTag.Span.SequenceEqual(fixture.HeaderTag)).IsTrue();
        await Assert.That(result.EncodedVoucherHeaderHmac.Span.SequenceEqual(fixture.EncodedHeaderHmac)).IsTrue();
        await Assert.That(result.EncodedDeviceCertificateChain.Span.SequenceEqual(fixture.EncodedCertificateChain)).IsTrue();
        await Assert.That(result.EncodedVoucherEntries[0].Span.SequenceEqual(entry.Span)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectsAWrongOrPublicOnlyCurrentOwner(bool publicOnly)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using ECDsa candidate = publicOnly
            ? ECDsa.Create(fixture.Manufacturer.ExportParameters(false))
            : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, candidate, fixture.FinalOwner))).IsTrue();
    }

    [Test]
    public async Task RejectsAProviderWhoseSignatureDoesNotMatchItsReportedOwnerKey()
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using var signer = new MismatchedSigningKey(fixture.Manufacturer, fixture.FirstOwner);
        ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, signer, fixture.FinalOwner))).IsTrue();
        await Assert.That(signer.SignCalls).IsEqualTo(1);
        await Assert.That(signer.PrivateParametersRequested).IsFalse();
    }

    [Test]
    public async Task DoesNotRequireOrAuthenticateTheDeviceHmac()
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        var unverifiedHmac = new FdoHashValue(fixture.HmacAlgorithm, new byte[32]);
        ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, unverifiedHmac, fixture.EncodedCertificateChain);

        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(
            voucher, fixture.Manufacturer, fixture.FinalOwner);

        await Assert.That(unverifiedHmac.MatchesHmac(
            fixture.HmacAlgorithm, fixture.Secret, fixture.Header)).IsFalse();
        await Assert.That(result.EncodedVoucherHeaderHmac.Span
            .SequenceEqual(unverifiedHmac.Encode().Span)).IsTrue();
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            result.EncodedVoucherHeaderTag, result.EncodedVoucherHeaderHmac, 1);
        verifier.AppendEntry(0, result.EncodedVoucherEntries[0]);
        verifier.CompleteInternalConsistency(fixture.FinalOwnerKey);
    }

    [Test]
    public async Task RejectsAPreviousOwnerOrMismatchedCertificateChain()
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);
        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(
            voucher, fixture.Manufacturer, fixture.FinalOwner);
        byte[] changedChain = (byte[])fixture.EncodedCertificateChain.Clone();
        changedChain[^1] ^= 1;
        ReadOnlyMemory<byte> mismatched = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, changedChain);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(result.EncodedVoucher, fixture.Manufacturer, fixture.FirstOwner))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(mismatched, fixture.Manufacturer, fixture.FinalOwner))).IsTrue();
    }

    [Test]
    public async Task RejectsAChangedOwnerKeyType()
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using ECDsa otherCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        ReadOnlyMemory<byte> voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, fixture.Manufacturer, otherCurve))).IsTrue();
    }

    [Test]
    [Arguments("version")]
    [Arguments("noncanonical")]
    [Arguments("digest")]
    public async Task RejectsInvalidVoucherVersionOrHeaderHmac(string scenario)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        FdoHashValue hash = scenario == "digest"
            ? FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, fixture.Header)
            : fixture.HeaderHmac;
        byte[] voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, hash, fixture.EncodedCertificateChain).ToArray();
        if (scenario == "version")
        {
            voucher[2]++;
        }
        else if (scenario == "noncanonical")
        {
            byte[] noncanonical = new byte[voucher.Length + 1];
            noncanonical[0] = voucher[0];
            noncanonical[1] = 0x19;
            noncanonical[2] = 0x00;
            noncanonical[3] = voucher[2];
            voucher.AsSpan(3).CopyTo(noncanonical.AsSpan(4));
            voucher = noncanonical;
        }

        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, fixture.Manufacturer, fixture.FinalOwner))).IsTrue();
    }

    [Test]
    public async Task RejectsAnExtensionThatWouldExceedTheVoucherByteLimit()
    {
        using var sizing = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        int certificateLength = ushort.MaxValue - sizing.HeaderTag.Length - sizing.EncodedHeaderHmac.Length - 7;
        ReadOnlyMemory<byte> chain = new FdoX5ChainCodec().Encode(
            new ReadOnlyMemory<byte>[] { new byte[certificateLength] });
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(encodedCertificateChain: chain);
        byte[] voucher = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain).ToArray();

        await Assert.That(voucher.Length).IsEqualTo((int)ushort.MaxValue);
        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, fixture.Manufacturer, fixture.FinalOwner))).IsTrue();
    }

    [Test]
    [Arguments(256)]
    [Arguments(384)]
    public async Task RepeatedEcTransfersPreserveAllPriorFieldsAndHashTheExactTaggedEntry(int curveSize)
    {
        FdoHashAlgorithm hmac = curveSize == 256 ? FdoHashAlgorithm.HmacSha256 : FdoHashAlgorithm.HmacSha384;
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(curveSize, hmac);
        using ECDsa nextOwner = ECDsa.Create(curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        ReadOnlyMemory<byte> zero = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);
        FdoTransferredOwnershipVoucher first = FdoOwnershipVoucherTransfer.Extend(
            zero, fixture.Manufacturer, fixture.FirstOwner);
        FdoTransferredOwnershipVoucher second = FdoOwnershipVoucherTransfer.Extend(
            first.EncodedVoucher, fixture.FirstOwner, fixture.FinalOwner);
        byte[] source = second.EncodedVoucher.ToArray();
        byte[] before = (byte[])source.Clone();

        FdoTransferredOwnershipVoucher third = FdoOwnershipVoucherTransfer.Extend(
            source, fixture.FinalOwner, nextOwner);

        await Assert.That(source.AsSpan().SequenceEqual(before)).IsTrue();
        await Assert.That(third.EncodedVoucherEntries.Count).IsEqualTo(3);
        await Assert.That(third.EncodedVoucherEntries[0].Span.SequenceEqual(first.EncodedVoucherEntries[0].Span)).IsTrue();
        await Assert.That(third.EncodedVoucherEntries[1].Span.SequenceEqual(second.EncodedVoucherEntries[1].Span)).IsTrue();
        await Assert.That(third.EncodedVoucherHeaderTag.Span.SequenceEqual(fixture.HeaderTag)).IsTrue();
        await Assert.That(third.EncodedVoucherHeaderHmac.Span.SequenceEqual(fixture.EncodedHeaderHmac)).IsTrue();
        await Assert.That(third.EncodedDeviceCertificateChain.Span.SequenceEqual(fixture.EncodedCertificateChain)).IsTrue();
        await Assert.That(third.EncodedVoucher.Span.SequenceEqual(EncodeVoucher(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, fixture.EncodedCertificateChain, third.EncodedVoucherEntries)))
            .IsTrue();
        FdoCoseSignatureAlgorithm algorithm = curveSize == 256
            ? FdoCoseSignatureAlgorithm.ES256 : FdoCoseSignatureAlgorithm.ES384;
        ReadOnlyMemory<byte> payload = new FdoCoseSign1Codec().Verify(
            FdoSignatureOperation.OVEntry, algorithm, fixture.FinalOwner, third.EncodedVoucherEntries[2]);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        reader.ReadStartArray();
        FdoHashValue previous = FdoHashValue.Decode(reader.ReadEncodedValue());
        byte[] expected = curveSize == 256
            ? SHA256.HashData(second.EncodedVoucherEntries[1].Span)
            : SHA384.HashData(second.EncodedVoucherEntries[1].Span);
        await Assert.That(previous.Value.AsSpan().SequenceEqual(expected)).IsTrue();
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            third.EncodedVoucherHeaderTag, third.EncodedVoucherHeaderHmac, 3);
        for (int i = 0; i < 3; i++)
        {
            verifier.AppendEntry(i, third.EncodedVoucherEntries[i]);
        }
        verifier.CompleteInternalConsistency(new FdoPublicKeyCodec().Encode(nextOwner));

        byte[] retained = third.EncodedVoucher.ToArray();
        byte[] retainedLastEntry = third.EncodedVoucherEntries[2].ToArray();
        source.AsSpan().Clear();
        foreach (ReadOnlyMemory<byte> entry in third.EncodedVoucherEntries)
        {
            ClearExposedMemory(entry);
        }
        await Assert.That(third.EncodedVoucher.Span.SequenceEqual(retained)).IsTrue();
        await Assert.That(third.EncodedVoucherEntries[0].Span.SequenceEqual(first.EncodedVoucherEntries[0].Span)).IsTrue();
        await Assert.That(third.EncodedVoucherEntries[1].Span.SequenceEqual(second.EncodedVoucherEntries[1].Span)).IsTrue();
        await Assert.That(third.EncodedVoucherEntries[2].Span.SequenceEqual(retainedLastEntry)).IsTrue();
    }

    [Test]
    [Arguments(2048, true)]
    [Arguments(2048, false)]
    [Arguments(3072, false)]
    public async Task RepeatedRsaTransfersRetainPriorEntriesAndBindTheFinalOwner(int keySize, bool restricted)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA firstOwner = RSA.Create(keySize);
        using RSA finalOwner = RSA.Create(keySize);
        var keys = new FdoPublicKeyCodec();
        byte[] header = fixture.CreateHeaderTag(manufacturerKey: keys.EncodeRsa(manufacturer, restricted));
        FdoHashValue hmac = FdoHashValue.ComputeHmac(
            fixture.HmacAlgorithm, fixture.Secret, new FdoCborCodec().ReadByteStringPayload(header).Span);
        ReadOnlyMemory<byte> zero = FdoInitializationFields.CreateVoucher(header, hmac, fixture.EncodedCertificateChain);
        FdoTransferredOwnershipVoucher first = FdoOwnershipVoucherTransfer.ExtendRsa(zero, manufacturer, firstOwner);

        FdoTransferredOwnershipVoucher second = FdoOwnershipVoucherTransfer.ExtendRsa(
            first.EncodedVoucher, firstOwner, finalOwner);

        await Assert.That(second.EncodedVoucherEntries.Count).IsEqualTo(2);
        await Assert.That(second.EncodedVoucherEntries[0].Span.SequenceEqual(first.EncodedVoucherEntries[0].Span)).IsTrue();
        await Assert.That(second.EncodedVoucherHeaderTag.Span.SequenceEqual(header)).IsTrue();
        await Assert.That(second.EncodedVoucherHeaderHmac.Span.SequenceEqual(hmac.Encode().Span)).IsTrue();
        await Assert.That(second.EncodedDeviceCertificateChain.Span.SequenceEqual(fixture.EncodedCertificateChain)).IsTrue();
        FdoCoseSignatureAlgorithm algorithm = keySize == 2048
            ? FdoCoseSignatureAlgorithm.RS256 : FdoCoseSignatureAlgorithm.RS384;
        ReadOnlyMemory<byte> payload = new FdoCoseSign1Codec().Verify(
            FdoSignatureOperation.OVEntry, algorithm, firstOwner, second.EncodedVoucherEntries[1]);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        reader.ReadStartArray();
        FdoHashValue previous = FdoHashValue.Decode(reader.ReadEncodedValue());
        await Assert.That(previous.Value.AsSpan().SequenceEqual(SHA256.HashData(first.EncodedVoucherEntries[0].Span)))
            .IsTrue();
        using var verifier = new FdoOwnershipVoucherChainVerifier(header, hmac.Encode(), 2);
        verifier.AppendEntry(0, second.EncodedVoucherEntries[0]);
        verifier.AppendEntry(1, second.EncodedVoucherEntries[1]);
        verifier.CompleteInternalConsistency(keys.EncodeRsa(finalOwner, restricted));
        await Assert.That(Throws<CryptographicException>(() => FdoOwnershipVoucherTransfer.ExtendRsa(
            second.EncodedVoucher, manufacturer, firstOwner))).IsTrue();
        using RSA differentSize = RSA.Create(keySize == 2048 ? 3072 : 2048);
        await Assert.That(Throws<CryptographicException>(() => FdoOwnershipVoucherTransfer.ExtendRsa(
            second.EncodedVoucher, finalOwner, differentSize))).IsTrue();
    }

    [Test]
    [Arguments(5, -43)]
    [Arguments(6, -16)]
    public async Task RetainsVerifiedEntryHashAlgorithmAndOpaqueSignedExtra(
        int hmacAlgorithm, int entryAlgorithm)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(
            hmacAlgorithm: (FdoHashAlgorithm)hmacAlgorithm, previousAlgorithm: (FdoHashAlgorithm)entryAlgorithm);
        using ECDsa nextOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] first = fixture.CreateEntry(
            fixture.InitialHashInput, fixture.Manufacturer, fixture.FirstOwnerKey,
            extra: Convert.FromHexString("A118014100")).Entry;
        byte[] second = fixture.CreateEntry(first, fixture.FirstOwner, fixture.FinalOwnerKey).Entry;
        byte[] source = EncodeVoucher(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, fixture.EncodedCertificateChain, [first, second]);

        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(source, fixture.FinalOwner, nextOwner);

        await Assert.That(result.EncodedVoucherEntries[0].Span.SequenceEqual(first)).IsTrue();
        await Assert.That(result.EncodedVoucherEntries[1].Span.SequenceEqual(second)).IsTrue();
        ReadOnlyMemory<byte> payload = new FdoCoseSign1Codec().Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256,
            fixture.FinalOwner, result.EncodedVoucherEntries[2]);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        reader.ReadStartArray();
        FdoHashValue previous = FdoHashValue.Decode(reader.ReadEncodedValue());
        await Assert.That(previous.Algorithm).IsEqualTo((FdoHashAlgorithm)entryAlgorithm);
        await Assert.That(previous.MatchesDigest((FdoHashAlgorithm)entryAlgorithm, second)).IsTrue();
    }

    [Test]
    [Arguments("first-signature")]
    [Arguments("last-signature")]
    [Arguments("payload-only-hash")]
    [Arguments("header-info")]
    [Arguments("header-hmac")]
    [Arguments("certificate-chain")]
    [Arguments("reordered")]
    public async Task RejectsTamperedNonemptyVoucherBeforeSigning(string scenario)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using var signer = new MismatchedSigningKey(fixture.FinalOwner, fixture.FinalOwner);
        byte[] first = (byte[])fixture.FirstEntry.Clone();
        byte[] second = (byte[])fixture.SecondEntry.Clone();
        byte[] hmac = (byte[])fixture.EncodedHeaderHmac.Clone();
        byte[] chain = (byte[])fixture.EncodedCertificateChain.Clone();
        switch (scenario)
        {
            case "first-signature": first[^1] ^= 1; break;
            case "last-signature": second[^1] ^= 1; break;
            case "payload-only-hash":
                second = fixture.CreateEntry(fixture.FirstPayload, fixture.FirstOwner, fixture.FinalOwnerKey).Entry;
                break;
            case "header-info":
                second = fixture.CreateEntry(first, fixture.FirstOwner, fixture.FinalOwnerKey, headerInfo: [0]).Entry;
                break;
            case "header-hmac": hmac[^1] ^= 1; break;
            case "certificate-chain": chain[^1] ^= 1; break;
            case "reordered": (first, second) = (second, first); break;
            default: throw new InvalidOperationException("Unknown test scenario.");
        }
        byte[] voucher = EncodeVoucher(fixture.HeaderTag, hmac, chain, [first, second]);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, signer, fixture.Manufacturer))).IsTrue();
        await Assert.That(signer.SignCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("initial")]
    [Arguments("intermediate")]
    [Arguments("wrong")]
    [Arguments("public-only")]
    [Arguments("changed-curve")]
    [Arguments("mismatched-provider")]
    public async Task RejectsNoncurrentOrInvalidSignerForANonemptyVoucher(string scenario)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        using ECDsa wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa publicOnly = ECDsa.Create(fixture.FinalOwner.ExportParameters(false));
        using ECDsa changedCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var mismatch = new MismatchedSigningKey(fixture.FinalOwner, fixture.FirstOwner);
        ECDsa signer = scenario switch
        {
            "initial" => fixture.Manufacturer,
            "intermediate" => fixture.FirstOwner,
            "wrong" => wrong,
            "public-only" => publicOnly,
            "changed-curve" => changedCurve,
            "mismatched-provider" => mismatch,
            _ => throw new InvalidOperationException("Unknown test scenario."),
        };
        byte[] voucher = EncodeVoucher(fixture.HeaderTag, fixture.EncodedHeaderHmac,
            fixture.EncodedCertificateChain, [fixture.FirstEntry, fixture.SecondEntry]);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, signer, fixture.FirstOwner))).IsTrue();
    }

    [Test]
    [Arguments(23)]
    [Arguments(254)]
    public async Task SupportsEntryArrayHeaderGrowthAndTheFinalAllowedTransfer(int priorCount)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(
            headerInfoAlgorithm: FdoHashAlgorithm.Sha256);
        byte[] voucher = CreateRepeatedOwnerVoucher(fixture, priorCount);

        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(
            voucher, fixture.FirstOwner, fixture.FinalOwner);

        await Assert.That(result.EncodedVoucherEntries.Count).IsEqualTo(priorCount + 1);
        int growth = priorCount == 23 ? 1 : 0;
        await Assert.That(result.EncodedVoucher.Length).IsEqualTo(
            voucher.Length + result.EncodedVoucherEntries[priorCount].Length + growth);
    }

    [Test]
    [Arguments(255)]
    [Arguments(256)]
    public async Task RejectsEntryCountOverflowBeforeSigning(int priorCount)
    {
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(
            headerInfoAlgorithm: FdoHashAlgorithm.Sha256);
        using var signer = new MismatchedSigningKey(fixture.FirstOwner, fixture.FirstOwner);
        byte[] voucher = CreateRepeatedOwnerVoucher(fixture, priorCount);
        await Assert.That(voucher.Length <= ushort.MaxValue).IsTrue();

        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherTransfer.Extend(voucher, signer, fixture.FinalOwner))).IsTrue();
        await Assert.That(signer.SignCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task CountsPriorEntryBytesAtTheExtendedVoucherByteLimit(int excess)
    {
        using var sizing = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture();
        ReadOnlyMemory<byte> zero = FdoInitializationFields.CreateVoucher(
            sizing.HeaderTag, sizing.HeaderHmac, sizing.EncodedCertificateChain);
        FdoTransferredOwnershipVoucher first = FdoOwnershipVoucherTransfer.Extend(zero, sizing.Manufacturer, sizing.FirstOwner);
        FdoTransferredOwnershipVoucher second = FdoOwnershipVoucherTransfer.Extend(
            first.EncodedVoucher, sizing.FirstOwner, sizing.FinalOwner);
        int chainLength = ushort.MaxValue - second.EncodedVoucher.Length + sizing.EncodedCertificateChain.Length + excess;
        ReadOnlyMemory<byte> chain = new FdoX5ChainCodec().Encode(
            new ReadOnlyMemory<byte>[] { new byte[chainLength - 3] });
        await Assert.That(chain.Length).IsEqualTo(chainLength);
        using var fixture = new FdoOwnershipVoucherChainVerifierTests.VoucherFixture(encodedCertificateChain: chain);
        ReadOnlyMemory<byte> source = FdoInitializationFields.CreateVoucher(
            fixture.HeaderTag, fixture.HeaderHmac, fixture.EncodedCertificateChain);
        FdoTransferredOwnershipVoucher transferred = FdoOwnershipVoucherTransfer.Extend(
            source, fixture.Manufacturer, fixture.FirstOwner);
        await Assert.That(transferred.EncodedVoucher.Length + second.EncodedVoucherEntries[1].Length)
            .IsEqualTo(ushort.MaxValue + excess);
        if (excess != 0)
        {
            await Assert.That(Throws<CborContentException>(() => FdoOwnershipVoucherTransfer.Extend(
                transferred.EncodedVoucher, fixture.FirstOwner, fixture.FinalOwner))).IsTrue();
            return;
        }

        FdoTransferredOwnershipVoucher result = FdoOwnershipVoucherTransfer.Extend(
            transferred.EncodedVoucher, fixture.FirstOwner, fixture.FinalOwner);
        await Assert.That(result.EncodedVoucher.Length).IsEqualTo((int)ushort.MaxValue);
    }

    private static byte[] CreateRepeatedOwnerVoucher(
        FdoOwnershipVoucherChainVerifierTests.VoucherFixture fixture, int count)
    {
        var entries = new ReadOnlyMemory<byte>[count];
        ReadOnlyMemory<byte> previous = fixture.InitialHashInput;
        for (int i = 0; i < count; i++)
        {
            entries[i] = fixture.CreateEntry(
                previous, i == 0 ? fixture.Manufacturer : fixture.FirstOwner, fixture.FirstOwnerKey).Entry;
            previous = entries[i];
        }

        return EncodeVoucher(fixture.HeaderTag, fixture.EncodedHeaderHmac, fixture.EncodedCertificateChain, entries);
    }

    private static byte[] EncodeVoucher(
        ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> hmac, ReadOnlyMemory<byte> chain,
        IReadOnlyList<ReadOnlyMemory<byte>> entries)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteInt32(200);
        writer.WriteEncodedValue(header.Span);
        writer.WriteEncodedValue(hmac.Span);
        writer.WriteEncodedValue(chain.Span);
        writer.WriteStartArray(entries.Count);
        foreach (ReadOnlyMemory<byte> entry in entries)
        {
            writer.WriteEncodedValue(entry.Span);
        }
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        segment.AsSpan().Clear();
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

    private sealed class MismatchedSigningKey(ECDsa reportedKey, ECDsa actualSigner) : ECDsa
    {
        public int SignCalls { get; private set; }
        public bool PrivateParametersRequested { get; private set; }
        public override int KeySize
        {
            get => reportedKey.KeySize;
            set => throw new NotSupportedException();
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                PrivateParametersRequested = true;
                throw new InvalidOperationException("The private key must not be exported.");
            }

            return reportedKey.ExportParameters(false);
        }

        public override byte[] ExportSubjectPublicKeyInfo() => reportedKey.ExportSubjectPublicKeyInfo();

        public override byte[] SignHash(byte[] hash)
        {
            SignCalls++;
            return actualSigner.SignHash(hash);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature) => reportedKey.VerifyHash(hash, signature);
    }
}
