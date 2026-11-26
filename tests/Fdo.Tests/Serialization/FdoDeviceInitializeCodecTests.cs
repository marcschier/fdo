// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using AppStart = Fdo.Serialization.FdoDeviceInitializeCodec.AppStart;
using SetCredentials = Fdo.Serialization.FdoDeviceInitializeCodec.SetCredentials;

namespace Fdo.Tests.Serialization;

public sealed class FdoDeviceInitializeCodecTests
{
    private const string HeaderHex = "860050000102030405060708090A0B0C0D0E0F806080F6";
    private const string HeaderTagHex = "57" + HeaderHex;

    [Test]
    [Arguments("8341048041F6")]
    [Arguments("83410480F6")]
    public async Task MissingManufacturingInfoIsAcceptedAndWrittenAsWrappedNull(string wireHex)
    {
        var codec = new FdoDeviceInitializeCodec();
        AppStart decoded = codec.DecodeAppStart(Convert.FromHexString(wireHex));

        await Assert.That(decoded.EncodedDeviceMfgInfo.HasValue).IsFalse();
        await Assert.That(Convert.ToHexString(codec.EncodeAppStart(decoded).Span))
            .IsEqualTo("8341048041F6");
    }

    [Test]
    public async Task AppStartPreservesACompleteEmbeddedValueAndOwnsItsInputs()
    {
        var codec = new FdoDeviceInitializeCodec();
        byte[] flags = [0x85, 0x20];
        string[] vendors = ["com"];
        byte[] value = Convert.FromHexString("A1616B820102");
        var message = new AppStart(flags, vendors, value);

        byte[] encoded = codec.EncodeAppStart(message).ToArray();
        await Assert.That(Convert.ToHexString(encoded)).IsEqualTo("834285208163636F6D46A1616B820102");
        AppStart decoded = codec.DecodeAppStart(encoded);
        Array.Fill(flags, (byte)0);
        vendors[0] = "changed";
        Array.Fill(value, (byte)0);
        Array.Fill(encoded, (byte)0);

        await Assert.That(Convert.ToHexString(decoded.CapabilityFlags.Span)).IsEqualTo("8520");
        await Assert.That(decoded.VendorCapabilities.SequenceEqual(["com"])).IsTrue();
        await Assert.That(decoded.EncodedDeviceMfgInfo.HasValue).IsTrue();
        await Assert.That(Convert.ToHexString(decoded.EncodedDeviceMfgInfo!.Value.Span)).IsEqualTo("A1616B820102");
    }

    [Test]
    [Arguments("8341048000")]
    [Arguments("8341048060")]
    [Arguments("8341048080")]
    [Arguments("83410480F4")]
    [Arguments("8341048040")]
    [Arguments("83410480420000")]
    [Arguments("83410480421800")]
    [Arguments("83410480435F40FF")]
    [Arguments("8341088041F6")]
    [Arguments("834104810041F6")]
    [Arguments("82410480")]
    [Arguments("8341048041F600")]
    public async Task AppStartRejectsInvalidFieldsAndEmbeddedValues(string hex)
    {
        var codec = new FdoDeviceInitializeCodec();

        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeAppStart(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task AppStartEncodingRejectsInvalidEmbeddedValuesAndCapabilityFields()
    {
        var codec = new FdoDeviceInitializeCodec();
        var emptyValue = new AppStart(new byte[] { 0x04 }, Array.Empty<string>(), ReadOnlyMemory<byte>.Empty);
        var multipleValues = new AppStart(new byte[] { 0x04 }, Array.Empty<string>(), new byte[] { 0x00, 0x00 });
        var reserved = new AppStart(new byte[] { 0x08 }, Array.Empty<string>(), null);
        var nullVendor = new AppStart(new byte[] { 0x04 }, new string[] { null! }, null);

        await Assert.That(Throws<CborContentException>(() => codec.EncodeAppStart(emptyValue))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.EncodeAppStart(multipleValues))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.EncodeAppStart(reserved))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.EncodeAppStart(nullVendor))).IsTrue();
    }

    [Test]
    public async Task SetCredentialsKeepsTheVoucherHeaderWrapperAndOwnsItsInputs()
    {
        var codec = new FdoDeviceInitializeCodec();
        byte[] flags = [0x04];
        byte[] tag = Convert.FromHexString(HeaderTagHex);
        var message = new SetCredentials(flags, Array.Empty<string>(), tag);

        byte[] encoded = codec.EncodeSetCredentials(message).ToArray();
        await Assert.That(Convert.ToHexString(encoded)).IsEqualTo("83410480" + HeaderTagHex);
        SetCredentials decoded = codec.DecodeSetCredentials(encoded);
        Array.Fill(flags, (byte)0);
        Array.Fill(tag, (byte)0);
        Array.Fill(encoded, (byte)0);

        await Assert.That(Convert.ToHexString(decoded.CapabilityFlags.Span)).IsEqualTo("04");
        await Assert.That(Convert.ToHexString(decoded.EncodedHeaderTag.Span)).IsEqualTo(HeaderTagHex);
    }

    [Test]
    [Arguments("83410480860050000102030405060708090A0B0C0D0E0F806080F6")]
    [Arguments("8341048040")]
    [Arguments("834104804180")]
    [Arguments("834104804186")]
    [Arguments("8341048046850000000000")]
    [Arguments("83410480488600000000000000")]
    [Arguments("834104805701")]
    public async Task SetCredentialsRejectsMalformedOrUnwrappedHeaders(string hex)
    {
        var codec = new FdoDeviceInitializeCodec();

        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeSetCredentials(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task SetHmacUsesOnlyTheWrappedHeaderContents(int algorithm)
    {
        var codec = new FdoDeviceInitializeCodec();
        byte[] secret = Enumerable.Range(0, algorithm == 5 ? 32 : 64).Select(value => (byte)value).ToArray();
        byte[] header = Convert.FromHexString(HeaderHex);
        byte[] tag = Convert.FromHexString(HeaderTagHex);
        var first = new SetCredentials(new byte[] { 0x04 }, Array.Empty<string>(), tag);
        var changedFlags = new SetCredentials(new byte[] { 0x01 }, ["com"], tag);
        var type = (FdoHashAlgorithm)algorithm;
        byte[] expected = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, header)
            : HMACSHA384.HashData(secret, header);
        byte[] overMessage = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, codec.EncodeSetCredentials(first).Span)
            : HMACSHA384.HashData(secret, codec.EncodeSetCredentials(first).Span);

        FdoHashValue actual = codec.ComputeSetHmac(type, secret, first);
        FdoHashValue afterFlagChange = codec.ComputeSetHmac(type, secret, changedFlags);
        FdoHashValue decoded = codec.DecodeSetHmac(codec.EncodeSetHmac(actual));

        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(Convert.ToHexString(actual.Value) != Convert.ToHexString(overMessage)).IsTrue();
        await Assert.That(Convert.ToHexString(afterFlagChange.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(decoded.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(decoded.Value)).IsEqualTo(Convert.ToHexString(expected));
    }

    [Test]
    [Arguments(5, 0)]
    [Arguments(5, 31)]
    [Arguments(5, 33)]
    [Arguments(6, 63)]
    [Arguments(6, 65)]
    public async Task SetHmacRejectsSecretsOutsideTheDevicePolicy(int algorithm, int secretLength)
    {
        var codec = new FdoDeviceInitializeCodec();
        var credentials = new SetCredentials(
            new byte[] { 0x04 }, Array.Empty<string>(), Convert.FromHexString(HeaderTagHex));

        await Assert.That(Throws<ArgumentException>(() =>
            codec.ComputeSetHmac((FdoHashAlgorithm)algorithm, new byte[secretLength], credentials))).IsTrue();
    }

    [Test]
    public async Task SetHmacRejectsNonHmacAlgorithms()
    {
        var codec = new FdoDeviceInitializeCodec();
        var credentials = new SetCredentials(
            new byte[] { 0x04 }, Array.Empty<string>(), Convert.FromHexString(HeaderTagHex));

        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.ComputeSetHmac(FdoHashAlgorithm.Sha256, new byte[32], credentials))).IsTrue();
    }

    [Test]
    public async Task SetHmacRejectsDigestsAndInvalidBodyShapes()
    {
        var codec = new FdoDeviceInitializeCodec();
        var digest = new FdoHashValue(FdoHashAlgorithm.Sha256, new byte[32]);
        byte[] encodedDigest = [0x81, .. digest.Encode().ToArray()];

        await Assert.That(Throws<ArgumentException>(() => codec.EncodeSetHmac(digest))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeSetHmac(encodedDigest))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeSetHmac(Convert.FromHexString("80")))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeSetHmac(Convert.FromHexString("8100")))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeSetHmac(Convert.FromHexString("81820541FF")))).IsTrue();
    }

    [Test]
    public async Task DoneIsAnEmptyArrayAndRejectsOtherBodies()
    {
        var codec = new FdoDeviceInitializeCodec();

        await Assert.That(Convert.ToHexString(codec.EncodeDone().Span)).IsEqualTo("80");
        codec.DecodeDone(Convert.FromHexString("80"));
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeDone(Convert.FromHexString("81F6")))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeDone(Convert.FromHexString("F6")))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.DecodeDone(Convert.FromHexString("8000")))).IsTrue();
    }

    [Test]
    public async Task AppStartEnforcesByteItemAndEmbeddedDepthLimits()
    {
        var message = new AppStart(new byte[] { 0x04 }, Array.Empty<string>(), null);
        var withVendor = new AppStart(new byte[] { 0x04 }, ["v"], null);
        var withNestedValue = new AppStart(new byte[] { 0x04 }, Array.Empty<string>(), new byte[] { 0x81, 0x81, 0x00 });
        var byteLimited = new FdoDeviceInitializeCodec(maxEncodedBytes: 6);
        var itemLimited = new FdoDeviceInitializeCodec(maxItems: 4);
        var depthLimited = new FdoDeviceInitializeCodec(maxDepth: 2);

        await Assert.That(byteLimited.EncodeAppStart(message).Length).IsEqualTo(6);
        await Assert.That(Throws<CborContentException>(() =>
            new FdoDeviceInitializeCodec(maxEncodedBytes: 5).EncodeAppStart(message))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            byteLimited.DecodeAppStart(Convert.FromHexString("83410480421800")))).IsTrue();
        await Assert.That(itemLimited.EncodeAppStart(message).Length).IsEqualTo(6);
        await Assert.That(Throws<CborContentException>(() => itemLimited.EncodeAppStart(withVendor))).IsTrue();
        await Assert.That(depthLimited.EncodeAppStart(message).Length).IsEqualTo(6);
        await Assert.That(Throws<CborContentException>(() => depthLimited.EncodeAppStart(withNestedValue))).IsTrue();
    }

    [Test]
    public async Task SetHmacHonorsTheConfiguredLimitForLargeHeaders()
    {
        var headerWriter = new CborWriter(CborConformanceMode.Canonical);
        headerWriter.WriteStartArray(6);
        headerWriter.WriteByteString(new byte[65530]);
        for (int i = 0; i < 5; i++)
        {
            headerWriter.WriteNull();
        }

        headerWriter.WriteEndArray();
        byte[] header = headerWriter.Encode();
        var tagWriter = new CborWriter(CborConformanceMode.Canonical);
        tagWriter.WriteByteString(header);
        byte[] tag = tagWriter.Encode();
        var message = new SetCredentials(new byte[] { 0x04 }, Array.Empty<string>(), tag);
        var codec = new FdoDeviceInitializeCodec(maxEncodedBytes: 100000);
        byte[] secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

        FdoHashValue actual = codec.ComputeSetHmac(FdoHashAlgorithm.HmacSha256, secret, message);

        await Assert.That(tag.Length > ushort.MaxValue).IsTrue();
        await Assert.That(Convert.ToHexString(actual.Value))
            .IsEqualTo(Convert.ToHexString(HMACSHA256.HashData(secret, header)));
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
}
