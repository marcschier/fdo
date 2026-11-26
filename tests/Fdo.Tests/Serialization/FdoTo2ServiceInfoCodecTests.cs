// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Threading.Tasks;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.Serialization;

public sealed class FdoTo2ServiceInfoCodecTests
{
    private const string NonceHex = "000102030405060708090A0B0C0D0E0F";

    [Test]
    [Arguments(-1, "F6")]
    [Arguments(0, "00")]
    [Arguments(1300, "190514")]
    [Arguments(65535, "19FFFF")]
    public async Task ReadyUsesNullHmacOptionalUint16AndSetupNonce(int maximum, string encodedMaximum)
    {
        var codec = new FdoTo2ServiceInfoCodec();
        ushort? size = maximum < 0 ? null : (ushort)maximum;
        string expected = "83F6" + encodedMaximum + "50" + NonceHex;

        ReadOnlyMemory<byte> encoded = codec.EncodeDeviceReady(size, Convert.FromHexString(NonceHex));
        FdoTo2ServiceInfoCodec.DeviceServiceInfoReady decoded = codec.DecodeDeviceReady(Convert.FromHexString(expected));

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(decoded.MaxOwnerServiceInfoSize).IsEqualTo(size);
        await Assert.That(Convert.ToHexString(decoded.Nonce.Span)).IsEqualTo(NonceHex);
    }

    [Test]
    public async Task DeviceServiceInfoPreservesOrderDuplicateKeysAndEncodedValues()
    {
        const string wire = "83F6F58282636D3A7842180082636D3A784241FF";
        var codec = new FdoTo2ServiceInfoCodec();
        byte[] source = Convert.FromHexString(wire);

        FdoTo2ServiceInfoCodec.DeviceServiceInfo decoded = codec.DecodeDevice(source);
        Array.Fill(source, (byte)0);
        ReadOnlyMemory<byte> encoded = codec.EncodeDevice(decoded.IsMoreServiceInfo, decoded.ServiceInfo);

        await Assert.That(decoded.IsMoreServiceInfo).IsTrue();
        await Assert.That(decoded.ServiceInfo.Select(entry => entry.Key).SequenceEqual(new[] { "m:x", "m:x" })).IsTrue();
        await Assert.That(Convert.ToHexString(decoded.ServiceInfo[0].EncodedValue.Span)).IsEqualTo("1800");
        await Assert.That(Convert.ToHexString(decoded.ServiceInfo[1].EncodedValue.Span)).IsEqualTo("41FF");
        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(wire);
    }

    [Test]
    [Arguments(false, false, "83F4F480")]
    [Arguments(true, false, "83F5F480")]
    [Arguments(false, true, "83F4F580")]
    public async Task OwnerServiceInfoPreservesFlagsAndEmptyItems(bool more, bool done, string wire)
    {
        var codec = new FdoTo2ServiceInfoCodec();

        FdoTo2ServiceInfoCodec.OwnerServiceInfo decoded = codec.DecodeOwner(Convert.FromHexString(wire));
        ReadOnlyMemory<byte> encoded = codec.EncodeOwner(more, done, Array.Empty<Entry>());

        await Assert.That(decoded.IsMoreServiceInfo).IsEqualTo(more);
        await Assert.That(decoded.IsDone).IsEqualTo(done);
        await Assert.That(decoded.ServiceInfo.Count).IsEqualTo(0);
        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(wire);
    }

    [Test]
    [Arguments("80")]
    [Arguments("83F6F6")]
    [Arguments("8300F650000102030405060708090A0B0C0D0E0F")]
    [Arguments("83F62050000102030405060708090A0B0C0D0E0F")]
    [Arguments("83F61A0001000050000102030405060708090A0B0C0D0E0F")]
    [Arguments("83F6F640")]
    [Arguments("83F6F64F000102030405060708090A0B0C0D0E")]
    [Arguments("83F6F651000102030405060708090A0B0C0D0E0F10")]
    [Arguments("83F6F650000102030405060708090A0B0C0D0E0F00")]
    public async Task ReadyRejectsInvalidShapeHmacSizeAndNonce(string wire)
    {
        var codec = new FdoTo2ServiceInfoCodec();

        await Assert.That(Throws<CborContentException>(() => codec.DecodeDeviceReady(Convert.FromHexString(wire)))).IsTrue();
    }

    [Test]
    [Arguments("80")]
    [Arguments("8300F480")]
    [Arguments("83F60080")]
    [Arguments("83F6F400")]
    [Arguments("83F6F48182636D3A78420000")]
    [Arguments("83F6F48000")]
    public async Task DeviceRejectsNonNullHmacInvalidFlagsAndMalformedEntries(string wire)
    {
        var codec = new FdoTo2ServiceInfoCodec();

        await Assert.That(Throws<CborContentException>(() => codec.DecodeDevice(Convert.FromHexString(wire)))).IsTrue();
    }

    [Test]
    [Arguments("80")]
    [Arguments("8300F480")]
    [Arguments("83F40080")]
    [Arguments("83F4F400")]
    [Arguments("83F4F48182636D3A78420000")]
    [Arguments("83F4F48000")]
    public async Task OwnerRejectsInvalidFlagsAndMalformedEntries(string wire)
    {
        var codec = new FdoTo2ServiceInfoCodec();

        await Assert.That(Throws<CborContentException>(() => codec.DecodeOwner(Convert.FromHexString(wire)))).IsTrue();
    }

    [Test]
    public async Task BodyLimitsIncludeTheOuterArrayAndEmbeddedServiceInfo()
    {
        Entry[] entries = [new Entry("m:x", Convert.FromHexString("41FF"))];
        var atLimit = new FdoTo2ServiceInfoCodec(maxEncodedBytes: 12, maxDepth: 4, maxItems: 7);
        var byteLimited = new FdoTo2ServiceInfoCodec(maxEncodedBytes: 11);
        var depthLimited = new FdoTo2ServiceInfoCodec(maxDepth: 3);
        var itemLimited = new FdoTo2ServiceInfoCodec(maxItems: 6);
        ReadOnlyMemory<byte> device = atLimit.EncodeDevice(false, entries);
        ReadOnlyMemory<byte> owner = atLimit.EncodeOwner(false, false, entries);

        await Assert.That(device.Length).IsEqualTo(12);
        await Assert.That(atLimit.DecodeDevice(device).ServiceInfo.Count).IsEqualTo(1);
        await Assert.That(atLimit.DecodeOwner(owner).ServiceInfo.Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() => byteLimited.EncodeDevice(false, entries))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => byteLimited.EncodeOwner(false, false, entries))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => byteLimited.DecodeDevice(device))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => byteLimited.DecodeOwner(owner))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => depthLimited.DecodeDevice(device))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => itemLimited.DecodeOwner(owner))).IsTrue();
    }

    [Test]
    public async Task ReadyNonceIsCopiedAndEncodingRejectsWrongLengths()
    {
        var codec = new FdoTo2ServiceInfoCodec();
        byte[] wire = Convert.FromHexString("83F6F650" + NonceHex);
        byte[] nonce = Convert.FromHexString(NonceHex);
        FdoTo2ServiceInfoCodec.DeviceServiceInfoReady decoded = codec.DecodeDeviceReady(wire);
        ReadOnlyMemory<byte> encoded = codec.EncodeDeviceReady(null, nonce);
        Array.Fill(wire, (byte)0);
        Array.Fill(nonce, (byte)0);

        await Assert.That(Convert.ToHexString(decoded.Nonce.Span)).IsEqualTo(NonceHex);
        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo("83F6F650" + NonceHex);
        await Assert.That(Throws<ArgumentException>(() => codec.EncodeDeviceReady(null, new byte[15]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.EncodeDeviceReady(null, new byte[17]))).IsTrue();
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
