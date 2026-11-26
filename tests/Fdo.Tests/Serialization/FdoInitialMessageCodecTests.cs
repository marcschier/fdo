using System;
using System.Formats.Cbor;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fdo.Serialization;
using Fdo.Tests.Transport;
using Fdo.Transport;
using Fdo.Transport.Http;
using InitialMessage = Fdo.Serialization.FdoInitialMessageCodec.InitialMessage;

namespace Fdo.Tests.Serialization;

public sealed class FdoInitialMessageCodecTests
{
    private static readonly byte[] Identifier = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    [Test]
    [Arguments(FdoMessageTypes.TO0Hello, "82410480")]
    [Arguments(FdoMessageTypes.TO0HelloAck, "8341048050000102030405060708090A0B0C0D0E0F")]
    [Arguments(FdoMessageTypes.TO1HelloRV, "8341048050000102030405060708090A0B0C0D0E0F")]
    [Arguments(FdoMessageTypes.TO1HelloRVAck, "8341048050000102030405060708090A0B0C0D0E0F")]
    public async Task InitialMessagesHaveTheSpecifiedArrayShape(ushort messageType, string expectedHex)
    {
        var codec = new FdoInitialMessageCodec();
        ReadOnlyMemory<byte>? identifier = null;
        if (messageType != FdoMessageTypes.TO0Hello)
        {
            identifier = Identifier;
        }
        var message = new InitialMessage(messageType, new byte[] { 0x04 }, Array.Empty<string>(), identifier);

        ReadOnlyMemory<byte> encoded = codec.Encode(message);
        InitialMessage decoded = codec.Decode(messageType, encoded);

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expectedHex);
        await Assert.That(decoded.MessageType).IsEqualTo(messageType);
        await Assert.That(decoded.AdvertisedCapabilities).IsEqualTo(FdoKnownCapabilities.Fdo20);
        await Assert.That(decoded.VendorCapabilities.Count).IsEqualTo(0);
        await Assert.That(decoded.GuidOrNonce.HasValue).IsEqualTo(identifier.HasValue);
        if (identifier.HasValue)
        {
            await Assert.That(Convert.ToHexString(decoded.GuidOrNonce!.Value.Span))
                .IsEqualTo(Convert.ToHexString(Identifier));
        }
    }

    [Test]
    public async Task EmptyFlagsAndVendorCapabilitiesArePreserved()
    {
        var codec = new FdoInitialMessageCodec();
        InitialMessage message = codec.Decode(FdoMessageTypes.TO0Hello, Convert.FromHexString("824080"));

        await Assert.That(message.CapabilityFlags.IsEmpty).IsTrue();
        await Assert.That(message.AdvertisedCapabilities).IsEqualTo(FdoKnownCapabilities.None);
        await Assert.That(message.VendorCapabilities.Count).IsEqualTo(0);
        await Assert.That(Convert.ToHexString(codec.Encode(message).Span)).IsEqualTo("824080");
    }

    [Test]
    public async Task FlagsAndVendorOrderSurviveRoundTripWithoutTrustingTheSender()
    {
        var codec = new FdoInitialMessageCodec();
        byte[] flags = [0x85, 0x20];
        byte[] identifier = Identifier.ToArray();
        string[] vendors = ["com.example.first", "org.example.second"];
        var message = new InitialMessage(FdoMessageTypes.TO1HelloRV, flags, vendors, identifier);
        byte[] encoded = codec.Encode(message).ToArray();
        InitialMessage decoded = codec.Decode(FdoMessageTypes.TO1HelloRV, encoded);

        Array.Fill(flags, (byte)0);
        Array.Fill(identifier, (byte)0);
        vendors[0] = "changed";
        Array.Fill(encoded, (byte)0);

        await Assert.That(Convert.ToHexString(decoded.CapabilityFlags.Span)).IsEqualTo("8520");
        await Assert.That(decoded.AdvertisedCapabilities)
            .IsEqualTo(FdoKnownCapabilities.Fdo10 | FdoKnownCapabilities.Fdo20 | FdoKnownCapabilities.Delegation);
        await Assert.That(decoded.VendorCapabilities.SequenceEqual(
            new[] { "com.example.first", "org.example.second" })).IsTrue();
        await Assert.That(Convert.ToHexString(decoded.GuidOrNonce!.Value.Span))
            .IsEqualTo(Convert.ToHexString(Identifier));
        InitialMessage again = codec.Decode(FdoMessageTypes.TO1HelloRV, codec.Encode(decoded));
        await Assert.That(Convert.ToHexString(again.CapabilityFlags.Span)).IsEqualTo("8520");
        await Assert.That(again.VendorCapabilities.SequenceEqual(decoded.VendorCapabilities)).IsTrue();
    }

    [Test]
    [Arguments(FdoMessageTypes.TO0Hello, "814104")]
    [Arguments(FdoMessageTypes.TO0Hello, "820080")]
    [Arguments(FdoMessageTypes.TO0Hello, "82410880")]
    [Arguments(FdoMessageTypes.TO0Hello, "82411080")]
    [Arguments(FdoMessageTypes.TO0Hello, "82412080")]
    [Arguments(FdoMessageTypes.TO0Hello, "82414080")]
    [Arguments(FdoMessageTypes.TO0Hello, "8241048100")]
    [Arguments(FdoMessageTypes.TO0Hello, "8241048161FF")]
    [Arguments(FdoMessageTypes.TO0Hello, "82410480F6")]
    [Arguments(FdoMessageTypes.TO0Hello, "825F4104FF80")]
    [Arguments(FdoMessageTypes.TO0Hello, "8258010480")]
    [Arguments(FdoMessageTypes.TO1HelloRV, "82410480")]
    [Arguments(FdoMessageTypes.TO1HelloRV, "8341048040")]
    [Arguments(FdoMessageTypes.TO1HelloRV, "8341048060")]
    [Arguments(FdoMessageTypes.TO1HelloRV, "8341048050000102")]
    public async Task MalformedInitialMessagesAreRejected(ushort messageType, string hex)
    {
        var codec = new FdoInitialMessageCodec();

        await Assert.That(Throws<CborContentException>(
            () => codec.Decode(messageType, Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task EncodingRejectsReservedFlagsAndIncorrectIdentifierShapes()
    {
        var codec = new FdoInitialMessageCodec();
        var reserved = new InitialMessage(FdoMessageTypes.TO0Hello, new byte[] { 0x08 }, Array.Empty<string>(), null);
        var unexpected = new InitialMessage(FdoMessageTypes.TO0Hello, ReadOnlyMemory<byte>.Empty, Array.Empty<string>(), Identifier);
        var absent = new InitialMessage(FdoMessageTypes.TO1HelloRV, ReadOnlyMemory<byte>.Empty, Array.Empty<string>(), null);
        var shortNonce = new InitialMessage(FdoMessageTypes.TO1HelloRVAck, ReadOnlyMemory<byte>.Empty, Array.Empty<string>(), new byte[15]);
        var nullVendor = new InitialMessage(FdoMessageTypes.TO0Hello, ReadOnlyMemory<byte>.Empty, new string[] { null! }, null);

        await Assert.That(Throws<ArgumentException>(() => codec.Encode(reserved))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Encode(unexpected))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Encode(absent))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Encode(shortNonce))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Encode(nullVendor))).IsTrue();
    }

    [Test]
    public async Task OnlyTheFourInitialMessageTypesAreAccepted()
    {
        var codec = new FdoInitialMessageCodec();
        var message = new InitialMessage(FdoMessageTypes.TO0OwnerSign, ReadOnlyMemory<byte>.Empty, Array.Empty<string>(), null);

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => codec.Encode(message))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => codec.Decode(FdoMessageTypes.TO1ProveToRV, Convert.FromHexString("824080")))).IsTrue();
    }

    [Test]
    public async Task ByteItemAndDepthLimitsApplyToEncodingAndDecoding()
    {
        var byteLimited = new FdoInitialMessageCodec(maxEncodedBytes: 4);
        var emptyVendors = new InitialMessage(FdoMessageTypes.TO0Hello, new byte[] { 0x04 }, Array.Empty<string>(), null);
        var oneVendor = new InitialMessage(FdoMessageTypes.TO0Hello, new byte[] { 0x04 }, new[] { "com.example.a" }, null);
        var itemLimited = new FdoInitialMessageCodec(maxItems: 3);
        var depthLimited = new FdoInitialMessageCodec(maxDepth: 2);

        await Assert.That(byteLimited.Encode(emptyVendors).Length).IsEqualTo(4);
        await Assert.That(Throws<CborContentException>(() => byteLimited.Encode(oneVendor))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => byteLimited.Decode(FdoMessageTypes.TO0Hello, Convert.FromHexString("8242040080")))).IsTrue();
        await Assert.That(itemLimited.Encode(emptyVendors).Length).IsEqualTo(4);
        await Assert.That(Throws<CborContentException>(() => itemLimited.Encode(oneVendor))).IsTrue();
        await Assert.That(depthLimited.Encode(emptyVendors).Length).IsEqualTo(4);
        await Assert.That(Throws<CborContentException>(() => depthLimited.Encode(oneVendor))).IsTrue();
    }

    [Test]
    public async Task ByteLimitCountsUtf8BytesRatherThanCharacters()
    {
        var message = new InitialMessage(
            FdoMessageTypes.TO0Hello, new byte[] { 0x04 }, new[] { "com.example.\u00e9" }, null);

        await Assert.That(new FdoInitialMessageCodec(maxEncodedBytes: 19).Encode(message).Length).IsEqualTo(19);
        await Assert.That(Throws<CborContentException>(
            () => new FdoInitialMessageCodec(maxEncodedBytes: 18).Encode(message))).IsTrue();
    }

    [Test]
    [UnsupportedOSPlatform("browser")]
    public async Task To1InitialBodiesCanBeCarriedByASyntheticVersionHttpSession()
    {
        var codec = new FdoInitialMessageCodec();
        var request = new InitialMessage(
            FdoMessageTypes.TO1HelloRV, new byte[] { 0x04 }, Array.Empty<string>(), Identifier);
        var ack = new InitialMessage(
            FdoMessageTypes.TO1HelloRVAck, new byte[] { 0x04 }, Array.Empty<string>(), Identifier);
        byte[] requestBody = codec.Encode(request).ToArray();
        byte[] responseBody = codec.Encode(ack).ToArray();
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, responseBody, "token-1"));
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, new Uri("http://rv.example/"), FdoProtocolKind.TransferOwnership1, FdoTestVersions.SyntheticHttp);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, requestBody);
        InitialMessage decoded = codec.Decode(response.MessageType, response.Body);

        await Assert.That(handler.Requests.Single().Body.SequenceEqual(requestBody)).IsTrue();
        await Assert.That(decoded.MessageType).IsEqualTo(FdoMessageTypes.TO1HelloRVAck);
        await Assert.That(Convert.ToHexString(decoded.GuidOrNonce!.Value.Span))
            .IsEqualTo(Convert.ToHexString(Identifier));
        await Assert.That(session.HasAuthorizationToken).IsTrue();
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
