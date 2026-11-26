// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading.Tasks;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoX5ChainCodecTests
{
    [Test]
    public async Task SingleCertificateUsesABareByteString()
    {
        // These bytes test CBOR framing, not X.509 certificate validity.
        byte[] certificate = Convert.FromHexString("616263");
        byte[] encoded = Convert.FromHexString("43616263");
        var codec = new FdoX5ChainCodec();

        IReadOnlyList<ReadOnlyMemory<byte>> decoded = codec.Decode(encoded);
        ReadOnlyMemory<byte> written = codec.Encode(new ReadOnlyMemory<byte>[] { certificate });

        await Assert.That(decoded.Count).IsEqualTo(1);
        await Assert.That(Convert.ToHexString(decoded[0].Span)).IsEqualTo("616263");
        await Assert.That(Convert.ToHexString(written.Span)).IsEqualTo("43616263");
    }

    [Test]
    public async Task MultipleCertificatesUseAnOrderedArrayOfByteStrings()
    {
        byte[] encoded = Convert.FromHexString("834261624163426162");
        var certificates = new ReadOnlyMemory<byte>[]
        {
            Convert.FromHexString("6162"),
            Convert.FromHexString("63"),
            Convert.FromHexString("6162"),
        };
        var codec = new FdoX5ChainCodec();

        IReadOnlyList<ReadOnlyMemory<byte>> decoded = codec.Decode(encoded);
        ReadOnlyMemory<byte> written = codec.Encode(certificates);

        await Assert.That(decoded.Count).IsEqualTo(3);
        await Assert.That(Convert.ToHexString(decoded[0].Span)).IsEqualTo("6162");
        await Assert.That(Convert.ToHexString(decoded[1].Span)).IsEqualTo("63");
        await Assert.That(Convert.ToHexString(decoded[2].Span)).IsEqualTo("6162");
        await Assert.That(Convert.ToHexString(written.Span)).IsEqualTo("834261624163426162");
    }

    [Test]
    [Arguments(23, "57")]
    [Arguments(24, "5818")]
    [Arguments(255, "58FF")]
    [Arguments(256, "590100")]
    public async Task SingleCertificateUsesShortestByteStringLength(int length, string prefix)
    {
        byte[] certificate = new byte[length];
        string expected = prefix + new string('0', length * 2);
        var codec = new FdoX5ChainCodec();

        ReadOnlyMemory<byte> encoded = codec.Encode(new ReadOnlyMemory<byte>[] { certificate });
        IReadOnlyList<ReadOnlyMemory<byte>> decoded = codec.Decode(Convert.FromHexString(expected));

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(decoded.Count).IsEqualTo(1);
        await Assert.That(decoded[0].Length).IsEqualTo(length);
        await Assert.That(Convert.ToHexString(decoded[0].Span)).IsEqualTo(new string('0', length * 2));
    }

    [Test]
    [Arguments(23, "97")]
    [Arguments(24, "9818")]
    [Arguments(255, "98FF")]
    [Arguments(256, "990100")]
    public async Task ArrayUsesShortestLengthAndPreservesEveryCertificate(int count, string prefix)
    {
        var certificates = new ReadOnlyMemory<byte>[count];
        string expected = prefix;
        for (int i = 0; i < count; i++)
        {
            byte[] certificate = [(byte)i];
            certificates[i] = certificate;
            expected += "41" + Convert.ToHexString(certificate);
        }

        var codec = new FdoX5ChainCodec();
        ReadOnlyMemory<byte> encoded = codec.Encode(certificates);
        IReadOnlyList<ReadOnlyMemory<byte>> decoded = codec.Decode(Convert.FromHexString(expected));

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(decoded.Count).IsEqualTo(count);
        for (int i = 0; i < count; i++)
        {
            await Assert.That(Convert.ToHexString(decoded[i].Span))
                .IsEqualTo(Convert.ToHexString(certificates[i].Span));
        }
    }

    [Test]
    [Arguments("")]
    [Arguments("00")]
    [Arguments("F6")]
    [Arguments("80")]
    [Arguments("814161")]
    [Arguments("82416100")]
    [Arguments("824161")]
    [Arguments("416100")]
    [Arguments("580161")]
    [Arguments("5F4161FF")]
    [Arguments("9F41614162FF")]
    [Arguments("D24161")]
    [Arguments("824161814162")]
    public async Task DecodeRejectsValuesOutsideTheCanonicalX5ChainShape(string hex)
    {
        var codec = new FdoX5ChainCodec();

        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task EncodeRejectsAnEmptyOrMissingCertificateList()
    {
        var codec = new FdoX5ChainCodec();

        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encode(Array.Empty<ReadOnlyMemory<byte>>()))).IsTrue();
        await Assert.That(Throws<ArgumentNullException>(() =>
            codec.Encode(null!))).IsTrue();
    }

    [Test]
    public async Task EncodedByteLimitAppliesToBothDirections()
    {
        var codec = new FdoX5ChainCodec(maxEncodedBytes: 5);
        var fits = new ReadOnlyMemory<byte>[] { new byte[] { 0x61 }, new byte[] { 0x62 } };
        var tooLong = new ReadOnlyMemory<byte>[] { new byte[] { 0x61 }, new byte[] { 0x62, 0x63 } };
        byte[] encodedFits = Convert.FromHexString("8241614162");
        byte[] encodedTooLong = Convert.FromHexString("824161426263");

        await Assert.That(Convert.ToHexString(codec.Encode(fits).Span)).IsEqualTo("8241614162");
        await Assert.That(codec.Decode(encodedFits).Count).IsEqualTo(2);
        await Assert.That(Throws<CborContentException>(() => codec.Encode(tooLong))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decode(encodedTooLong))).IsTrue();
    }

    [Test]
    public async Task ItemLimitCountsTheArrayAndEachCertificate()
    {
        var codec = new FdoX5ChainCodec(maxItems: 3);
        var fits = new ReadOnlyMemory<byte>[] { new byte[] { 0x61 }, new byte[] { 0x62 } };
        var tooMany = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 0x61 },
            new byte[] { 0x62 },
            new byte[] { 0x63 },
        };

        await Assert.That(Convert.ToHexString(codec.Encode(fits).Span)).IsEqualTo("8241614162");
        await Assert.That(codec.Decode(Convert.FromHexString("8241614162")).Count).IsEqualTo(2);
        await Assert.That(Throws<CborContentException>(() => codec.Encode(tooMany))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            codec.Decode(Convert.FromHexString("83416141624163")))).IsTrue();
    }

    [Test]
    public async Task AStandAloneByteStringUsesOneItem()
    {
        var codec = new FdoX5ChainCodec(maxItems: 1);
        var certificate = new ReadOnlyMemory<byte>[] { new byte[] { 0x61 } };

        await Assert.That(Convert.ToHexString(codec.Encode(certificate).Span)).IsEqualTo("4161");
        await Assert.That(codec.Decode(Convert.FromHexString("4161")).Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() =>
            codec.Encode(new ReadOnlyMemory<byte>[] { new byte[] { 0x61 }, new byte[] { 0x62 } }))).IsTrue();
    }

    [Test]
    public async Task DecodeAndEncodeOwnTheirInputBytes()
    {
        byte[] input = Convert.FromHexString("824261624163");
        byte[] first = Convert.FromHexString("6162");
        byte[] second = Convert.FromHexString("63");
        var codec = new FdoX5ChainCodec();

        IReadOnlyList<ReadOnlyMemory<byte>> decoded = codec.Decode(input);
        ReadOnlyMemory<byte> encoded = codec.Encode(new ReadOnlyMemory<byte>[] { first, second });
        Array.Fill(input, (byte)0);
        Array.Fill(first, (byte)0);
        Array.Fill(second, (byte)0);

        await Assert.That(Convert.ToHexString(decoded[0].Span)).IsEqualTo("6162");
        await Assert.That(Convert.ToHexString(decoded[1].Span)).IsEqualTo("63");
        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo("824261624163");
        await Assert.That(Throws<NotSupportedException>(() =>
            ((IList<ReadOnlyMemory<byte>>)decoded)[0] = ReadOnlyMemory<byte>.Empty)).IsTrue();
    }

    [Test]
    public async Task NonpositiveLimitsAreRejected()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            _ = new FdoX5ChainCodec(maxEncodedBytes: 0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            _ = new FdoX5ChainCodec(maxItems: 0))).IsTrue();
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException exception)
        {
            return exception.GetType() == typeof(TException);
        }
    }
}
