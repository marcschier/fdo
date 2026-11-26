// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Threading.Tasks;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoErrorMessageCodecTests
{
    [Test]
    public async Task EncodesTheSelectedSubsetWithANonSensitiveMessageDescription()
    {
        var codec = new FdoErrorMessageCodec();

        ReadOnlyMemory<byte> encoded = codec.Encode(1, 21, 42);
        FdoErrorMessageCodec.ErrorMessage decoded = codec.Decode(encoded);

        await Assert.That(Convert.ToHexString(encoded.Span))
            .IsEqualTo("8501157646444F206D657373616765203231206661696C65642EF6182A");
        await Assert.That(decoded.ErrorCode).IsEqualTo((ushort)1);
        await Assert.That(decoded.PreviousMessageId).IsEqualTo((byte)21);
        await Assert.That(decoded.UntrustedDescription).IsEqualTo("FDO message 21 failed.");
        await Assert.That(decoded.CorrelationId).IsEqualTo(42UL);
    }

    [Test]
    public async Task AcceptsTheIntegerBoundariesAndExistingZeroCorrelationId()
    {
        var codec = new FdoErrorMessageCodec();
        FdoErrorMessageCodec.ErrorMessage low = codec.Decode(codec.Encode(0, 0, 0));
        FdoErrorMessageCodec.ErrorMessage high = codec.Decode(codec.Encode(ushort.MaxValue, 254, ulong.MaxValue));

        await Assert.That(low.ErrorCode).IsEqualTo((ushort)0);
        await Assert.That(low.PreviousMessageId).IsEqualTo((byte)0);
        await Assert.That(low.CorrelationId).IsEqualTo(0UL);
        await Assert.That(high.ErrorCode).IsEqualTo(ushort.MaxValue);
        await Assert.That(high.PreviousMessageId).IsEqualTo((byte)254);
        await Assert.That(high.CorrelationId).IsEqualTo(ulong.MaxValue);
    }

    [Test]
    public async Task DoesNotEncodeOrAcceptAnErrorInResponseToAnError()
    {
        var codec = new FdoErrorMessageCodec();

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => codec.Encode(1, 255, 1))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => codec.Decode(Convert.FromHexString("850118FF60F601")))).IsTrue();
    }

    [Test]
    [Arguments("80")]
    [Arguments("85012060F601")]
    [Arguments("851A000100000160F601")]
    [Arguments("850119010060F601")]
    [Arguments("85010100F601")]
    [Arguments("85010160F620")]
    [Arguments("85010160F60100")]
    public async Task RejectsMalformedOrOutOfRangeFields(string hex)
    {
        var codec = new FdoErrorMessageCodec();

        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    [Arguments("85010160C10001")]
    [Arguments("85010160F6F6")]
    public async Task GuardsOtherTimestampAndCorrelationForms(string hex)
    {
        var codec = new FdoErrorMessageCodec();

        await Assert.That(Throws<NotSupportedException>(() => codec.Decode(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task AppliesTheEncodedByteLimit()
    {
        var codec = new FdoErrorMessageCodec();
        ReadOnlyMemory<byte> body = codec.Encode(1, 21, 42);
        var atLimit = new FdoErrorMessageCodec(maxEncodedBytes: body.Length);
        var overLimit = new FdoErrorMessageCodec(maxEncodedBytes: body.Length - 1);

        await Assert.That(atLimit.Encode(1, 21, 42).Length).IsEqualTo(body.Length);
        await Assert.That(Throws<CborContentException>(() => overLimit.Encode(1, 21, 42))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => overLimit.Decode(body))).IsTrue();
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
