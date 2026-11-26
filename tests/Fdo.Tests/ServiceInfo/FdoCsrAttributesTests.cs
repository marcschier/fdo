using System;
using System.Formats.Asn1;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Enrollment;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrAttributesTests
{
    private const string RfcExample =
        "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJ" +
        "BgcrBgEBAQEWBggqhkjOPQQDAw==";

    [Test]
    public async Task ParsesTheRfc8951ExampleAndPreservesEveryChoice()
    {
        byte[] encoded = Convert.FromBase64String(RfcExample);
        var attributes = new FdoCsrAttributes(encoded);

        await Assert.That(attributes.EncodedValue.Span.SequenceEqual(encoded)).IsTrue();
        await Assert.That(attributes.Entries.Count).IsEqualTo(4);
        await Assert.That(attributes.Entries.Select(item => item.ObjectIdentifier).SequenceEqual(
        [
            "1.2.840.113549.1.9.7",
            "1.2.840.10045.2.1",
            "1.2.840.113549.1.9.14",
            "1.2.840.10045.4.3.3",
        ])).IsTrue();
        await Assert.That(attributes.Entries.Select(item => item.IsAttribute)
            .SequenceEqual(new[] { false, true, true, false })).IsTrue();
        await Assert.That(attributes.Entries[0].Values.Count).IsEqualTo(0);
        await Assert.That(attributes.Entries[1].Values.Count).IsEqualTo(1);
        await Assert.That(Convert.ToHexString(attributes.Entries[1].Values[0].Span))
            .IsEqualTo("06052B81040022");
        await Assert.That(Convert.ToHexString(attributes.Entries[2].Values[0].Span))
            .IsEqualTo("06072B060101010116");
    }

    [Test]
    public async Task AcceptsEmptyAndUnknownAttributesWithoutExposingMutableBuffers()
    {
        var empty = new FdoCsrAttributes(new byte[] { 0x30, 0x00 });
        byte[] encoded = Convert.FromHexString("300C06022A03300606022A043100");
        // The Attribute SET must contain a value, including for an unknown type.
        await Assert.That(Throws<CryptographicException>(() => new FdoCsrAttributes(encoded))).IsTrue();

        encoded = Convert.FromHexString("300E06022A03300806022A0431020500");
        byte[] original = (byte[])encoded.Clone();
        var attributes = new FdoCsrAttributes(encoded);
        Array.Clear(encoded);
        ClearExposedMemory(attributes.EncodedValue);
        ClearExposedMemory(attributes.Entries[1].Values[0]);

        await Assert.That(empty.Entries.Count).IsEqualTo(0);
        await Assert.That(attributes.Entries.Count).IsEqualTo(2);
        await Assert.That(attributes.Entries[0].ObjectIdentifier).IsEqualTo("1.2.3");
        await Assert.That(attributes.Entries[1].ObjectIdentifier).IsEqualTo("1.2.4");
        await Assert.That(attributes.EncodedValue.Span.SequenceEqual(original)).IsTrue();
        await Assert.That(Convert.ToHexString(attributes.Entries[1].Values[0].Span)).IsEqualTo("0500");
    }

    [Test]
    [Arguments("")]
    [Arguments("30800000")]
    [Arguments("300000")]
    [Arguments("3003020100")]
    [Arguments("300406028000")]
    [Arguments("3006300406022A03")]
    [Arguments("3009300706032A03043100")]
    [Arguments("300B300906022A033103300100")]
    [Arguments("300C300A06022A03310402020001")]
    public async Task RejectsMalformedOrNonDerAttributeStructures(string hex)
    {
        byte[] encoded = Convert.FromHexString(hex);
        await Assert.That(Throws<CryptographicException>(() => new FdoCsrAttributes(encoded))).IsTrue();
    }

    [Test]
    public async Task RejectsUnsortedAttributeValues()
    {
        byte[] unsorted = Convert.FromHexString("300E300C06022A033106020102020101");
        await Assert.That(Throws<CryptographicException>(() => new FdoCsrAttributes(unsorted))).IsTrue();
    }

    [Test]
    public async Task PreservesAnOpaqueNestedSetWithoutAssumingSetOfOrdering()
    {
        byte[] encoded = Convert.FromHexString("300F300D06022A0331073105A100830107");
        var attributes = new FdoCsrAttributes(encoded);

        await Assert.That(attributes.Entries.Count).IsEqualTo(1);
        await Assert.That(Convert.ToHexString(attributes.Entries[0].Values[0].Span))
            .IsEqualTo("3105A100830107");
    }

    [Test]
    public async Task EnforcesTheExactDerLengthLimit()
    {
        byte[] sample = AttributesWithOctets(65400);
        int contentLength = 65400 + ushort.MaxValue - sample.Length;
        byte[] atLimit = AttributesWithOctets(contentLength);
        byte[] overLimit = AttributesWithOctets(contentLength + 1);

        await Assert.That(atLimit.Length).IsEqualTo((int)ushort.MaxValue);
        await Assert.That(new FdoCsrAttributes(atLimit).EncodedValue.Length).IsEqualTo((int)ushort.MaxValue);
        await Assert.That(overLimit.Length).IsEqualTo(ushort.MaxValue + 1);
        await Assert.That(Throws<CryptographicException>(() => new FdoCsrAttributes(overLimit))).IsTrue();
    }

    private static byte[] AttributesWithOctets(int length)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.3");
        writer.PushSetOf();
        writer.WriteOctetString(new byte[length]);
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
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
