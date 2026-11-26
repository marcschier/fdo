// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoCoseSigningInputTests
{
    /// <summary>
    /// CBOR text string "Signature1" (RFC 9052 section 4.4) preceded by a four-element array header.
    /// </summary>
    private const string Sign1Prefix = "846A5369676E617475726531";
    private const string To0OwnerSignAadField = "568174" + "46444F2D544F302D4F776E65725369676E2D7631";
    private const string OvEntryAad = "816E" + "46444F2D4F56456E7472792D7631";

    [Test]
    [Arguments(0, "FDO-TO0-OwnerSign-v1")]
    [Arguments(1, "FDO-TO1-ProveToRV-v1")]
    [Arguments(2, "FDO-TO2-ProveDevice-v1")]
    [Arguments(3, "FDO-TO2-ProveOVHdr-v1")]
    [Arguments(4, "FDO-TO2-SetupDevice-v1")]
    [Arguments(5, "FDO-OVEntry-v1")]
    public async Task EachOperationUsesItsSection338DomainTagInAOneElementArray(int value, string tag)
    {
        var operation = (FdoSignatureOperation)value;

        // Every tag is shorter than 24 bytes, so its text-string header is 0x60 + length.
        string expected = "81" + Convert.ToHexString(new[] { (byte)(0x60 + tag.Length) })
            + Convert.ToHexString(Encoding.ASCII.GetBytes(tag));

        await Assert.That(FdoCoseSigningInput.GetDomainTag(operation)).IsEqualTo(tag);
        await Assert.That(Convert.ToHexString(FdoCoseSigningInput.EncodeExternalAad(operation))).IsEqualTo(expected);
    }

    [Test]
    public async Task ToBeSignedMatchesTheHandEncodedSign1Structure()
    {
        // Protected header {1: -7}; payload [1, 2].
        byte[] toBeSigned = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.TO0OwnerSign,
            Convert.FromHexString("A10126"),
            Convert.FromHexString("820102"));

        await Assert.That(Convert.ToHexString(toBeSigned))
            .IsEqualTo(Sign1Prefix + "43A10126" + To0OwnerSignAadField + "43820102");
    }

    [Test]
    public async Task AbsentProtectedHeaderAndPayloadUseZeroLengthByteStrings()
    {
        byte[] toBeSigned = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.TO0OwnerSign,
            ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty);

        await Assert.That(Convert.ToHexString(toBeSigned)).IsEqualTo(Sign1Prefix + "40" + To0OwnerSignAadField + "40");
    }

    [Test]
    [Arguments(23, "57")]
    [Arguments(24, "5818")]
    public async Task ByteStringLengthsUseTheShortestHeader(int payloadLength, string payloadHeader)
    {
        byte[] payload = new byte[payloadLength];

        byte[] toBeSigned = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.TO0OwnerSign, ReadOnlySpan<byte>.Empty, payload);

        await Assert.That(Convert.ToHexString(toBeSigned))
            .IsEqualTo(Sign1Prefix + "40" + To0OwnerSignAadField + payloadHeader + Convert.ToHexString(payload));
    }

    [Test]
    public async Task ReceivedHeaderAndPayloadBytesAreNotReencoded()
    {
        // An empty map (A0) is not normalized to an empty byte string, and the
        // non-minimal integer 18 01 in the payload is not rewritten.
        byte[] toBeSigned = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.TO0OwnerSign,
            Convert.FromHexString("A0"),
            Convert.FromHexString("1801"));

        await Assert.That(Convert.ToHexString(toBeSigned))
            .IsEqualTo(Sign1Prefix + "41A0" + To0OwnerSignAadField + "421801");
    }

    [Test]
    public async Task EveryOperationProducesADistinctSigningInputForTheSameMessage()
    {
        byte[] protectedHeader = Convert.FromHexString("A10126");
        byte[] payload = Convert.FromHexString("820102");
        FdoSignatureOperation[] operations = Enum.GetValues<FdoSignatureOperation>();
        var inputs = new HashSet<string>(StringComparer.Ordinal);

        foreach (FdoSignatureOperation operation in operations)
        {
            byte[] aad = FdoCoseSigningInput.EncodeExternalAad(operation);
            byte[] toBeSigned = FdoCoseSigningInput.CreateToBeSigned(operation, protectedHeader, payload);
            string aadHeader = aad.Length < 24
                ? (0x40 + aad.Length).ToString("X2")
                : "58" + aad.Length.ToString("X2");
            string expected = Sign1Prefix + "43A10126"
                + aadHeader + Convert.ToHexString(aad) + "43820102";

            await Assert.That(Convert.ToHexString(toBeSigned)).IsEqualTo(expected);
            inputs.Add(Convert.ToHexString(toBeSigned));
        }

        await Assert.That(operations.Length).IsEqualTo(6);
        await Assert.That(inputs.Count).IsEqualTo(operations.Length);
    }

    [Test]
    public async Task ReturnedBuffersAreNotSharedBetweenCalls()
    {
        byte[] first = FdoCoseSigningInput.EncodeExternalAad(FdoSignatureOperation.OVEntry);
        byte[] firstInput = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.OVEntry, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
        Array.Fill(first, (byte)0);
        Array.Fill(firstInput, (byte)0);

        byte[] second = FdoCoseSigningInput.EncodeExternalAad(FdoSignatureOperation.OVEntry);
        byte[] secondInput = FdoCoseSigningInput.CreateToBeSigned(
            FdoSignatureOperation.OVEntry, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

        await Assert.That(Convert.ToHexString(second)).IsEqualTo(OvEntryAad);
        await Assert.That(Convert.ToHexString(secondInput)).IsEqualTo(Sign1Prefix + "40" + "50" + OvEntryAad + "40");
    }

    [Test]
    public async Task UndefinedOperationsAreRejected()
    {
        var undefined = (FdoSignatureOperation)99;

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => FdoCoseSigningInput.GetDomainTag(undefined))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => FdoCoseSigningInput.EncodeExternalAad(undefined))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoCoseSigningInput.CreateToBeSigned(undefined, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty))).IsTrue();
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
