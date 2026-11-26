// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoCoseSignatureTests
{
    [Test]
    [Arguments(-7, "A10126")]
    [Arguments(-35, "A1013822")]
    [Arguments(-257, "A101390100")]
    [Arguments(-258, "A101390101")]
    public async Task SignsWithTheSelectedAlgorithmAndOperation(int algorithmValue, string headerHex)
    {
        var algorithm = (FdoCoseSignatureAlgorithm)algorithmValue;
        using AsymmetricAlgorithm key = CreateKey(algorithm);
        byte[] header = Convert.FromHexString(headerHex);
        byte[] payload = [0x82, 0x01, 0x02];
        var signer = new FdoCoseSignature();
        byte[] signature = signer.Sign(FdoSignatureOperation.OVEntry, algorithm, key, header, payload);
        byte[] input = FdoCoseSigningInput.CreateToBeSigned(FdoSignatureOperation.OVEntry, header, payload);
        HashAlgorithmName hash = algorithm is FdoCoseSignatureAlgorithm.ES256 or FdoCoseSignatureAlgorithm.RS256
            ? HashAlgorithmName.SHA256
            : HashAlgorithmName.SHA384;
        bool verifiedByBcl = key switch
        {
            ECDsa ecdsa => ecdsa.VerifyData(
                input, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            RSA rsa => rsa.VerifyData(input, signature, hash, RSASignaturePadding.Pkcs1),
            _ => false,
        };
        bool wrongOperation = signer.TryVerify(
            FdoSignatureOperation.TO0OwnerSign, algorithm, key, header, payload, signature, out _);

        await Assert.That(verifiedByBcl).IsTrue();
        await Assert.That(wrongOperation).IsFalse();
    }

    [Test]
    [Arguments(-7, "A10126")]
    [Arguments(-35, "A1013822")]
    [Arguments(-257, "A101390100")]
    [Arguments(-258, "A101390101")]
    public async Task ValidSignaturesReturnAnOwnedCopyOfTheVerifiedPayload(int algorithmValue, string headerHex)
    {
        var algorithm = (FdoCoseSignatureAlgorithm)algorithmValue;
        using AsymmetricAlgorithm key = CreateKey(algorithm);
        byte[] header = Convert.FromHexString(headerHex);
        byte[] payload = [0x82, 0x01, 0x02];
        byte[] signature = Sign(key, algorithm, FdoSignatureOperation.OVEntry, header, payload);
        var verifier = new FdoCoseSignature();

        bool result = verifier.TryVerify(
            FdoSignatureOperation.OVEntry, algorithm, key, header, payload, signature, out ReadOnlyMemory<byte> verified);
        Array.Fill(header, (byte)0);
        Array.Fill(payload, (byte)0);
        Array.Fill(signature, (byte)0);

        await Assert.That(result).IsTrue();
        await Assert.That(Convert.ToHexString(verified.Span)).IsEqualTo("820102");
    }

    [Test]
    [Arguments(-7, "A10126")]
    [Arguments(-35, "A1013822")]
    [Arguments(-257, "A101390100")]
    [Arguments(-258, "A101390101")]
    public async Task PayloadOperationAndSignatureChangesDoNotVerify(int algorithmValue, string headerHex)
    {
        var algorithm = (FdoCoseSignatureAlgorithm)algorithmValue;
        using AsymmetricAlgorithm key = CreateKey(algorithm);
        byte[] header = Convert.FromHexString(headerHex);
        byte[] payload = [0x82, 0x01, 0x02];
        byte[] signature = Sign(key, algorithm, FdoSignatureOperation.OVEntry, header, payload);
        var verifier = new FdoCoseSignature();

        bool wrongOperation = verifier.TryVerify(
            FdoSignatureOperation.TO0OwnerSign, algorithm, key, header, payload, signature, out _);
        bool wrongPayload = verifier.TryVerify(
            FdoSignatureOperation.OVEntry, algorithm, key, header, new byte[] { 0x82, 0x01, 0x03 }, signature, out _);
        byte[] truncated = signature[..^1];
        bool wrongLength = verifier.TryVerify(
            FdoSignatureOperation.OVEntry, algorithm, key, header, payload, truncated, out _);
        signature[0] ^= 0x01;
        bool wrongSignature = verifier.TryVerify(
            FdoSignatureOperation.OVEntry, algorithm, key, header, payload, signature, out ReadOnlyMemory<byte> rejected);

        await Assert.That(wrongOperation).IsFalse();
        await Assert.That(wrongPayload).IsFalse();
        await Assert.That(wrongLength).IsFalse();
        await Assert.That(wrongSignature).IsFalse();
        await Assert.That(rejected.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("A0")]
    [Arguments("A1013822")]
    [Arguments("A20126028101")]
    [Arguments("A101F6")]
    [Arguments("B8010126")]
    public async Task RejectsMissingMismatchedExtendedAndNoncanonicalProtectedHeaders(string headerHex)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new FdoCoseSignature();

        await Assert.That(Throws<CborContentException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            Convert.FromHexString(headerHex), new byte[] { 0x80 }, new byte[64], out _))).IsTrue();
    }

    [Test]
    public async Task RejectsTheWrongKeyFamilyAndCurve()
    {
        using RSA rsa = RSA.Create(2048);
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using ECDsa p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new FdoCoseSignature();
        byte[] es256Header = Convert.FromHexString("A10126");
        byte[] rs256Header = Convert.FromHexString("A101390100");

        await Assert.That(Throws<ArgumentException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, rsa,
            es256Header, new byte[] { 0x80 }, new byte[64], out _))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, p384,
            es256Header, new byte[] { 0x80 }, new byte[64], out _))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.RS256, p256,
            rs256Header, new byte[] { 0x80 }, new byte[256], out _))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.RS384, rsa,
            Convert.FromHexString("A101390101"), new byte[] { 0x80 }, new byte[384], out _))).IsTrue();
    }

    [Test]
    public async Task EnforcesTheSignedComponentLimit()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] header = Convert.FromHexString("A10126");
        byte[] payload = [0x82, 0x01, 0x02];
        byte[] signature = Sign(key, FdoCoseSignatureAlgorithm.ES256, FdoSignatureOperation.OVEntry, header, payload);
        int length = header.Length + payload.Length + signature.Length;
        var atLimit = new FdoCoseSignature(length);
        var overLimit = new FdoCoseSignature(length - 1);

        await Assert.That(atLimit.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            header, payload, signature, out _)).IsTrue();
        await Assert.That(atLimit.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            header, payload).Length).IsEqualTo(64);
        await Assert.That(Throws<CborContentException>(() => overLimit.TryVerify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            header, payload, signature, out _))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => overLimit.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            header, payload))).IsTrue();
    }

    [Test]
    public async Task RejectsUnsupportedAlgorithmsAndOperations()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new FdoCoseSignature();
        byte[] header = Convert.FromHexString("A10126");

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => verifier.TryVerify(
            FdoSignatureOperation.OVEntry, (FdoCoseSignatureAlgorithm)(-36), key,
            header, new byte[] { 0x80 }, new byte[64], out _))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => verifier.TryVerify(
            (FdoSignatureOperation)99, FdoCoseSignatureAlgorithm.ES256, key,
            header, new byte[] { 0x80 }, new byte[64], out _))).IsTrue();
    }

    private static AsymmetricAlgorithm CreateKey(FdoCoseSignatureAlgorithm algorithm) => algorithm switch
    {
        FdoCoseSignatureAlgorithm.ES256 => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        FdoCoseSignatureAlgorithm.ES384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
        FdoCoseSignatureAlgorithm.RS256 => RSA.Create(2048),
        FdoCoseSignatureAlgorithm.RS384 => RSA.Create(3072),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    private static byte[] Sign(
        AsymmetricAlgorithm key,
        FdoCoseSignatureAlgorithm algorithm,
        FdoSignatureOperation operation,
        byte[] protectedHeader,
        byte[] payload)
    {
        byte[] input = FdoCoseSigningInput.CreateToBeSigned(operation, protectedHeader, payload);
        HashAlgorithmName hash = algorithm is FdoCoseSignatureAlgorithm.ES256 or FdoCoseSignatureAlgorithm.RS256
            ? HashAlgorithmName.SHA256
            : HashAlgorithmName.SHA384;
        return key switch
        {
            ECDsa ecdsa => ecdsa.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            RSA rsa => rsa.SignData(input, hash, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException("Unsupported signing key.", nameof(key)),
        };
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
