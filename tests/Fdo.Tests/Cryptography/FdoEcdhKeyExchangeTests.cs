using System;
using System.Buffers.Binary;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoEcdhKeyExchangeTests
{
    [Test]
    [Arguments(0, 32, 16)]
    [Arguments(1, 48, 48)]
    public async Task BothPartiesProduceTheSameFixedWidthSecretAndGcmKey(
        int suiteValue, int coordinateLength, int randomLength)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using var device = FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Device);
        using var owner = FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Owner);
        byte[] deviceParameter = device.ExportParameter();
        byte[] ownerParameter = owner.ExportParameter();

        byte[] deviceSecret = device.DeriveSharedSecret(ownerParameter);
        byte[] ownerSecret = owner.DeriveSharedSecret(deviceParameter);
        try
        {
            await Assert.That(deviceSecret.Length).IsEqualTo(coordinateLength + (2 * randomLength));
            await Assert.That(deviceSecret.SequenceEqual(ownerSecret)).IsTrue();
            await Assert.That(deviceSecret.AsSpan(coordinateLength, randomLength)
                .SequenceEqual(deviceParameter.AsSpan(deviceParameter.Length - randomLength))).IsTrue();
            await Assert.That(deviceSecret.AsSpan(coordinateLength + randomLength, randomLength)
                .SequenceEqual(ownerParameter.AsSpan(ownerParameter.Length - randomLength))).IsTrue();

            byte[] deviceKey = new byte[16];
            byte[] ownerKey = new byte[16];
            try
            {
                FdoKeyDerivation.Derive(deviceSecret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, deviceKey);
                FdoKeyDerivation.Derive(ownerSecret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, ownerKey);
                await Assert.That(deviceKey.SequenceEqual(ownerKey)).IsTrue();

                byte[] plaintext = [1, 2, 3];
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] decrypted = new byte[plaintext.Length];
                byte[] tag = new byte[16];
                byte[] nonce = new byte[12];
                byte[] associatedData = [4, 5];
                FdoCoseAead.Encrypt(FdoCoseAeadAlgorithm.A128Gcm, deviceKey, nonce, plaintext, ciphertext, tag, associatedData);
                FdoCoseAead.Decrypt(FdoCoseAeadAlgorithm.A128Gcm, ownerKey, nonce, ciphertext, tag, decrypted, associatedData);
                await Assert.That(decrypted.SequenceEqual(plaintext)).IsTrue();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(deviceKey);
                CryptographicOperations.ZeroMemory(ownerKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(deviceSecret);
            CryptographicOperations.ZeroMemory(ownerSecret);
        }
    }

    [Test]
    [Arguments(0, 0, 32, 16)]
    [Arguments(0, 1, 32, 16)]
    [Arguments(1, 0, 48, 48)]
    [Arguments(1, 1, 48, 48)]
    public async Task PeerAgreementUsesBigEndianFieldsAndRoleOrderedRandoms(
        int suiteValue, int partyValue, int coordinateLength, int randomLength)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        var party = (FdoEcdhParty)partyValue;
        using var local = FdoEcdhKeyExchange.Create(suite, party);
        byte[] localParameter = local.ExportParameter();
        ECCurve curve = suite == FdoKeyExchangeSuite.Ecdh256
            ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384;
        using ECDiffieHellman peer = ECDiffieHellman.Create(curve);
        byte[] peerRandom = Enumerable.Repeat((byte)0xA5, randomLength).ToArray();
        byte[] peerParameter = EncodeParameter(peer.ExportParameters(false), peerRandom);
        using ECDiffieHellman localPublic = ECDiffieHellman.Create(DecodePublicKey(localParameter, curve, coordinateLength));
        using ECDiffieHellmanPublicKey publicKey = localPublic.PublicKey;
        byte[] expectedRaw = peer.DeriveRawSecretAgreement(publicKey);
        byte[] actual = local.DeriveSharedSecret(peerParameter);
        try
        {
            byte[] expectedX = new byte[coordinateLength];
            expectedRaw.CopyTo(expectedX.AsSpan(coordinateLength - expectedRaw.Length));
            byte[] localRandom = localParameter.AsSpan(localParameter.Length - randomLength).ToArray();
            await Assert.That(actual.AsSpan(0, coordinateLength).SequenceEqual(expectedX)).IsTrue();
            await Assert.That(actual.AsSpan(coordinateLength, randomLength).SequenceEqual(
                party == FdoEcdhParty.Device ? localRandom : peerRandom)).IsTrue();
            await Assert.That(actual.AsSpan(coordinateLength + randomLength, randomLength).SequenceEqual(
                party == FdoEcdhParty.Device ? peerRandom : localRandom)).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedRaw);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    [Test]
    [Arguments(0, 32, 16)]
    [Arguments(1, 48, 48)]
    public async Task ExportHasFixedWidthFieldsAndReturnsIndependentCopies(
        int suiteValue, int coordinateLength, int randomLength)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using var exchange = FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Device);
        using var other = FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Device);
        byte[] original = exchange.ExportParameter();
        byte[] copy = exchange.ExportParameter();
        byte[] differentKey = other.ExportParameter();

        await Assert.That(original.Length).IsEqualTo(6 + (2 * coordinateLength) + randomLength);
        await Assert.That(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(0, 2))).IsEqualTo((ushort)coordinateLength);
        await Assert.That(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(2 + coordinateLength, 2)))
            .IsEqualTo((ushort)coordinateLength);
        await Assert.That(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4 + (2 * coordinateLength), 2)))
            .IsEqualTo((ushort)randomLength);
        await Assert.That(original.AsSpan(2, (2 * coordinateLength) + 2)
            .SequenceEqual(differentKey.AsSpan(2, (2 * coordinateLength) + 2))).IsFalse();
        Array.Fill(copy, (byte)0);
        await Assert.That(exchange.ExportParameter().SequenceEqual(original)).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task RejectsMalformedFieldsInvalidPointsAndReflectionWithoutReusingTheKey(int mutation)
    {
        using var local = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        using var peer = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        byte[] valid = peer.ExportParameter();
        byte[] invalid = (byte[])valid.Clone();
        switch (mutation)
        {
            case 0:
                invalid = invalid[..^1];
                break;
            case 1:
                invalid = [.. invalid, 0];
                break;
            case 2:
                invalid[1] = 31;
                break;
            case 3:
                invalid[35] = 31;
                break;
            case 4:
                invalid[69] = 15;
                break;
            case 5:
                invalid.AsSpan(2, 32).Clear();
                invalid.AsSpan(36, 32).Clear();
                break;
        }

        await Assert.That(Throws<CryptographicException>(() => local.DeriveSharedSecret(invalid))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => local.DeriveSharedSecret(valid))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => local.ExportParameter())).IsTrue();
    }

    [Test]
    public async Task RejectsReflectedAndMismatchedCurveParameters()
    {
        using var reflected = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        byte[] ownParameter = reflected.ExportParameter();
        using var mismatched = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        using var p384 = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh384, FdoEcdhParty.Owner);

        await Assert.That(Throws<CryptographicException>(() => reflected.DeriveSharedSecret(ownParameter))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => mismatched.DeriveSharedSecret(p384.ExportParameter()))).IsTrue();
    }

    [Test]
    public async Task SuccessfulDerivationConsumesTheKeyAndDisposeIsIdempotent()
    {
        var local = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        using var peer = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        byte[] peerParameter = peer.ExportParameter();
        byte[] secret = local.DeriveSharedSecret(peerParameter);
        CryptographicOperations.ZeroMemory(secret);

        await Assert.That(Throws<InvalidOperationException>(() => local.DeriveSharedSecret(peerParameter))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => local.ExportParameter())).IsTrue();
        local.Dispose();
        local.Dispose();
        await Assert.That(Throws<ObjectDisposedException>(() => local.ExportParameter())).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => local.DeriveSharedSecret(peerParameter))).IsTrue();
    }

    [Test]
    public async Task RejectsUnknownPartyAndSuite()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoEcdhKeyExchange.Create((FdoKeyExchangeSuite)99, FdoEcdhParty.Device))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, (FdoEcdhParty)99))).IsTrue();
    }

    private static byte[] EncodeParameter(ECParameters key, byte[] random)
    {
        byte[] x = key.Q.X ?? throw new InvalidOperationException("The peer public key has no X coordinate.");
        byte[] y = key.Q.Y ?? throw new InvalidOperationException("The peer public key has no Y coordinate.");
        byte[] encoded = new byte[6 + x.Length + y.Length + random.Length];
        int offset = 0;
        foreach (byte[] part in new[] { x, y, random })
        {
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset, 2), (ushort)part.Length);
            offset += 2;
            part.CopyTo(encoded.AsSpan(offset));
            offset += part.Length;
        }

        return encoded;
    }

    private static ECParameters DecodePublicKey(byte[] parameter, ECCurve curve, int coordinateLength)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(parameter.AsSpan(0, 2)) != coordinateLength ||
            BinaryPrimitives.ReadUInt16BigEndian(parameter.AsSpan(2 + coordinateLength, 2)) != coordinateLength)
        {
            throw new InvalidOperationException("The local coordinates have the wrong lengths.");
        }

        return new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = parameter.AsSpan(2, coordinateLength).ToArray(),
                Y = parameter.AsSpan(4 + coordinateLength, coordinateLength).ToArray(),
            },
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
