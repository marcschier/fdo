// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoAsymKeyExchangeTests
{
    [Test]
    [Arguments(0, 2048, 32)]
    [Arguments(1, 3072, 96)]
    public async Task BothPartiesDeriveTheDeviceSecretAndOwnerContext(
        int suiteValue, int keyBits, int randomLength)
    {
        using RSA ownerKey = RSA.Create(keyBits);
        using RSA ownerPublicKey = RSA.Create();
        ownerPublicKey.ImportParameters(ownerKey.ExportParameters(false));
        var suite = (FdoAsymSuite)suiteValue;
        using var device = FdoAsymKeyExchange.Create(suite, FdoAsymParty.Device, ownerPublicKey);
        using var owner = FdoAsymKeyExchange.Create(suite, FdoAsymParty.Owner, ownerKey);
        byte[] deviceParameter = device.ExportParameter();
        byte[] ownerParameter = owner.ExportParameter();
        byte[] copy = owner.ExportParameter();
        Array.Fill(copy, (byte)0);
        await Assert.That(owner.ExportParameter().AsSpan().SequenceEqual(ownerParameter)).IsTrue();
        await Assert.That(deviceParameter.Length).IsEqualTo(keyBits / 8);
        await Assert.That(ownerParameter.Length).IsEqualTo(randomLength);

        byte[] deviceSecret = device.DeriveSharedSecret(ownerParameter, out byte[] deviceContext);
        byte[] ownerSecret = owner.DeriveSharedSecret(deviceParameter, out byte[] ownerContext);
        byte[] independentlyDecrypted = ownerKey.Decrypt(deviceParameter, RSAEncryptionPadding.OaepSHA256);
        try
        {
            await Assert.That(deviceSecret.Length).IsEqualTo(randomLength);
            await Assert.That(deviceSecret.AsSpan().SequenceEqual(ownerSecret)).IsTrue();
            await Assert.That(deviceSecret.AsSpan().SequenceEqual(independentlyDecrypted)).IsTrue();
            await Assert.That(deviceContext.AsSpan().SequenceEqual(ownerParameter)).IsTrue();
            await Assert.That(ownerContext.AsSpan().SequenceEqual(ownerParameter)).IsTrue();

            byte[] deviceKey = new byte[32];
            byte[] ownerDerivedKey = new byte[32];
            try
            {
                FdoKeyDerivation.Derive(deviceSecret, deviceContext, HashAlgorithmName.SHA256, deviceKey);
                FdoKeyDerivation.Derive(ownerSecret, ownerContext, HashAlgorithmName.SHA256, ownerDerivedKey);
                await Assert.That(deviceKey.AsSpan().SequenceEqual(ownerDerivedKey)).IsTrue();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(deviceKey);
                CryptographicOperations.ZeroMemory(ownerDerivedKey);
            }

            await Assert.That(Throws<InvalidOperationException>(() => device.ExportParameter())).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() => DeriveAndClear(owner, deviceParameter))).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(deviceSecret);
            CryptographicOperations.ZeroMemory(ownerSecret);
            CryptographicOperations.ZeroMemory(deviceContext);
            CryptographicOperations.ZeroMemory(ownerContext);
            CryptographicOperations.ZeroMemory(independentlyDecrypted);
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task OwnerRejectsInvalidCiphertextsAndConsumesTheExchange(int mutation)
    {
        using RSA key = RSA.Create(2048);
        using var device = FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, FdoAsymParty.Device, key);
        using var owner = FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, FdoAsymParty.Owner, key);
        byte[] valid = device.ExportParameter();
        byte[] invalid = mutation switch
        {
            0 => valid[..^1],
            1 => [.. valid, 0],
            2 => new byte[valid.Length],
            3 => key.Encrypt(new byte[31], RSAEncryptionPadding.OaepSHA256),
            4 => key.Encrypt(new byte[32], RSAEncryptionPadding.OaepSHA1),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };

        await Assert.That(Throws<CryptographicException>(() => DeriveAndClear(owner, invalid))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => DeriveAndClear(owner, valid))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => owner.ExportParameter())).IsTrue();
    }

    [Test]
    public async Task RejectsWrongOwnerKeyAndMalformedOwnerRandom()
    {
        using RSA key = RSA.Create(2048);
        using RSA wrongKey = RSA.Create(2048);
        using var device = FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, FdoAsymParty.Device, key);
        using var owner = FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, FdoAsymParty.Owner, wrongKey);
        byte[] deviceParameter = device.ExportParameter();

        await Assert.That(Throws<CryptographicException>(() => DeriveAndClear(owner, deviceParameter))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => DeriveAndClear(device, new byte[31]))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => DeriveAndClear(device, new byte[32]))).IsTrue();
    }

    [Test]
    public async Task RejectsInvalidSuitesAndDisposedExchangesWithoutDisposingTheOwnerKey()
    {
        using RSA key = RSA.Create(2048);
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoAsymKeyExchange.Create((FdoAsymSuite)99, FdoAsymParty.Device, key))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, (FdoAsymParty)99, key))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoAsymKeyExchange.Create(FdoAsymSuite.Asym3072, FdoAsymParty.Owner, key))).IsTrue();

        var owner = FdoAsymKeyExchange.Create(FdoAsymSuite.Asym2048, FdoAsymParty.Owner, key);
        owner.Dispose();
        owner.Dispose();
        await Assert.That(Throws<ObjectDisposedException>(() => owner.ExportParameter())).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => DeriveAndClear(owner, new byte[256]))).IsTrue();
        await Assert.That(key.KeySize).IsEqualTo(2048);
    }

    private static void DeriveAndClear(FdoAsymKeyExchange exchange, byte[] peer)
    {
        byte[] secret = exchange.DeriveSharedSecret(peer, out byte[] context);
        CryptographicOperations.ZeroMemory(secret);
        CryptographicOperations.ZeroMemory(context);
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
