// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Numerics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoDhKeyExchangeTests
{
    [Test]
    [Arguments(0, 256)]
    [Arguments(1, 384)]
    public async Task BothPartiesAgreeOnFixedWidthSecretsAndConsumeTheirKeys(int groupValue, int width)
    {
        var group = (FdoDhGroup)groupValue;
        if (!OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => FdoDhKeyExchange.Create(group))).IsTrue();
            return;
        }

        using var device = FdoDhKeyExchange.Create(group);
        using var owner = FdoDhKeyExchange.Create(group);
        byte[] deviceParameter = device.ExportParameter();
        byte[] ownerParameter = owner.ExportParameter();
        byte[] copy = device.ExportParameter();
        Array.Fill(copy, (byte)0);
        await Assert.That(device.ExportParameter().AsSpan().SequenceEqual(deviceParameter)).IsTrue();
        await Assert.That(deviceParameter.Length).IsEqualTo(width);
        await Assert.That(ownerParameter.Length).IsEqualTo(width);

        byte[] deviceSecret = device.DeriveSharedSecret(ownerParameter);
        byte[] ownerSecret = owner.DeriveSharedSecret(deviceParameter);
        try
        {
            await Assert.That(deviceSecret.Length).IsEqualTo(width);
            await Assert.That(ownerSecret.Length).IsEqualTo(width);
            await Assert.That(deviceSecret.AsSpan().SequenceEqual(ownerSecret)).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() => device.ExportParameter())).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() => DeriveAndClear(device, ownerParameter))).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() => owner.ExportParameter())).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(deviceSecret);
            CryptographicOperations.ZeroMemory(ownerSecret);
        }
    }

    [Test]
    [Arguments(0, 256)]
    [Arguments(1, 384)]
    public async Task GeneratorPeerProducesTheLocalPublicValueWithLeadingZeroInput(int groupValue, int width)
    {
        var group = (FdoDhGroup)groupValue;
        if (!OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => FdoDhKeyExchange.Create(group))).IsTrue();
            return;
        }

        using var local = FdoDhKeyExchange.Create(group);
        byte[] expected = local.ExportParameter();
        byte[] generator = new byte[width];
        generator[^1] = 2;
        byte[] actual = local.DeriveSharedSecret(generator);
        try
        {
            await Assert.That(actual.Length).IsEqualTo(width);
            await Assert.That(actual.AsSpan().SequenceEqual(expected)).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    [Test]
    [Arguments(0, 0)]
    [Arguments(0, 1)]
    [Arguments(0, 2)]
    [Arguments(0, 3)]
    [Arguments(0, 4)]
    [Arguments(0, 5)]
    [Arguments(0, 6)]
    [Arguments(0, 7)]
    [Arguments(0, 8)]
    [Arguments(1, 0)]
    [Arguments(1, 1)]
    [Arguments(1, 2)]
    [Arguments(1, 3)]
    [Arguments(1, 4)]
    [Arguments(1, 5)]
    [Arguments(1, 6)]
    [Arguments(1, 7)]
    [Arguments(1, 8)]
    public async Task RejectsInvalidPeerValuesAndConsumesTheKey(int groupValue, int mutation)
    {
        var group = (FdoDhGroup)groupValue;
        if (!OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => FdoDhKeyExchange.Create(group))).IsTrue();
            return;
        }

        using var local = FdoDhKeyExchange.Create(group);
        byte[] ownParameter = local.ExportParameter();
        byte[] primeBytes = Convert.FromHexString(group == FdoDhGroup.DhkexId14 ? Prime14 : Prime15);
        var prime = new BigInteger(primeBytes, isUnsigned: true, isBigEndian: true);
        byte[] invalid = mutation switch
        {
            0 => new byte[primeBytes.Length - 1],
            1 => new byte[primeBytes.Length + 1],
            2 => new byte[primeBytes.Length],
            3 => Number(1, primeBytes.Length),
            4 => Number(prime - 1, primeBytes.Length),
            5 => Number(prime, primeBytes.Length),
            6 => Number(prime + 1, primeBytes.Length),
            7 => Number(prime - 2, primeBytes.Length),
            8 => ownParameter,
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        byte[] retry = Number(2, primeBytes.Length);

        await Assert.That(Throws<CryptographicException>(() => DeriveAndClear(local, invalid))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => DeriveAndClear(local, retry))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => local.ExportParameter())).IsTrue();
    }

    [Test]
    public async Task RejectsUnknownGroupsAndDisposedKeys()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoDhKeyExchange.Create((FdoDhGroup)99))).IsTrue();
        if (!OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoDhKeyExchange.Create(FdoDhGroup.DhkexId14))).IsTrue();
            return;
        }

        var local = FdoDhKeyExchange.Create(FdoDhGroup.DhkexId14);
        byte[] parameter = local.ExportParameter();
        local.Dispose();
        local.Dispose();
        await Assert.That(Throws<ObjectDisposedException>(() => local.ExportParameter())).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => DeriveAndClear(local, parameter))).IsTrue();
    }

    private static byte[] Number(BigInteger value, int width)
    {
        byte[] number = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] result = new byte[width];
        number.CopyTo(result.AsSpan(width - number.Length));
        return result;
    }

    private static void DeriveAndClear(FdoDhKeyExchange exchange, byte[] peer)
    {
        byte[] secret = exchange.DeriveSharedSecret(peer);
        CryptographicOperations.ZeroMemory(secret);
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

    private const string PrimePrefix =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A";

    private const string Prime14 = PrimePrefix + "8AACAA68FFFFFFFFFFFFFFFF";

    private const string Prime15 = PrimePrefix +
        "8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
}
