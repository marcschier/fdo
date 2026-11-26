// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoDeviceHmacSecretPolicyTests
{
    [Test]
    [Arguments(5, 32)]
    [Arguments(6, 64)]
    public async Task RequiredLengthMatchesTheNormativeVoucherHmacSize(int algorithm, int expectedLength)
    {
        int actual = FdoDeviceHmacSecretPolicy.GetRequiredLength((FdoHashAlgorithm)algorithm);

        await Assert.That(actual).IsEqualTo(expectedLength);
    }

    [Test]
    [Arguments(5, 32)]
    [Arguments(6, 64)]
    public async Task GeneratedSecretHasTheRequiredLength(int algorithm, int expectedLength)
    {
        byte[] secret = FdoDeviceHmacSecretPolicy.Generate((FdoHashAlgorithm)algorithm);
        try
        {
            await Assert.That(secret.Length).IsEqualTo(expectedLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    [Test]
    [Arguments(5, 31)]
    [Arguments(5, 33)]
    [Arguments(6, 63)]
    [Arguments(6, 65)]
    public async Task RejectsSecretsShorterOrLongerThanTheRequiredLength(int algorithm, int actualLength)
    {
        await Assert.That(Throws<ArgumentException>(() =>
            FdoDeviceHmacSecretPolicy.ValidateLength((FdoHashAlgorithm)algorithm, actualLength))).IsTrue();
    }

    [Test]
    public async Task RejectsDigestAlgorithmsAndUnknownValues()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoDeviceHmacSecretPolicy.GetRequiredLength(FdoHashAlgorithm.Sha256))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoDeviceHmacSecretPolicy.Generate((FdoHashAlgorithm)0))).IsTrue();
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
