// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoKeyDerivationTests
{
    [Test]
    [Arguments(
        "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE",
        16,
        "9486EF2D8E9FB4E0B270ACB090D00119",
        "43F7B6F4204C0A4951EEC176CBD791996FF04741C791E181DCA98A6AD63442C2")]
    [Arguments(
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746",
        48,
        "D4CAC5AF7D1AE6A178EADD5070067B92",
        "8F0FF9DD2FD395D341D763D981F3D7C3B75F20A0E0F0F5BABF46D2FC722A38E9")]
    public async Task EcdhGcmUsesSha256WithDeviceThenOwnerRandoms(
        string sharedXHex, int randomLength, string expected128, string expected256)
    {
        // RFC 5903 sections 8.1-8.2 supply Shx; the FDO KDF results were
        // independently computed with Python HMAC, not captured from a peer.
        byte[] sharedX = Convert.FromHexString(sharedXHex);
        byte[] sharedSecret = new byte[sharedX.Length + (2 * randomLength)];
        sharedX.CopyTo(sharedSecret, 0);
        for (int i = 0; i < randomLength; i++)
        {
            sharedSecret[sharedX.Length + i] = (byte)i;
            sharedSecret[sharedX.Length + randomLength + i] = (byte)(0x80 + i);
        }

        byte[] key128 = new byte[16];
        byte[] key256 = new byte[32];
        try
        {
            FdoKeyDerivation.Derive(sharedSecret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, key128);
            FdoKeyDerivation.Derive(sharedSecret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, key256);
            await Assert.That(Convert.ToHexString(key128)).IsEqualTo(expected128);
            await Assert.That(Convert.ToHexString(key256)).IsEqualTo(expected256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(key128);
            CryptographicOperations.ZeroMemory(key256);
        }
    }

    [Test]
    public async Task PublishedFdoFramingKnownResultMatches()
    {
        // Mathematical vector from go-fdo; it is not an FDO 2.0 interoperability vector.
        // https://github.com/fido-device-onboard/go-fdo/blob/65061850e1c91a2cfe83c2dea748989a7e70c110/internal/nistkdf/kdf_test.go
        byte[] secret = Convert.FromHexString(
            "08C9DC0CC5E9DD2558A12AE60CD00670D01A09CCA52BAE8A671A21E1BABDB25B" +
            "C21963C48B4AA77BB8ED338F0C5A15EFEE069CE10A09BE2AACF857B8DCD9DF8E");
        byte[] expected = Convert.FromHexString(
            "E5E959C8CBDD5989C819F7EA8C69BCB3F70A442830BA235C5AA0B4047D0CDA0B");
        byte[] result = new byte[expected.Length];

        FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, result);

        await Assert.That(result.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task NistSha256CounterModeVectorSpansTwoBlocks()
    {
        // NIST CAVP CounterMode: HMAC_SHA256, BEFORE_FIXED, RLEN=8, COUNT=30.
        // https://github.com/pyca/cryptography/blob/9f119db1beba2834af325cc631b3d787b895943d/vectors/cryptography_vectors/KDF/nist-800-108-KBKDF-CTR.txt
        byte[] secret = Convert.FromHexString("63A657FB6C5BACB9A124D3E7DB8BBB7D42BFDFAF8F04CB6359CD888C70669652");
        byte[] fixedInput = Convert.FromHexString(
            "2697B6EC112CAB4D6F1714C991C17D44FB36A0B6EF0B0F5451619AB248950F56" +
            "F403215C78711AA563683CED05BE7246F32574FA294F162DBBEB3DEE");
        byte[] expected = Convert.FromHexString(
            "1992E75756FA64734D5CAECC5F6420FCB28B8B90421EEE97DC8B6140CE185184" +
            "05688BEA489D2AAA");
        byte[] result = new byte[expected.Length];

        FdoKeyDerivation.DeriveCounterMode(
            secret, fixedInput, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, result);

        await Assert.That(result.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task NistSha384CounterModeVectorMatches()
    {
        // NIST CAVP CounterMode: HMAC_SHA384, BEFORE_FIXED, RLEN=8, COUNT=10.
        // https://github.com/pyca/cryptography/blob/9f119db1beba2834af325cc631b3d787b895943d/vectors/cryptography_vectors/KDF/nist-800-108-KBKDF-CTR.txt
        byte[] secret = Convert.FromHexString(
            "218F47301A3ADF39A4E1DDC25A1DF2B7DB53D7780C207F47AB4CEFCAA960ED82" +
            "CB6CBC34B97B4C332D52CA81CC40CB9A");
        byte[] fixedInput = Convert.FromHexString(
            "60DCB116D7CFD3CCA7315C9DC7E9650F886B67D9FBCD98C226239A0F66EFF075" +
            "DA23C6CB750A2129AE71B9582934F57423A815249CAC2C61F958B35D");
        byte[] expected = Convert.FromHexString("26B01D94C4DD51A9C8B54F78647257F9E937A8D67DFFA78F85749CDFB22DB620");
        byte[] result = new byte[expected.Length];

        FdoKeyDerivation.DeriveCounterMode(
            secret, fixedInput, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA384, result);

        await Assert.That(result.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task FdoSha256UsesContextBitLengthAndThreeCounterBlocks()
    {
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] context = Convert.FromHexString("DEADBEEF");
        byte[] result = new byte[80];
        byte[] first = HMACSHA256.HashData(secret, Convert.FromHexString(
            "014649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0280"));
        byte[] second = HMACSHA256.HashData(secret, Convert.FromHexString(
            "024649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0280"));
        byte[] third = HMACSHA256.HashData(secret, Convert.FromHexString(
            "034649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0280"));

        FdoKeyDerivation.Derive(secret, context, HashAlgorithmName.SHA256, result);

        await Assert.That(result.AsSpan(0, 32).SequenceEqual(first)).IsTrue();
        await Assert.That(result.AsSpan(32, 32).SequenceEqual(second)).IsTrue();
        await Assert.That(result.AsSpan(64, 16).SequenceEqual(third.AsSpan(0, 16))).IsTrue();
    }

    [Test]
    public async Task FdoSha384UsesContextBitLengthAndTwoCounterBlocks()
    {
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] context = Convert.FromHexString("DEADBEEF");
        byte[] result = new byte[80];
        byte[] first = HMACSHA384.HashData(secret, Convert.FromHexString(
            "014649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0280"));
        byte[] second = HMACSHA384.HashData(secret, Convert.FromHexString(
            "024649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0280"));

        FdoKeyDerivation.Derive(secret, context, HashAlgorithmName.SHA384, result);

        await Assert.That(result.AsSpan(0, 48).SequenceEqual(first)).IsTrue();
        await Assert.That(result.AsSpan(48, 32).SequenceEqual(second.AsSpan(0, 32))).IsTrue();
    }

    [Test]
    public async Task EncryptThenMacSha256UsesTotalLengthAndVerificationKeyFirst()
    {
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] context = Convert.FromHexString("DEADBEEF");
        byte[] verificationKey = new byte[32];
        byte[] encryptionKey = new byte[16];
        byte[] first = HMACSHA256.HashData(secret, Convert.FromHexString(
            "014649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0180"));
        byte[] second = HMACSHA256.HashData(secret, Convert.FromHexString(
            "024649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0180"));

        FdoKeyDerivation.DeriveEncryptThenMac(
            secret, context, HashAlgorithmName.SHA256, verificationKey, encryptionKey);

        await Assert.That(verificationKey.AsSpan().SequenceEqual(first)).IsTrue();
        await Assert.That(encryptionKey.AsSpan().SequenceEqual(second.AsSpan(0, 16))).IsTrue();
    }

    [Test]
    public async Task EncryptThenMacSha384SplitsWithinTheSecondBlock()
    {
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] context = Convert.FromHexString("DEADBEEF");
        byte[] verificationKey = new byte[64];
        byte[] encryptionKey = new byte[32];
        byte[] first = HMACSHA384.HashData(secret, Convert.FromHexString(
            "014649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0300"));
        byte[] second = HMACSHA384.HashData(secret, Convert.FromHexString(
            "024649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CDEADBEEF0300"));

        FdoKeyDerivation.DeriveEncryptThenMac(
            secret, context, HashAlgorithmName.SHA384, verificationKey, encryptionKey);

        await Assert.That(verificationKey.AsSpan(0, 48).SequenceEqual(first)).IsTrue();
        await Assert.That(verificationKey.AsSpan(48, 16).SequenceEqual(second.AsSpan(0, 16))).IsTrue();
        await Assert.That(encryptionKey.AsSpan().SequenceEqual(second.AsSpan(16, 32))).IsTrue();
    }

    [Test]
    public async Task EncryptThenMacSupportsAdjacentOutputsAndPreservesSurroundingBytes()
    {
        // The go-fdo vector establishes KDF output, not FDO 2.0 interoperability.
        // The equal split exercises adjacent buffers; it is not a cipher suite.
        // https://github.com/fido-device-onboard/go-fdo/blob/65061850e1c91a2cfe83c2dea748989a7e70c110/internal/nistkdf/kdf_test.go
        byte[] secret = Convert.FromHexString(
            "08C9DC0CC5E9DD2558A12AE60CD00670D01A09CCA52BAE8A671A21E1BABDB25B" +
            "C21963C48B4AA77BB8ED338F0C5A15EFEE069CE10A09BE2AACF857B8DCD9DF8E");
        byte[] expected = Convert.FromHexString(
            "E5E959C8CBDD5989C819F7EA8C69BCB3F70A442830BA235C5AA0B4047D0CDA0B");
        byte[] outputs = new byte[48];
        Array.Fill(outputs, (byte)0x5A);

        FdoKeyDerivation.DeriveEncryptThenMac(
            secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256,
            outputs.AsSpan(8, 16), outputs.AsSpan(24, 16));

        await Assert.That(outputs.AsSpan(8, 32).SequenceEqual(expected)).IsTrue();
        await Assert.That(outputs.AsSpan(0, 8).ToArray().All(value => value == 0x5A)).IsTrue();
        await Assert.That(outputs.AsSpan(40, 8).ToArray().All(value => value == 0x5A)).IsTrue();
    }

    [Test]
    public async Task EncryptThenMacAcceptsTheMaximumEncodedBitLength()
    {
        // These lengths exercise the KDF boundary, not a cipher suite.
        byte[] secret = [0x01];
        byte[] verificationKey = new byte[8190];
        byte[] encryptionKey = new byte[1];
        byte[] finalBlock = HMACSHA384.HashData(secret, Convert.FromHexString(
            "AB4649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CFFF8"));

        FdoKeyDerivation.DeriveEncryptThenMac(
            secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA384, verificationKey, encryptionKey);

        await Assert.That(verificationKey.AsSpan(8160, 30).SequenceEqual(finalBlock.AsSpan(0, 30))).IsTrue();
        await Assert.That(encryptionKey[0]).IsEqualTo(finalBlock[30]);
    }

    [Test]
    public async Task EncryptThenMacRejectsInvalidInputsWithoutChangingOutputs()
    {
        byte[] secret = [0x01];
        byte[] verificationKey = new byte[32];
        byte[] encryptionKey = new byte[16];
        byte[] counterLimitedKey = new byte[8160];
        byte[] oversizedKey = new byte[8191];
        byte[] oneByteKey = [0x5A];
        Array.Fill(verificationKey, (byte)0x5A);
        Array.Fill(encryptionKey, (byte)0x5A);
        Array.Fill(counterLimitedKey, (byte)0x5A);
        Array.Fill(oversizedKey, (byte)0x5A);

        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, Span<byte>.Empty, encryptionKey))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, verificationKey, Span<byte>.Empty))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, verificationKey, encryptionKey))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA1, verificationKey, encryptionKey))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, counterLimitedKey, oneByteKey))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA384, oversizedKey, oneByteKey))).IsTrue();
        await Assert.That(verificationKey.All(value => value == 0x5A)).IsTrue();
        await Assert.That(encryptionKey.All(value => value == 0x5A)).IsTrue();
        await Assert.That(counterLimitedKey.All(value => value == 0x5A)).IsTrue();
        await Assert.That(oversizedKey.All(value => value == 0x5A)).IsTrue();
        await Assert.That(oneByteKey[0]).IsEqualTo((byte)0x5A);
    }

    [Test]
    public async Task EncryptThenMacRejectsOverlappingInputsAndOutputs()
    {
        byte[] secret = [0x01];
        byte[] context = [0x02];
        byte[] buffer = new byte[64];
        byte[] separate = new byte[32];
        Array.Fill(buffer, (byte)0x5A);
        Array.Fill(separate, (byte)0x5A);

        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, context, HashAlgorithmName.SHA256, buffer.AsSpan(0, 32), buffer.AsSpan(16, 16)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                buffer.AsSpan(0, 32), context, HashAlgorithmName.SHA256, buffer.AsSpan(16, 16), separate))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                buffer.AsSpan(0, 32), context, HashAlgorithmName.SHA256, separate, buffer.AsSpan(16, 16)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, buffer.AsSpan(0, 32), HashAlgorithmName.SHA256, buffer.AsSpan(16, 16), separate))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.DeriveEncryptThenMac(
                secret, buffer.AsSpan(0, 32), HashAlgorithmName.SHA256, separate, buffer.AsSpan(16, 16)))).IsTrue();
        await Assert.That(buffer.All(value => value == 0x5A)).IsTrue();
        await Assert.That(separate.All(value => value == 0x5A)).IsTrue();
    }

    [Test]
    public async Task Sha256CounterAccepts255BlocksAndRejects256()
    {
        byte[] secret = [0x01];
        byte[] result = new byte[255 * 32];
        byte[] finalBlock = HMACSHA256.HashData(secret, Convert.FromHexString(
            "FF4649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CFF00"));

        FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, result);

        await Assert.That(result.AsSpan(result.Length - 32).SequenceEqual(finalBlock)).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, new byte[(255 * 32) + 1]))).IsTrue();
    }

    [Test]
    public async Task Sha384BitLengthAccepts8191BytesAndRejects8192()
    {
        byte[] secret = [0x01];
        byte[] result = new byte[8191];
        byte[] finalBlock = HMACSHA384.HashData(secret, Convert.FromHexString(
            "AB4649444F2D4B4446004175746F6D617469634F6E626F61726454756E6E656CFFF8"));

        FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA384, result);

        await Assert.That(result.AsSpan(result.Length - 31).SequenceEqual(finalBlock.AsSpan(0, 31))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA384, new byte[8192]))).IsTrue();
    }

    [Test]
    public async Task OutputLengthChangesTheDerivedMaterial()
    {
        byte[] secret = [0x01];
        byte[] shortOutput = new byte[16];
        byte[] longOutput = new byte[32];

        FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, shortOutput);
        FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, longOutput);

        await Assert.That(shortOutput.AsSpan().SequenceEqual(longOutput.AsSpan(0, 16))).IsFalse();
    }

    [Test]
    public async Task InvalidInputsAndOverlappingBuffersAreRejected()
    {
        byte[] secret = [0x01];
        byte[] buffer = new byte[64];
        Array.Fill(buffer, (byte)0x5A);

        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.Derive(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, buffer))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, Span<byte>.Empty))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA1, buffer))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.Derive(secret, ReadOnlySpan<byte>.Empty, default, buffer))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.Derive(buffer.AsSpan(0, 32), ReadOnlySpan<byte>.Empty, HashAlgorithmName.SHA256, buffer.AsSpan(16, 16)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoKeyDerivation.Derive(secret, buffer.AsSpan(0, 32), HashAlgorithmName.SHA256, buffer.AsSpan(16, 16)))).IsTrue();
        await Assert.That(buffer.All(value => value == 0x5A)).IsTrue();
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
