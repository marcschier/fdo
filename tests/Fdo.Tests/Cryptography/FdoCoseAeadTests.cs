// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCoseAeadTests
{
    /// <summary>
    /// NIST CAVP GCM EncryptExtIV, key sizes 128/256, IV 96, PT/AAD/tag 128, count 0.
    /// NIST ACVP AES-CCM internalProjection groups 2, 70, 206, and 220.
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="keyHex"></param>
    /// <param name="nonceHex"></param>
    /// <param name="plaintextHex"></param>
    /// <param name="aadHex"></param>
    /// <param name="ciphertextHex"></param>
    /// <param name="tagHex"></param>
    /// <returns></returns>
    [Test]
    [Arguments(1,
        "C939CC13397C1D37DE6AE0E1CB7C423C",
        "B3D8CC017CBB89B39E0F67E2",
        "C3B3C41F113A31B73D9A5CD432103069",
        "24825602BD12A984E0092D3E448EDA5F",
        "93FE7D9E9BFD10348A5606E5CAFA7354",
        "0032A1DC85F1C9786925A2E71D8272DD")]
    [Arguments(3,
        "92E11DCDAA866F5CE790FD24501F92509AACF4CB8B1339D50C9C1240935DD08B",
        "AC93A1A6145299BDE902F21A",
        "2D71BCFA914E4AC045B2AA60955FAD24",
        "1E0889016F67601C8EBEA4943BC23AD6",
        "8995AE2E6DF3DBF96FAC7B7137BAE67F",
        "ECA5AA77D51D4A0A14D9C51E1DA474AB")]
    [Arguments(30,
        "35D0F28D2C560D07CC5CDC0B32B7CDD3",
        "996A0414F8684E266494B32325",
        "3B8D8DD2A2582E95D9DDE28F05DCD72064063513D17EFD846B67F1999AEED64B",
        "C5",
        "72DF9F388CF13BD258A69C2A351E354AAEC4E86D41829A95F8FAF16F1F544AEC",
        "8FCB2B314077B525E407F66D5DCE0DCE")]
    [Arguments(31,
        "E7C02307BE76E34F9DC955C62EC3CC4548B34DD032065638EE572E48109FA1BF",
        "31AD82AB4F0106FCAFD31327A4",
        "1D3597552258A41D4E563803BA99A7304F0D4F75D244DA7F154660639332A5D6",
        "23",
        "1257307F4616CD8061C2A17777AE62E9AA92011D4B04EB77BFAFC71EC6997D28",
        "6050910895F8083E3CC55E0D7B15D784")]
    [Arguments(32,
        "0D549953BB66A668B572D37418D0C4EB",
        "F20AD602F75D40",
        "C1453070BCFD5E64003BEE427F3673BEF254B488730974EF383019EDD7159E33",
        "EA4339137BF009CBAD7F879C168000EB7E3CE3C387472FBEC7741B8F72156345",
        "48653A97A2802923E490C9D248E3618236C6A3E59B3E916C9A879212A7C41A4B",
        "2E1724F7A952FF13C0011768D773E28E")]
    [Arguments(33,
        "EA8C2AC93F38EA059A8FF17182ACD4810C9352175CA0757EC704ACCB2BEC89D7",
        "388389CDECAC25",
        "5F4BC0F8D2B65273574D29D1184EDCE803AE7557C30B71AA85FD7F91AC4153C3",
        "83C5666A36B6E954FDC573E12552F9E5EDC9132451A9BF213FF0885C9986D73C",
        "5D6BEE85D6BBF6369E62C3497A2F0E165277AA8124C22479D783014D0704DF1B",
        "07961BCE4BF99B36C6C6AC09A690A37B")]
    public async Task MatchesNistEncryptionAndDecryptionVectors(
        int algorithm,
        string keyHex,
        string nonceHex,
        string plaintextHex,
        string aadHex,
        string ciphertextHex,
        string tagHex)
    {
        var type = (FdoCoseAeadAlgorithm)algorithm;
        byte[] key = Convert.FromHexString(keyHex);
        byte[] nonce = Convert.FromHexString(nonceHex);
        byte[] plaintext = Convert.FromHexString(plaintextHex);
        byte[] associatedData = Convert.FromHexString(aadHex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        if (!FdoCoseAead.IsSupported(type))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoCoseAead.Encrypt(type, key, nonce, plaintext, ciphertext, tag, associatedData))).IsTrue();
            return;
        }

        FdoCoseAead.Encrypt(type, key, nonce, plaintext, ciphertext, tag, associatedData);
        var decrypted = new byte[plaintext.Length];
        FdoCoseAead.Decrypt(type, key, nonce, ciphertext, tag, decrypted, associatedData);

        await Assert.That(Convert.ToHexString(ciphertext)).IsEqualTo(ciphertextHex);
        await Assert.That(Convert.ToHexString(tag)).IsEqualTo(tagHex);
        await Assert.That(Convert.ToHexString(decrypted)).IsEqualTo(plaintextHex);
    }

    [Test]
    public async Task EmptyPlaintextStillAuthenticatesAssociatedData()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        byte[] key = Convert.FromHexString("4B2CBE2158F5D6A28CC798DF4F99F777");
        byte[] nonce = Convert.FromHexString("3851BAF79831605B75086E79");
        byte[] associatedData = Convert.FromHexString("4607F76F4FDA85DAFDC8CE085E0CE5");
        byte[] tag = new byte[16];

        if (!FdoCoseAead.IsSupported(algorithm))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => FdoCoseAead.Encrypt(
                algorithm, key, nonce, Array.Empty<byte>(), Array.Empty<byte>(), tag, associatedData))).IsTrue();
            return;
        }

        FdoCoseAead.Encrypt(algorithm, key, nonce, Array.Empty<byte>(), Array.Empty<byte>(), tag, associatedData);
        FdoCoseAead.Decrypt(algorithm, key, nonce, Array.Empty<byte>(), tag, Array.Empty<byte>(), associatedData);

        await Assert.That(Convert.ToHexString(tag)).IsEqualTo("9E557D92647C1510D4101EBEED0C52DD");
        associatedData[0] ^= 1;
        await Assert.That(Throws<CryptographicException>(() => FdoCoseAead.Decrypt(
            algorithm, key, nonce, Array.Empty<byte>(), tag, Array.Empty<byte>(), associatedData))).IsTrue();
    }

    [Test]
    [Arguments(1, 16, 12)]
    [Arguments(3, 32, 12)]
    [Arguments(30, 16, 13)]
    [Arguments(31, 32, 13)]
    [Arguments(32, 16, 7)]
    [Arguments(33, 32, 7)]
    public async Task ModifiedCiphertextTagNonceOrAssociatedDataIsRejectedAndClearsOutput(
        int algorithm, int keyLength, int nonceLength)
    {
        var type = (FdoCoseAeadAlgorithm)algorithm;
        byte[] key = new byte[keyLength];
        byte[] nonce = new byte[nonceLength];
        byte[] plaintext = Convert.FromHexString("010203040506070809");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] associatedData = [0x05, 0x06];
        if (!FdoCoseAead.IsSupported(type))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoCoseAead.Encrypt(type, key, nonce, plaintext, ciphertext, tag, associatedData))).IsTrue();
            return;
        }

        FdoCoseAead.Encrypt(type, key, nonce, plaintext, ciphertext, tag, associatedData);
        for (int alteration = 0; alteration < 4; alteration++)
        {
            byte[] changedNonce = nonce.ToArray();
            byte[] changedCiphertext = ciphertext.ToArray();
            byte[] changedTag = tag.ToArray();
            byte[] changedData = associatedData.ToArray();
            byte[][] inputs = [changedCiphertext, changedTag, changedNonce, changedData];
            inputs[alteration][0] ^= 1;
            byte[] output = Enumerable.Repeat((byte)0xA5, plaintext.Length).ToArray();

            await Assert.That(Throws<CryptographicException>(() => FdoCoseAead.Decrypt(
                type, key, changedNonce, changedCiphertext, changedTag, output, changedData))).IsTrue();
            await Assert.That(output.All(value => value == 0)).IsTrue();
        }
    }

    [Test]
    public async Task RejectsIncorrectAlgorithmLengthsAndOverlappingBuffers()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        byte[] input = Enumerable.Repeat((byte)0xA5, 16).ToArray();
        byte[] output = new byte[16];
        byte[] tag = new byte[16];
        byte[] aad = [0x01];

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => FdoCoseAead.IsSupported(
            (FdoCoseAeadAlgorithm)2))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, new byte[32], nonce, input, output, tag, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, new byte[13], input, output, tag, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            FdoCoseAeadAlgorithm.AesCcm64_128_128, key, new byte[13], input, output, tag, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, nonce, input, output, new byte[15], aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, nonce, input, new byte[15], tag, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, nonce, input, input, tag, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, nonce, input, output, output, aad))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Decrypt(
            algorithm, key, nonce, input, tag, input, aad))).IsTrue();
        await Assert.That(input.All(value => value == 0xA5)).IsTrue();
    }

    [Test]
    public async Task Ccm16Accepts65535BytesAndRejects65536()
    {
        var algorithm = FdoCoseAeadAlgorithm.AesCcm16_128_128;
        byte[] key = new byte[16];
        byte[] nonce = new byte[13];
        byte[] plaintext = new byte[ushort.MaxValue];
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] tooLarge = new byte[ushort.MaxValue + 1];

        await Assert.That(Throws<ArgumentException>(() => FdoCoseAead.Encrypt(
            algorithm, key, nonce, tooLarge, new byte[tooLarge.Length], tag, Array.Empty<byte>()))).IsTrue();
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => FdoCoseAead.Encrypt(
                algorithm, key, nonce, plaintext, ciphertext, tag, Array.Empty<byte>()))).IsTrue();
            return;
        }

        plaintext[^1] = 0x7F;
        FdoCoseAead.Encrypt(algorithm, key, nonce, plaintext, ciphertext, tag, Array.Empty<byte>());
        byte[] decrypted = new byte[plaintext.Length];
        FdoCoseAead.Decrypt(algorithm, key, nonce, ciphertext, tag, decrypted, Array.Empty<byte>());

        await Assert.That(decrypted.SequenceEqual(plaintext)).IsTrue();
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
