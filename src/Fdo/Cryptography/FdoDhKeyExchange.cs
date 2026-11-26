using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal enum FdoDhGroup
{
    DhkexId14,
    DhkexId15,
}

/// <summary>
/// An internal, single-use Linux DH exchange. Public values and the raw
/// shared secret use fixed-width unsigned big-endian encoding for paired peers.
/// The caller must authenticate the peer parameter before using the result.
/// </summary>
internal sealed partial class FdoDhKeyExchange : IFdoPairedKeyExchange
{
    private const int PublicKeySelection = 0x86;
    private const int KeyPairSelection = 0x87;
    private readonly object _sync = new();
    private readonly FdoDhGroup _group;
    private readonly byte[] _parameter;
    private SafeOpenSslKey? _key;
    private bool _attempted;
    private bool _disposed;

    private FdoDhKeyExchange(FdoDhGroup group, SafeOpenSslKey key, byte[] parameter)
    {
        _group = group;
        _key = key;
        _parameter = parameter;
    }

    public static FdoDhKeyExchange Create(FdoDhGroup group)
    {
        (int width, int exponentBits) = group switch
        {
            FdoDhGroup.DhkexId14 => (256, 256),
            FdoDhGroup.DhkexId15 => (384, 768),
            _ => throw new ArgumentOutOfRangeException(nameof(group)),
        };
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Paired finite-field DH currently requires OpenSSL 3 on Linux.");
        }

        return CreateLinux(group, width, exponentBits);
    }

    public byte[] ExportParameter()
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            return (byte[])_parameter.Clone();
        }
    }

    /// <summary>
    /// Consumes the ephemeral key even on failure. The caller must clear the
    /// returned secret and apply the FDO KDF before using it as key material.
    /// </summary>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerParameter)
    {
        lock (_sync)
        {
            ThrowIfUnavailable();
            _attempted = true;
            try
            {
                if (peerParameter.Length != _parameter.Length)
                {
                    throw new CryptographicException("The peer DH parameter has an invalid length.");
                }

                if (peerParameter.SequenceEqual(_parameter))
                {
                    throw new CryptographicException("The peer DH public value matches the local ephemeral value.");
                }

                return DeriveLinux(_group, _key!, peerParameter);
            }
            finally
            {
                _key!.Dispose();
                _key = null;
            }
        }
    }

    byte[] IFdoPairedKeyExchange.DeriveSharedSecret(ReadOnlySpan<byte> peerParameter, out byte[] contextRand)
    {
        contextRand = Array.Empty<byte>();
        return DeriveSharedSecret(peerParameter);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (!_disposed)
            {
                _disposed = true;
                _key?.Dispose();
                _key = null;
            }
        }
    }

    private static unsafe FdoDhKeyExchange CreateLinux(FdoDhGroup group, int width, int exponentBits)
    {
        nint modulus = 0;
        nint order = 0;
        nint generator = 0;
        nint exponent = 0;
        nint publicValue = 0;
        nint bnContext = 0;
        nint checkContext = 0;
        SafeOpenSslKey? key = null;
        try
        {
            modulus = Require(group == FdoDhGroup.DhkexId14
                ? OpenSslPrime2048(0)
                : OpenSslPrime3072(0), "load the DH modulus");
            order = Require(OpenSslBnDuplicate(modulus), "allocate the DH subgroup order");
            Check(OpenSslBnSubtractWord(order, 1), "calculate the DH subgroup order");
            Check(OpenSslBnRightShiftOne(order, order), "calculate the DH subgroup order");
            generator = Require(OpenSslBnNew(), "allocate the DH generator");
            Check(OpenSslBnSetWord(generator, 2), "set the DH generator");
            exponent = Require(OpenSslBnSecureNew(), "allocate the DH private exponent");
            publicValue = Require(OpenSslBnNew(), "allocate the DH public value");
            bnContext = Require(OpenSslBnContextSecureNew(), "allocate the DH private arithmetic context");

            Check(OpenSslBnPrivateRandom(exponent, exponentBits, 0, 0, 0, bnContext), "generate the DH private exponent");
            if (OpenSslBnBitCount(exponent) != exponentBits || OpenSslBnCompare(exponent, order) >= 0)
            {
                throw new CryptographicException("OpenSSL generated a DH private exponent outside the required range.");
            }

            Check(OpenSslBnModExpConstantTime(publicValue, generator, exponent, modulus, bnContext, 0),
                "calculate the DH public value");
            key = ImportKey(group, publicValue, exponent);
            RequireGroup(key, modulus, order, generator);
            checkContext = Require(OpenSslKeyContextFromKey(0, key, 0), "allocate the DH validation context");
            Check(OpenSslKeyPairwiseCheck(checkContext), "validate the generated DH key pair");

            var parameter = new byte[width];
            fixed (byte* parameterPtr = parameter)
            {
                if (OpenSslBnToBigEndianPadded(publicValue, parameterPtr, width) != width)
                {
                    throw new CryptographicException("OpenSSL returned a DH public value of an unexpected length.");
                }
            }

            var exchange = new FdoDhKeyExchange(group, key, parameter);
            key = null;
            return exchange;
        }
        finally
        {
            if (checkContext != 0) OpenSslKeyContextFree(checkContext);
            key?.Dispose();
            if (bnContext != 0) OpenSslBnContextFree(bnContext);
            if (publicValue != 0) OpenSslBnClearFree(publicValue);
            if (exponent != 0) OpenSslBnClearFree(exponent);
            if (generator != 0) OpenSslBnClearFree(generator);
            if (order != 0) OpenSslBnClearFree(order);
            if (modulus != 0) OpenSslBnClearFree(modulus);
        }
    }

    private static unsafe byte[] DeriveLinux(FdoDhGroup group, SafeOpenSslKey key, ReadOnlySpan<byte> peerParameter)
    {
        nint modulus = 0;
        nint upperBound = 0;
        nint order = 0;
        nint publicValue = 0;
        nint result = 0;
        nint bnContext = 0;
        nint checkContext = 0;
        SafeOpenSslKey? peer = null;
        try
        {
            modulus = Require(group == FdoDhGroup.DhkexId14
                ? OpenSslPrime2048(0)
                : OpenSslPrime3072(0), "load the DH modulus");
            upperBound = Require(OpenSslBnDuplicate(modulus), "allocate the DH upper bound");
            Check(OpenSslBnSubtractWord(upperBound, 1), "calculate the DH upper bound");
            order = Require(OpenSslBnDuplicate(upperBound), "allocate the DH subgroup order");
            Check(OpenSslBnRightShiftOne(order, order), "calculate the DH subgroup order");
            fixed (byte* peerPtr = peerParameter)
            {
                publicValue = Require(OpenSslBnFromBigEndian(peerPtr, peerParameter.Length, 0),
                    "read the peer DH public value");
            }

            if (OpenSslBnIsWord(publicValue, 0) == 1 || OpenSslBnIsWord(publicValue, 1) == 1 ||
                OpenSslBnCompare(publicValue, upperBound) >= 0)
            {
                throw new CryptographicException("The peer DH public value is outside the permitted range.");
            }

            result = Require(OpenSslBnNew(), "allocate the DH subgroup result");
            bnContext = Require(OpenSslBnContextNew(), "allocate the DH public arithmetic context");
            // This exponentiation uses only the public peer value and group parameters.
            Check(OpenSslBnModExp(result, publicValue, order, modulus, bnContext),
                "check the peer DH subgroup");
            if (OpenSslBnIsWord(result, 1) != 1)
            {
                throw new CryptographicException("The peer DH public value is not in the required subgroup.");
            }

            peer = ImportKey(group, publicValue, 0);
            checkContext = Require(OpenSslKeyContextFromKey(0, peer, 0), "allocate the DH peer validation context");
            Check(OpenSslKeyPublicCheck(checkContext), "validate the peer DH public key");
            return DerivePadded(key, peer, peerParameter.Length);
        }
        finally
        {
            if (checkContext != 0) OpenSslKeyContextFree(checkContext);
            peer?.Dispose();
            if (bnContext != 0) OpenSslBnContextFree(bnContext);
            if (result != 0) OpenSslBnClearFree(result);
            if (publicValue != 0) OpenSslBnClearFree(publicValue);
            if (order != 0) OpenSslBnClearFree(order);
            if (upperBound != 0) OpenSslBnClearFree(upperBound);
            if (modulus != 0) OpenSslBnClearFree(modulus);
        }
    }

    private static unsafe byte[] DerivePadded(SafeOpenSslKey key, SafeOpenSslKey peer, int width)
    {
        nint context = 0;
        nint builder = 0;
        nint parameters = 0;
        byte[]? secret = null;
        bool completed = false;
        fixed (byte* padName = "pad\0"u8)
        {
            try
            {
                context = Require(OpenSslKeyContextFromKey(0, key, 0), "allocate the DH agreement context");
                Check(OpenSslKeyDeriveInit(context), "initialize DH agreement");
                builder = Require(OpenSslParameterBuilderNew(), "allocate DH padding parameters");
                Check(OpenSslParameterPushUInt(builder, padName, 1), "request padded DH agreement");
                parameters = Require(OpenSslParameterBuilderToParameters(builder), "build DH padding parameters");
                Check(OpenSslKeyContextSetParameters(context, parameters), "set DH agreement padding");
                Check(OpenSslKeyDeriveSetPeer(context, peer), "set the peer DH public key");

                nuint length = 0;
                Check(OpenSslKeyDerive(context, null, ref length), "determine the DH shared-secret length");
                if (length != (nuint)width)
                {
                    throw new CryptographicException("OpenSSL returned an unexpected DH shared-secret length.");
                }

                secret = new byte[width];
                fixed (byte* secretPtr = secret)
                {
                    Check(OpenSslKeyDerive(context, secretPtr, ref length), "derive the DH shared secret");
                }

                if (length != (nuint)width)
                {
                    throw new CryptographicException("OpenSSL returned an unexpected DH shared-secret length.");
                }

                completed = true;
                return secret;
            }
            finally
            {
                if (!completed && secret is not null) CryptographicOperations.ZeroMemory(secret);
                if (parameters != 0) OpenSslParametersFree(parameters);
                if (builder != 0) OpenSslParameterBuilderFree(builder);
                if (context != 0) OpenSslKeyContextFree(context);
            }
        }
    }

    private static unsafe SafeOpenSslKey ImportKey(FdoDhGroup group, nint publicValue, nint privateValue)
    {
        ReadOnlySpan<byte> groupValue = group == FdoDhGroup.DhkexId14 ? "modp_2048\0"u8 : "modp_3072\0"u8;
        nint builder = 0;
        nint parameters = 0;
        nint context = 0;
        nint key = 0;
        fixed (byte* groupName = "group\0"u8, groupPtr = groupValue, publicName = "pub\0"u8,
            privateName = "priv\0"u8, algorithm = "DH\0"u8)
        {
            try
            {
                builder = Require(OpenSslParameterBuilderNew(), "allocate DH key parameters");
                Check(OpenSslParameterPushString(builder, groupName, groupPtr, 0), "set the DH group");
                Check(OpenSslParameterPushBigNumber(builder, publicName, publicValue), "set the DH public value");
                if (privateValue != 0)
                {
                    Check(OpenSslParameterPushBigNumber(builder, privateName, privateValue), "set the DH private value");
                }

                parameters = Require(OpenSslParameterBuilderToParameters(builder), "build DH key parameters");
                context = Require(OpenSslKeyContextFromName(0, algorithm, 0), "allocate the DH import context");
                Check(OpenSslKeyFromDataInit(context), "initialize DH key import");
                Check(OpenSslKeyFromData(
                    context, out key, privateValue == 0 ? PublicKeySelection : KeyPairSelection, parameters),
                    "import the DH key");
                if (key == 0)
                {
                    throw new CryptographicException("OpenSSL returned an empty DH key.");
                }

                var result = new SafeOpenSslKey(key);
                key = 0;
                return result;
            }
            finally
            {
                if (key != 0) OpenSslKeyFree(key);
                if (context != 0) OpenSslKeyContextFree(context);
                if (parameters != 0) OpenSslParametersFree(parameters);
                if (builder != 0) OpenSslParameterBuilderFree(builder);
            }
        }
    }

    private static unsafe void RequireGroup(SafeOpenSslKey key, nint modulus, nint order, nint generator)
    {
        nint importedModulus = 0;
        nint importedOrder = 0;
        nint importedGenerator = 0;
        fixed (byte* p = "p\0"u8, q = "q\0"u8, g = "g\0"u8)
        {
            try
            {
                Check(OpenSslKeyGetBigNumber(key, p, out importedModulus), "read the imported DH modulus");
                Check(OpenSslKeyGetBigNumber(key, q, out importedOrder), "read the imported DH subgroup order");
                Check(OpenSslKeyGetBigNumber(key, g, out importedGenerator), "read the imported DH generator");
                if (importedModulus == 0 || importedOrder == 0 || importedGenerator == 0 ||
                    OpenSslBnCompare(importedModulus, modulus) != 0 ||
                    OpenSslBnCompare(importedOrder, order) != 0 ||
                    OpenSslBnCompare(importedGenerator, generator) != 0)
                {
                    throw new CryptographicException("OpenSSL imported unexpected DH group parameters.");
                }
            }
            finally
            {
                if (importedGenerator != 0) OpenSslBnClearFree(importedGenerator);
                if (importedOrder != 0) OpenSslBnClearFree(importedOrder);
                if (importedModulus != 0) OpenSslBnClearFree(importedModulus);
            }
        }
    }

    private static nint Require(nint value, string operation) =>
        value != 0 ? value : throw new CryptographicException($"OpenSSL could not {operation}.");

    private static void Check(int result, string operation)
    {
        if (result != 1)
        {
            throw new CryptographicException($"OpenSSL could not {operation}.");
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_attempted)
        {
            throw new InvalidOperationException("The ephemeral DH key has already been consumed.");
        }
    }

    private sealed class SafeOpenSslKey : SafeHandle
    {
        public SafeOpenSslKey(nint key) : base(0, true) => SetHandle(key);

        public override bool IsInvalid => handle == 0;

        protected override bool ReleaseHandle()
        {
            OpenSslKeyFree(handle);
            return true;
        }
    }

    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_get_rfc3526_prime_2048")]
    private static partial nint OpenSslPrime2048(nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_get_rfc3526_prime_3072")]
    private static partial nint OpenSslPrime3072(nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_new")]
    private static partial nint OpenSslBnNew();
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_secure_new")]
    private static partial nint OpenSslBnSecureNew();
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_dup")]
    private static partial nint OpenSslBnDuplicate(nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_clear_free")]
    private static partial void OpenSslBnClearFree(nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_set_word")]
    private static partial int OpenSslBnSetWord(nint value, nuint word);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_sub_word")]
    private static partial int OpenSslBnSubtractWord(nint value, nuint word);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_rshift1")]
    private static partial int OpenSslBnRightShiftOne(nint result, nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_num_bits")]
    private static partial int OpenSslBnBitCount(nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_cmp")]
    private static partial int OpenSslBnCompare(nint left, nint right);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_is_word")]
    private static partial int OpenSslBnIsWord(nint value, nuint word);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_priv_rand_ex")]
    private static partial int OpenSslBnPrivateRandom(
        nint value, int bits, int top, int bottom, uint strength, nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_bin2bn")]
    private static unsafe partial nint OpenSslBnFromBigEndian(byte* bytes, int length, nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_bn2binpad")]
    private static unsafe partial int OpenSslBnToBigEndianPadded(nint value, byte* bytes, int length);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_CTX_new")]
    private static partial nint OpenSslBnContextNew();
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_CTX_secure_new")]
    private static partial nint OpenSslBnContextSecureNew();
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_CTX_free")]
    private static partial void OpenSslBnContextFree(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_mod_exp")]
    private static partial int OpenSslBnModExp(nint result, nint value, nint exponent, nint modulus, nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "BN_mod_exp_mont_consttime")]
    private static partial int OpenSslBnModExpConstantTime(
        nint result, nint value, nint exponent, nint modulus, nint context, nint montgomery);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_new")]
    private static partial nint OpenSslParameterBuilderNew();
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_free")]
    private static partial void OpenSslParameterBuilderFree(nint builder);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_push_utf8_string")]
    private static unsafe partial int OpenSslParameterPushString(nint builder, byte* name, byte* value, nuint size);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_push_BN")]
    private static unsafe partial int OpenSslParameterPushBigNumber(nint builder, byte* name, nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_push_uint")]
    private static unsafe partial int OpenSslParameterPushUInt(nint builder, byte* name, uint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_BLD_to_param")]
    private static partial nint OpenSslParameterBuilderToParameters(nint builder);
    [LibraryImport("libcrypto.so.3", EntryPoint = "OSSL_PARAM_free")]
    private static partial void OpenSslParametersFree(nint parameters);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_CTX_new_from_name")]
    private static unsafe partial nint OpenSslKeyContextFromName(nint library, byte* name, nint properties);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_CTX_new_from_pkey")]
    private static partial nint OpenSslKeyContextFromKey(nint library, SafeOpenSslKey key, nint properties);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_CTX_free")]
    private static partial void OpenSslKeyContextFree(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_CTX_set_params")]
    private static partial int OpenSslKeyContextSetParameters(nint context, nint parameters);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_fromdata_init")]
    private static partial int OpenSslKeyFromDataInit(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_fromdata")]
    private static partial int OpenSslKeyFromData(nint context, out nint key, int selection, nint parameters);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_get_bn_param")]
    private static unsafe partial int OpenSslKeyGetBigNumber(SafeOpenSslKey key, byte* name, out nint value);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_free")]
    private static partial void OpenSslKeyFree(nint key);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_public_check")]
    private static partial int OpenSslKeyPublicCheck(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_pairwise_check")]
    private static partial int OpenSslKeyPairwiseCheck(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_derive_init")]
    private static partial int OpenSslKeyDeriveInit(nint context);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_derive_set_peer")]
    private static partial int OpenSslKeyDeriveSetPeer(nint context, SafeOpenSslKey peer);
    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_PKEY_derive")]
    private static unsafe partial int OpenSslKeyDerive(nint context, byte* secret, ref nuint length);
}
