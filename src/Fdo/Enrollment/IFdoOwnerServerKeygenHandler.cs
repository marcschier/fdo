// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Authorizes an authenticated Device and issues a server-generated key and certificate.</summary>
/// <remarks>
/// The request's public key and signature are ignored and do not prove
/// possession. The host must authorize the Device and requested identity
/// independently, generate the key, and apply certificate policy. Ownership
/// of the returned credential transfers to the session. The host must protect
/// and clear any other copies of the private key.
/// </remarks>
public interface IFdoOwnerServerKeygenHandler
{
    /// <summary>Returns a certificate and unencrypted DER PKCS#8 private key.</summary>
    /// <param name="request">The request data for this exchange.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<FdoServerKeygenCredential> AuthorizeAndIssueAsync(
        FdoEnrollmentRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Transfers a server-generated credential to one Owner session.</summary>
/// <remarks>
/// This object is not an enrollment receipt. The session disposes it after
/// encoding the response, clearing its private-key copy. The caller must not
/// use or dispose it after returning it to the session.
/// </remarks>
public sealed class FdoServerKeygenCredential : IDisposable
{
    private readonly byte[] _certificate;
    private readonly byte[] _privateKey;
    private bool _disposed;

    /// <summary>Snapshots one certificate and its unencrypted PKCS#8 private key.</summary>
    /// <param name="certificate">The certificate to process.</param>
    /// <param name="privateKeyPkcs8">The DER PKCS#8 private key.</param>
    public FdoServerKeygenCredential(
        ReadOnlyMemory<byte> certificate,
        ReadOnlyMemory<byte> privateKeyPkcs8)
    {
        if (certificate.IsEmpty || privateKeyPkcs8.IsEmpty ||
            (long)certificate.Length + privateKeyPkcs8.Length > ushort.MaxValue)
        {
            throw new ArgumentException("The generated credential exceeds the FDO message limit or is empty.");
        }

        _certificate = certificate.ToArray();
        _privateKey = privateKeyPkcs8.ToArray();
    }

    /// <summary>The DER certificate, returned as a detached copy.</summary>
    public ReadOnlyMemory<byte> Certificate => (byte[])_certificate.Clone();

    internal ReadOnlyMemory<byte> PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _privateKey;
        }
    }

    /// <summary>Clears the private-key copy owned by this object.</summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_privateKey);
        _disposed = true;
    }
}
