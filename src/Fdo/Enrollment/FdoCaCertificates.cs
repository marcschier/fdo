// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.Enrollment;

/// <summary>Detached DER certificates and revocation lists for CA distribution.</summary>
/// <remarks>
/// Construction checks the supported encodings, not certificate or CRL trust,
/// signatures, freshness, or authorization. The host owns those decisions.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoCaCertificates
{
    private readonly ReadOnlyMemory<byte>[] _certificates;
    private readonly ReadOnlyMemory<byte>[] _certificateRevocationLists;

    /// <summary>
    /// Snapshots the supplied DER objects. At least one certificate or CRL is
    /// required, and their combined size must fit in an FDO message.
    /// </summary>
    /// <param name="certificates">The DER certificates to distribute.</param>
    /// <param name="certificateRevocationLists">Optional DER certificate revocation lists to distribute.</param>
    public FdoCaCertificates(
        IReadOnlyList<ReadOnlyMemory<byte>> certificates,
        IReadOnlyList<ReadOnlyMemory<byte>>? certificateRevocationLists = null)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        int remaining = ushort.MaxValue;
        _certificates = Snapshot(certificates, ref remaining);
        _certificateRevocationLists = Snapshot(
            certificateRevocationLists ?? Array.Empty<ReadOnlyMemory<byte>>(), ref remaining);
        if (_certificates.Length == 0 && _certificateRevocationLists.Length == 0)
        {
            throw new ArgumentException("CA distribution requires a certificate or CRL.", nameof(certificates));
        }

        foreach (ReadOnlyMemory<byte> encoded in _certificates)
        {
            using X509Certificate2 certificate = FdoDerEncoding.LoadCertificate(encoded);
        }

        foreach (ReadOnlyMemory<byte> encoded in _certificateRevocationLists)
        {
            _ = CertificateRevocationListBuilder.Load(encoded.Span, out _, out int bytesConsumed);
            if (bytesConsumed != encoded.Length)
            {
                throw new CryptographicException("A CRL must contain exactly one DER value.");
            }
        }
    }

    /// <summary>Exact DER certificate values; each access returns detached copies.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Certificates => Copy(_certificates);

    /// <summary>Exact DER CRL values; each access returns detached copies.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificateRevocationLists => Copy(_certificateRevocationLists);

    internal IReadOnlyList<ReadOnlyMemory<byte>> CertificateData => _certificates;

    internal IReadOnlyList<ReadOnlyMemory<byte>> CertificateRevocationListData => _certificateRevocationLists;

    private static ReadOnlyMemory<byte>[] Snapshot(
        IReadOnlyList<ReadOnlyMemory<byte>> values, ref int remaining)
    {
        if (values.Count > ushort.MaxValue)
        {
            throw new ArgumentException("CA distribution contains too many DER values.", nameof(values));
        }

        var result = new ReadOnlyMemory<byte>[values.Count];
        for (int i = 0; i < result.Length; i++)
        {
            ReadOnlyMemory<byte> value = values[i];
            if (value.IsEmpty || value.Length > remaining)
            {
                throw new ArgumentException("CA distribution DER values exceed the FDO message limit.", nameof(values));
            }

            remaining -= value.Length;
            result[i] = value.ToArray();
        }

        return result;
    }

    private static ReadOnlyCollection<ReadOnlyMemory<byte>> Copy(ReadOnlyMemory<byte>[] values)
    {
        var result = new ReadOnlyMemory<byte>[values.Length];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = values[i].ToArray();
        }

        return Array.AsReadOnly(result);
    }
}
