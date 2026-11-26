// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Fdo.Enrollment;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>Frames the selected paired server-key MIME response in one CBOR text value.</summary>
/// <param name="maxPlaintextBytes">The maximum plaintext message size, in bytes.</param>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoCsrServerKeygenCodec(int maxPlaintextBytes)
{
    private const string ResponseKey = "fdo.csr:serverkeygen-res";
    private const string PrivateHeader =
        "--fdo\r\nContent-Type: application/pkcs8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    private const string CertificateHeader =
        "\r\n--fdo\r\nContent-Type: application/pkcs7-mime; smime-type=certs-only\r\n" +
        "Content-Transfer-Encoding: base64\r\n\r\n";
    private const string EndBoundary = "\r\n--fdo--\r\n";
    private static readonly byte[] PrivateHeaderBytes = Encoding.ASCII.GetBytes(PrivateHeader);
    private static readonly byte[] CertificateHeaderBytes = Encoding.ASCII.GetBytes(CertificateHeader);
    private static readonly byte[] EndBoundaryBytes = Encoding.ASCII.GetBytes(EndBoundary);
    private readonly FdoCsrBase64TextCodec _limits = new(maxPlaintextBytes);

    public Entry EncodeResponse(ReadOnlyMemory<byte> certificate, ReadOnlyMemory<byte> privateKeyPkcs8)
    {
        FdoCsrServerKeygen.ValidateCredential(certificate, privateKeyPkcs8);
        byte[] cms = FdoCsrCaCertificatesCodec.Encode(new FdoCaCertificates([certificate]));
        int keyTextLength = Base64Length(privateKeyPkcs8.Length);
        int certificateTextLength = Base64Length(cms.Length);
        int textLength = checked(PrivateHeader.Length + keyTextLength + CertificateHeader.Length +
            certificateTextLength + EndBoundary.Length);
        long encodedLength = FdoCborCodec.GetHeaderSize((ulong)textLength) + (long)textLength;
        _limits.CheckItemSize(ResponseKey, encodedLength);

        char[] keyText = new char[keyTextLength];
        char[] certificateText = new char[certificateTextLength];
        char[] mime = new char[textLength];
        try
        {
            EncodeBase64(privateKeyPkcs8.Span, keyText);
            EncodeBase64(cms, certificateText);
            int position = 0;
            Append(PrivateHeader.AsSpan(), mime, ref position);
            Append(keyText, mime, ref position);
            Append(CertificateHeader.AsSpan(), mime, ref position);
            Append(certificateText, mime, ref position);
            Append(EndBoundary.AsSpan(), mime, ref position);

            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteTextString(mime);
            return new Entry(ResponseKey, writer.Encode());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(keyText.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(mime.AsSpan()));
        }
    }

    public (byte[] Certificate, byte[] PrivateKey) DecodeResponse(Entry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!string.Equals(entry.Key, ResponseKey, StringComparison.Ordinal))
        {
            throw new ArgumentException("The ServiceInfo key does not identify a server-key response.", nameof(entry));
        }

        _limits.CheckItemSize(entry.Key, entry.EncodedValue.Length);
        var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("A server-key response must contain CBOR text.");
        }

        ReadOnlySpan<byte> mime = reader.ReadDefiniteLengthTextStringBytes().Span;
        if (reader.BytesRemaining != 0 ||
            mime.Length < PrivateHeaderBytes.Length + EndBoundaryBytes.Length ||
            !mime.StartsWith(PrivateHeaderBytes) || !mime.EndsWith(EndBoundaryBytes))
        {
            throw new CborContentException("The server-key MIME response has an unsupported structure.");
        }

        mime = mime[PrivateHeaderBytes.Length..^EndBoundaryBytes.Length];
        int separator = mime.IndexOf(CertificateHeaderBytes);
        if (separator <= 0)
        {
            throw new CborContentException("The server-key MIME response must contain both parts.");
        }

        byte[] privateKey = DecodeBase64(mime[..separator]);
        bool completed = false;
        try
        {
            byte[] cms = DecodeBase64(mime[(separator + CertificateHeaderBytes.Length)..]);
            FdoCaCertificates certificates = FdoCsrCaCertificatesCodec.Decode(cms);
            if (certificates.CertificateData.Count != 1 || certificates.CertificateRevocationListData.Count != 0)
            {
                throw new CryptographicException("The paired server-key response requires exactly one certificate.");
            }

            byte[] certificate = certificates.CertificateData[0].ToArray();
            FdoCsrServerKeygen.ValidateCredential(certificate, privateKey);
            completed = true;
            return (certificate, privateKey);
        }
        finally
        {
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    private static int Base64Length(int length)
    {
        int unwrapped = checked(4 * ((length + 2) / 3));
        return checked(unwrapped + (unwrapped == 0 ? 0 : 2 * ((unwrapped - 1) / 76)));
    }

    private static void EncodeBase64(ReadOnlySpan<byte> value, Span<char> destination)
    {
        if (!Convert.TryToBase64Chars(value, destination, out int written, Base64FormattingOptions.InsertLineBreaks) ||
            written != destination.Length)
        {
            throw new InvalidOperationException("The MIME Base64 payload could not be encoded.");
        }
    }

    private static byte[] DecodeBase64(ReadOnlySpan<byte> text)
    {
        if (text.IsEmpty)
        {
            throw new FormatException("A MIME Base64 part cannot be empty.");
        }

        byte[] compact = new byte[text.Length];
        byte[]? decoded = null;
        byte[]? result = null;
        byte[]? canonical = null;
        bool completed = false;
        try
        {
            int count = 0;
            int column = 0;
            for (int i = 0; i < text.Length; i++)
            {
                byte value = text[i];
                if (value == (byte)'\r')
                {
                    if (column != 76 || i + 1 >= text.Length || text[++i] != (byte)'\n')
                    {
                        throw new FormatException("MIME Base64 lines must use canonical CRLF wrapping.");
                    }

                    column = 0;
                    continue;
                }

                if (++column > 76 || value == (byte)'\n')
                {
                    throw new FormatException("MIME Base64 lines must use canonical CRLF wrapping.");
                }

                compact[count++] = value;
            }

            if (column == 0 || count == 0 || count % 4 != 0)
            {
                throw new FormatException("The MIME Base64 part is incomplete.");
            }

            decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(count)];
            if (Base64.DecodeFromUtf8(compact.AsSpan(0, count), decoded, out int consumed, out int written) !=
                OperationStatus.Done || consumed != count)
            {
                throw new FormatException("The MIME Base64 part is invalid.");
            }

            result = decoded.AsSpan(0, written).ToArray();
            canonical = new byte[Base64.GetMaxEncodedToUtf8Length(written)];
            if (Base64.EncodeToUtf8(result, canonical, out int read, out int encoded) != OperationStatus.Done ||
                read != written || encoded != count ||
                !canonical.AsSpan(0, encoded).SequenceEqual(compact.AsSpan(0, count)))
            {
                throw new FormatException("The MIME Base64 part is not canonical.");
            }

            completed = true;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(compact);
            if (decoded is not null)
            {
                CryptographicOperations.ZeroMemory(decoded);
            }

            if (canonical is not null)
            {
                CryptographicOperations.ZeroMemory(canonical);
            }

            if (!completed && result is not null)
            {
                CryptographicOperations.ZeroMemory(result);
            }
        }
    }

    private static void Append(ReadOnlySpan<char> source, Span<char> destination, ref int position)
    {
        source.CopyTo(destination[position..]);
        position += source.Length;
    }
}
