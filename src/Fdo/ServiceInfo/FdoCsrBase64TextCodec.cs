// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using Fdo.Enrollment;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>
/// An explicitly selected paired-peer profile for fdo.csr values: padded
/// RFC 4648 Base64 in one CBOR text value. The FSIM does not establish
/// this encoding for unknown peers. These values are not fragmented. The
/// separate server-key response codec uses MIME. The role must separately
/// enforce the final protected-message size.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoCsrBase64TextCodec
{
    private const string RequestKey = "fdo.csr:simpleenroll-req";
    private const string ResponseKey = "fdo.csr:simpleenroll-res";
    private const string ReenrollmentRequestKey = "fdo.csr:simplereenroll-req";
    private const string ReenrollmentResponseKey = "fdo.csr:simplereenroll-res";
    private const string ServerKeygenRequestKey = "fdo.csr:serverkeygen-req";
    private const string CaResponseKey = "fdo.csr:cacerts-res";
    private const string AttributesResponseKey = "fdo.csr:csrattrs-res";
    private readonly int _maxPlaintextBytes;

    /// <summary>
    /// Creates a codec bounded by the negotiated TO2 plaintext limit.
    /// </summary>
    /// <param name="maxPlaintextBytes">
    /// Maximum encoded TO2 plaintext body size available to one ServiceInfo item.
    /// </param>
    public FdoCsrBase64TextCodec(int maxPlaintextBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPlaintextBytes);
        _maxPlaintextBytes = maxPlaintextBytes;
    }

    public Entry EncodeRequest(
        ReadOnlyMemory<byte> request, bool isReenrollment = false, bool isServerKeyGeneration = false)
    {
        string key = RequestKeyFor(isReenrollment, isServerKeyGeneration);
        CheckEncodedPayloadSize(key, request.Length);
        byte[] copy = request.ToArray();
        ValidateRequest(copy, isServerKeyGeneration);
        return Encode(key, copy);
    }

    public byte[] DecodeRequest(Entry entry, bool isReenrollment = false, bool isServerKeyGeneration = false)
    {
        byte[] request = Decode(entry, RequestKeyFor(isReenrollment, isServerKeyGeneration));
        ValidateRequest(request, isServerKeyGeneration);
        return request;
    }

    public Entry EncodeResponse(
        ReadOnlyMemory<byte> request, ReadOnlyMemory<byte> certificate, bool isReenrollment = false)
    {
        string key = isReenrollment ? ReenrollmentResponseKey : ResponseKey;
        CheckEncodedPayloadSize(key, certificate.Length);
        byte[] requestCopy = request.ToArray();
        byte[] certificateCopy = certificate.ToArray();
        FdoCsrSimpleEnrollment.ValidateResponse(requestCopy, certificateCopy);
        return Encode(key, certificateCopy);
    }

    public byte[] DecodeResponse(Entry entry, ReadOnlyMemory<byte> request, bool isReenrollment = false)
    {
        byte[] certificate = Decode(entry, isReenrollment ? ReenrollmentResponseKey : ResponseKey);
        FdoCsrSimpleEnrollment.ValidateResponse(request, certificate);
        return certificate;
    }

    public Entry EncodeCaCertificates(FdoCaCertificates certificates)
    {
        byte[] encoded = FdoCsrCaCertificatesCodec.Encode(certificates);
        CheckEncodedPayloadSize(CaResponseKey, encoded.Length);
        return Encode(CaResponseKey, encoded);
    }

    public FdoCaCertificates DecodeCaCertificates(Entry entry) =>
        FdoCsrCaCertificatesCodec.Decode(Decode(entry, CaResponseKey));

    public Entry EncodeCsrAttributes(FdoCsrAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        CheckEncodedPayloadSize(AttributesResponseKey, attributes.EncodedData.Length);
        return Encode(AttributesResponseKey, attributes.EncodedData.ToArray());
    }

    public FdoCsrAttributes DecodeCsrAttributes(Entry entry) =>
        new(Decode(entry, AttributesResponseKey));

    private static Entry Encode(string key, byte[] payload)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(Convert.ToBase64String(payload));
        return new Entry(key, writer.Encode());
    }

    private byte[] Decode(Entry entry, string expectedKey)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!string.Equals(entry.Key, expectedKey, StringComparison.Ordinal))
        {
            throw new ArgumentException("The ServiceInfo key does not match the fdo.csr operation.", nameof(entry));
        }

        CheckItemSize(entry.Key, entry.EncodedValue.Length);
        var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The selected fdo.csr profile requires a CBOR text value.");
        }

        string text = reader.ReadTextString();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The fdo.csr value contains trailing CBOR data.");
        }

        byte[] decoded = Convert.FromBase64String(text);
        if (!string.Equals(Convert.ToBase64String(decoded), text, StringComparison.Ordinal))
        {
            throw new FormatException("The fdo.csr value must use canonical padded Base64 without whitespace.");
        }

        return decoded;
    }

    private void CheckEncodedPayloadSize(string key, int payloadLength)
    {
        long textLength = 4 * ((payloadLength + 2L) / 3);
        long encodedValueLength = FdoCborCodec.GetHeaderSize((ulong)textLength) + textLength;
        CheckItemSize(key, encodedValueLength);
    }

    internal void CheckItemSize(string key, long encodedValueLength)
    {
        long bodyLength = 3L + 1 + 1 + FdoCborCodec.GetHeaderSize((ulong)key.Length) + key.Length +
            FdoCborCodec.GetHeaderSize((ulong)encodedValueLength) + encodedValueLength;
        if (bodyLength > _maxPlaintextBytes)
        {
            throw new CborContentException("The fdo.csr item does not fit in the TO2 plaintext limit.");
        }
    }

    private static string RequestKeyFor(bool isReenrollment, bool isServerKeyGeneration)
    {
        if (isReenrollment && isServerKeyGeneration)
        {
            throw new ArgumentException("Server key generation is separate from simple re-enrollment.");
        }

        return isServerKeyGeneration ? ServerKeygenRequestKey :
            isReenrollment ? ReenrollmentRequestKey : RequestKey;
    }

    private static void ValidateRequest(ReadOnlyMemory<byte> request, bool isServerKeyGeneration)
    {
        if (isServerKeyGeneration)
        {
            FdoCsrServerKeygen.ValidateRequest(request);
        }
        else
        {
            FdoCsrSimpleEnrollment.ValidateRequest(request);
        }
    }
}
