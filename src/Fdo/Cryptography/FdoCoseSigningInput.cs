// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;

namespace Fdo.Cryptography;

/// <summary>
/// The COSE_Sign1 operations that FDO 2.0 section 3.3.8 binds to a domain tag.
/// </summary>
internal enum FdoSignatureOperation
{
    TO0OwnerSign = 0,
    TO1ProveToRV = 1,
    TO2ProveDevice = 2,
    TO2ProveOVHdr = 3,
    TO2SetupDevice = 4,
    OVEntry = 5,
}

/// <summary>
/// Builds the RFC 9052 COSE_Sign1 signing input with the FDO 2.0 external_aad.
/// It neither parses a COSE_Sign1 message nor signs or verifies a signature.
/// </summary>
internal static class FdoCoseSigningInput
{
    private const string Sign1Context = "Signature1";

    public static string GetDomainTag(FdoSignatureOperation operation) => operation switch
    {
        FdoSignatureOperation.TO0OwnerSign => "FDO-TO0-OwnerSign-v1",
        FdoSignatureOperation.TO1ProveToRV => "FDO-TO1-ProveToRV-v1",
        FdoSignatureOperation.TO2ProveDevice => "FDO-TO2-ProveDevice-v1",
        FdoSignatureOperation.TO2ProveOVHdr => "FDO-TO2-ProveOVHdr-v1",
        FdoSignatureOperation.TO2SetupDevice => "FDO-TO2-SetupDevice-v1",
        FdoSignatureOperation.OVEntry => "FDO-OVEntry-v1",
        _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "The FDO signature operation is not defined."),
    };

    /// <summary>
    /// Encodes the one-element FDOExternalAAD array that section 3.3.8 defines
    /// for this version. The verifier constructs this value; it is not received.
    /// </summary>
    /// <param name="operation">The protocol operation being encoded or verified.</param>
    public static byte[] EncodeExternalAad(FdoSignatureOperation operation)
    {
        string tag = GetDomainTag(operation);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteTextString(tag);
        writer.WriteEndArray();
        return writer.Encode();
    }

    /// <summary>
    /// Encodes Sig_structure = ["Signature1", body_protected, external_aad, payload].
    /// The caller supplies the exact protected-header and payload byte-string
    /// contents from the COSE_Sign1 message; they are copied without re-encoding.
    /// </summary>
    /// <param name="operation">The protocol operation being encoded or verified.</param>
    /// <param name="protectedHeader">The encoded COSE protected headers.</param>
    /// <param name="payload">The payload of the FDO message.</param>
    public static byte[] CreateToBeSigned(
        FdoSignatureOperation operation,
        ReadOnlySpan<byte> protectedHeader,
        ReadOnlySpan<byte> payload)
    {
        byte[] externalAad = EncodeExternalAad(operation);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteTextString(Sign1Context);
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }
}
