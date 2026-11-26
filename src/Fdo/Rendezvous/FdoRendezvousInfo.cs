// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Net;
using System.Runtime.Versioning;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Rendezvous;

/// <summary>One untrusted Rendezvous Server endpoint from a directive.</summary>
public sealed class FdoRendezvousServerCandidate
{
    internal FdoRendezvousServerCandidate(int directiveIndex, Uri baseAddress)
    {
        DirectiveIndex = directiveIndex;
        BaseAddress = baseAddress;
    }

    /// <summary>The zero-based position of the directive in RendezvousInfo.</summary>
    public int DirectiveIndex { get; }

    /// <summary>The HTTP or HTTPS base address to consider under host policy.</summary>
    public Uri BaseAddress { get; }
}

/// <summary>One role-applicable RendezvousInfo directive and its retry delay.</summary>
public sealed class FdoRendezvousDirective
{
    internal FdoRendezvousDirective(
        int directiveIndex,
        IReadOnlyList<FdoRendezvousServerCandidate> candidates,
        uint? delaySeconds)
    {
        DirectiveIndex = directiveIndex;
        Candidates = candidates;
        DelaySeconds = delaySeconds;
    }

    /// <summary>The zero-based position of the directive in RendezvousInfo.</summary>
    public int DirectiveIndex { get; }

    /// <summary>The untrusted endpoints, with the DNS name before the IP address.</summary>
    public IReadOnlyList<FdoRendezvousServerCandidate> Candidates { get; }

    /// <summary>The unjittered RVDelaysec value, or null when the directive has none.</summary>
    public uint? DelaySeconds { get; }
}

/// <summary>The role-applicable directives of one RendezvousInfo, in order.</summary>
public sealed class FdoRendezvousDirectiveSet
{
    internal FdoRendezvousDirectiveSet(
        FdoRendezvousProtocol protocol,
        IReadOnlyList<FdoRendezvousDirective> directives)
    {
        Protocol = protocol;
        Directives = directives;
    }

    /// <summary>The role for which the directives were selected.</summary>
    public FdoRendezvousProtocol Protocol { get; }

    /// <summary>
    /// The directives that apply to the role. Directives for the other role
    /// are omitted and contribute no delay.
    /// </summary>
    public IReadOnlyList<FdoRendezvousDirective> Directives { get; }
}

/// <summary>Parses the paired HTTP/HTTPS subset of FDO RendezvousInfo.</summary>
/// <remarks>
/// The returned endpoints are untrusted. Parsing performs no DNS lookup,
/// connection, retry, or bypass. The host applies network and resolution
/// policy and decides whether to start a role run. It must account for the
/// specification's retry delays before starting another run.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public static class FdoRendezvousInfo
{
    private const int MaxDirectives = 256;
    private const int MaxInstructionsPerDirective = 16;

    /// <summary>
    /// Reads an encoded RendezvousInfo and returns role-applicable endpoints in
    /// directive order, with DNS before IP within a directive.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Input is limited to 65,535 encoded bytes, 256 directives, and 16
    /// instructions per directive. A Device-applicable rvserver.local DNS
    /// directive is required. Each instruction must use the paired
    /// [variable, bstr .cbor value] representation; no-argument markers use
    /// a wrapped CBOR null. Duplicate variables and malformed values are
    /// rejected. Structurally valid directives for the other role are skipped,
    /// as are known role-specific settings that do not apply to the caller
    /// in shared directives.
    /// Unsupported variables in an applicable directive, including certificate
    /// hashes, network-medium constraints, delays, bypass, and extensions,
    /// cause an exception rather than being ignored.
    /// </para>
    /// <para>
    /// Owners use HTTPS and RVOwnerPort; Devices use RVProtocol and RVDevPort.
    /// An omitted protocol selects HTTPS/443 unless the Device port is 80,
    /// which selects HTTP. A nonstandard Device port without an explicit
    /// protocol is not supported. RVProtRest selects HTTPS. The host must
    /// process DNS results and apply its own policy before connecting.
    /// </para>
    /// </remarks>
    /// <param name="encodedRendezvousInfo">The encoded RendezvousInfo array.</param>
    /// <param name="protocol">The Owner registration or Device lookup role.</param>
    /// <returns>Read-only endpoints in the order supplied by the directives.</returns>
    /// <exception cref="CborContentException">The input is malformed or exceeds a limit.</exception>
    /// <exception cref="NotSupportedException">An instruction or protocol is outside the paired subset.</exception>
    public static IReadOnlyList<FdoRendezvousServerCandidate> Parse(
        ReadOnlyMemory<byte> encodedRendezvousInfo,
        FdoRendezvousProtocol protocol)
    {
        var candidates = new List<FdoRendezvousServerCandidate>();
        foreach (FdoRendezvousDirective directive in ParseCore(encodedRendezvousInfo, protocol, allowDelay: false))
        {
            candidates.AddRange(directive.Candidates);
        }

        return candidates.AsReadOnly();
    }

    /// <summary>
    /// Reads an encoded RendezvousInfo and returns the role-applicable
    /// directives with their candidates and RVDelaysec values.
    /// </summary>
    /// <remarks>
    /// This method applies the same limits, role selection, and endpoint rules
    /// as <see cref="Parse"/>, and additionally accepts RVDelaysec (variable
    /// 13) as a uint32 number of seconds. A directive must still contain a DNS
    /// name or IP address, so a delay-only directive is rejected. All other
    /// unsupported variables in an applicable directive still cause an exception. Use the result with
    /// <see cref="FdoRendezvousAttemptPlan"/> to step bounded attempts.
    /// </remarks>
    /// <param name="encodedRendezvousInfo">The encoded RendezvousInfo array.</param>
    /// <param name="protocol">The Owner registration or Device lookup role.</param>
    /// <returns>The role-applicable directives in RendezvousInfo order.</returns>
    /// <exception cref="CborContentException">The input is malformed or exceeds a limit.</exception>
    /// <exception cref="NotSupportedException">An instruction or protocol is outside the paired subset.</exception>
    public static FdoRendezvousDirectiveSet ParseDirectives(
        ReadOnlyMemory<byte> encodedRendezvousInfo,
        FdoRendezvousProtocol protocol) =>
        new(protocol, ParseCore(encodedRendezvousInfo, protocol, allowDelay: true));

    private static IReadOnlyList<FdoRendezvousDirective> ParseCore(
        ReadOnlyMemory<byte> encodedRendezvousInfo,
        FdoRendezvousProtocol protocol,
        bool allowDelay)
    {
        if (protocol is not (FdoRendezvousProtocol.OwnerRegistration or FdoRendezvousProtocol.DeviceLookup))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol));
        }

        var cbor = new FdoCborCodec();
        var reader = new CborReader(cbor.ValidateAndCopy(encodedRendezvousInfo), CborConformanceMode.Canonical);
        int directiveCount = ReadArray(reader, MaxDirectives);
        var directives = new List<FdoRendezvousDirective>();
        bool hasLocal = false;
        for (int directiveIndex = 0; directiveIndex < directiveCount; directiveIndex++)
        {
            int instructionCount = ReadArray(reader, MaxInstructionsPerDirective);
            var seen = new HashSet<byte>();
            var instructions = new (byte Variable, ReadOnlyMemory<byte> Value)[instructionCount];
            bool deviceOnly = false;
            bool ownerOnly = false;
            for (int i = 0; i < instructionCount; i++)
            {
                if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 2)
                {
                    throw new CborContentException("A rendezvous instruction must contain two fields.");
                }

                ulong variable = ReadUnsigned(reader);
                if (variable > byte.MaxValue)
                {
                    throw new CborContentException("A rendezvous variable must fit in uint8.");
                }

                if (reader.PeekState() != CborReaderState.ByteString)
                {
                    throw new CborContentException("A rendezvous instruction value must be a byte string.");
                }

                ReadOnlyMemory<byte> encodedValue =
                    cbor.ValidateEmbeddedValueAndCopy(reader.ReadDefiniteLengthByteString());
                reader.ReadEndArray();
                if (!seen.Add((byte)variable))
                {
                    throw new CborContentException("A rendezvous directive contains a duplicate variable.");
                }

                instructions[i] = ((byte)variable, encodedValue);
                if (variable is 0 or 1)
                {
                    ReadMarker(new CborReader(encodedValue, CborConformanceMode.Strict));
                    deviceOnly |= variable == 0;
                    ownerOnly |= variable == 1;
                }
            }

            reader.ReadEndArray();
            if (deviceOnly && ownerOnly)
            {
                throw new CborContentException("A rendezvous directive cannot be both Device-only and Owner-only.");
            }

            if ((protocol == FdoRendezvousProtocol.OwnerRegistration && deviceOnly) ||
                (protocol == FdoRendezvousProtocol.DeviceLookup && ownerOnly))
            {
                if (!hasLocal && deviceOnly)
                {
                    foreach ((byte variable, ReadOnlyMemory<byte> encodedValue) in instructions)
                    {
                        if (variable == 5)
                        {
                            // The Device discovery requirement still applies to the whole document.
                            var value = new CborReader(encodedValue, CborConformanceMode.Strict);
                            hasLocal = value.PeekState() == CborReaderState.TextString &&
                                string.Equals(value.ReadTextString(), "rvserver.local", StringComparison.Ordinal);
                            break;
                        }
                    }
                }

                continue;
            }

            byte[]? ip = null;
            string? dns = null;
            ushort? devicePort = null;
            ushort? ownerPort = null;
            byte? deviceProtocol = null;
            uint? delaySeconds = null;
            foreach ((byte variable, ReadOnlyMemory<byte> encodedValue) in instructions)
            {
                var value = new CborReader(encodedValue, CborConformanceMode.Strict);
                switch (variable)
                {
                    case 0:
                    case 1:
                        break;
                    case 2:
                        ip = ReadIpAddress(value);
                        break;
                    case 3 when protocol == FdoRendezvousProtocol.DeviceLookup:
                        devicePort = ReadPort(value);
                        break;
                    case 4 when protocol == FdoRendezvousProtocol.OwnerRegistration:
                        ownerPort = ReadPort(value);
                        break;
                    case 5:
                        dns = ReadDnsName(value);
                        break;
                    case 12 when protocol == FdoRendezvousProtocol.DeviceLookup:
                        ulong selected = ReadUnsigned(value);
                        if (selected > 2)
                        {
                            throw new NotSupportedException("The Device rendezvous protocol is not HTTP or HTTPS.");
                        }

                        deviceProtocol = (byte)selected;
                        break;
                    case 3:
                    case 4:
                    case 12:
                        break;
                    case >= 6 and <= 11 or 14 or 15 when protocol == FdoRendezvousProtocol.OwnerRegistration:
                        break;
                    case 13 when allowDelay:
                        ulong delay = ReadUnsigned(value);
                        if (delay > uint.MaxValue)
                        {
                            throw new CborContentException("RVDelaysec must fit in uint32.");
                        }

                        delaySeconds = (uint)delay;
                        break;
                    default:
                        throw new NotSupportedException("The rendezvous variable is not supported by the paired profile.");
                }
            }

            if (dns is null && ip is null)
            {
                throw new CborContentException("A rendezvous directive requires a DNS name or IP address.");
            }

            if (!ownerOnly && string.Equals(dns, "rvserver.local", StringComparison.Ordinal))
            {
                hasLocal = true;
            }

            bool https = protocol == FdoRendezvousProtocol.OwnerRegistration ||
                SelectDeviceHttps(deviceProtocol, devicePort);
            ushort port = protocol == FdoRendezvousProtocol.OwnerRegistration
                ? ownerPort ?? 443
                : devicePort ?? (https ? (ushort)443 : (ushort)80);
            string scheme = https ? Uri.UriSchemeHttps : Uri.UriSchemeHttp;
            var candidates = new List<FdoRendezvousServerCandidate>(2);
            if (dns is not null)
            {
                candidates.Add(new FdoRendezvousServerCandidate(
                    directiveIndex, new UriBuilder(scheme, dns, port).Uri));
            }

            if (ip is not null)
            {
                candidates.Add(new FdoRendezvousServerCandidate(
                    directiveIndex, new UriBuilder(scheme, new IPAddress(ip).ToString(), port).Uri));
            }

            directives.Add(new FdoRendezvousDirective(directiveIndex, candidates.AsReadOnly(), delaySeconds));
        }

        reader.ReadEndArray();
        if (!hasLocal)
        {
            throw new CborContentException("RendezvousInfo requires a Device-applicable rvserver.local DNS directive.");
        }

        return directives.AsReadOnly();
    }

    /// <summary>Reads RendezvousInfo from an encoded Ownership Voucher header tag.</summary>
    /// <remarks>
    /// Parsing a voucher header does not authenticate it or establish trust in
    /// the returned endpoints. The host must verify and authorize the voucher
    /// independently before relying on its contents.
    /// </remarks>
    /// <param name="encodedVoucherHeaderTag">The CBOR byte string containing the voucher header.</param>
    /// <param name="protocol">The Owner registration or Device lookup role.</param>
    /// <returns>Read-only endpoints in directive order.</returns>
    public static IReadOnlyList<FdoRendezvousServerCandidate> ParseVoucherHeader(
        ReadOnlyMemory<byte> encodedVoucherHeaderTag,
        FdoRendezvousProtocol protocol)
    {
        var cbor = new FdoCborCodec();
        FdoOwnershipVoucherHeader header = FdoOwnershipVoucherHeader.Decode(encodedVoucherHeaderTag, cbor);
        return Parse(header.RendezvousInfo, protocol);
    }

    private static bool SelectDeviceHttps(byte? protocol, ushort? port) => protocol switch
    {
        0 or 2 => true,
        1 => false,
        null when port is null or 443 => true,
        null when port == 80 => false,
        null => throw new NotSupportedException("A nonstandard Device port requires an explicit HTTP or HTTPS protocol."),
        _ => throw new NotSupportedException("The Device rendezvous protocol is not HTTP or HTTPS."),
    };

    private static int ReadArray(CborReader reader, int maxCount)
    {
        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CborContentException("RendezvousInfo requires arrays of directives and instructions.");
        }

        int? count = reader.ReadStartArray();
        if (count is null or 0 || count > maxCount)
        {
            throw new CborContentException("A rendezvous array is empty, indefinite, or exceeds its limit.");
        }

        return count.Value;
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("A rendezvous variable or value must be an unsigned integer.");
        }

        return reader.ReadUInt64();
    }

    private static void ReadMarker(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.Null)
        {
            throw new CborContentException("A paired rendezvous marker requires a wrapped CBOR null.");
        }

        reader.ReadNull();
    }

    private static byte[] ReadIpAddress(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("A rendezvous IP address must be a byte string.");
        }

        byte[] address = reader.ReadDefiniteLengthByteString().ToArray();
        if (address.Length is not (4 or 16))
        {
            throw new CborContentException("A rendezvous IP address must contain 4 or 16 bytes.");
        }

        return address;
    }

    private static ushort ReadPort(CborReader reader)
    {
        ulong port = ReadUnsigned(reader);
        if (port is 0 or > ushort.MaxValue)
        {
            throw new CborContentException("A rendezvous port must be a nonzero uint16.");
        }

        return (ushort)port;
    }

    private static string ReadDnsName(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("A rendezvous DNS name must be a text string.");
        }

        string name = reader.ReadTextString();
        if (Uri.CheckHostName(name) != UriHostNameType.Dns)
        {
            throw new CborContentException("A rendezvous DNS name is invalid.");
        }

        return name;
    }
}
