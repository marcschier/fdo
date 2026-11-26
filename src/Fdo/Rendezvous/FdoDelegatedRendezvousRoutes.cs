// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Fdo.Rendezvous;

internal static class FdoDelegatedRendezvousRoutes
{
    private static readonly StringComparer HostComparer = StringComparer.OrdinalIgnoreCase;

    public static void Validate(IReadOnlyList<FdoRendezvousAddress> addresses)
    {
        var routes = new HashSet<(FdoRendezvousTransportProtocol, ushort, string)>();
        foreach (FdoRendezvousAddress address in addresses)
        {
            if (address is null || (address.DnsName is null) == (address.IpAddress is null))
            {
                throw new CborContentException("Each multi-address delegated route must contain only DNS or only an IP address.");
            }

            string host;
            try
            {
                host = Host(address);
            }
            catch (ArgumentException e)
            {
                throw new CborContentException("A multi-address delegated route has an invalid DNS name.", e);
            }

            if (!routes.Add((address.Protocol, address.Port, host.ToUpperInvariant())))
            {
                throw new CborContentException("The multi-address delegated redirect contains duplicate routes.");
            }
        }
    }

    public static bool MatchesOrigin(FdoRendezvousAddress address, Uri? uri)
    {
        if (uri?.IsAbsoluteUri != true || uri.Port != address.Port ||
            uri.Scheme != (address.Protocol == FdoRendezvousTransportProtocol.Https ? Uri.UriSchemeHttps : Uri.UriSchemeHttp))
        {
            return false;
        }

        if (address.DnsName is not null)
        {
            return uri.HostNameType == UriHostNameType.Dns && HostComparer.Equals(Host(address), NormalizeDns(uri.IdnHost));
        }

        string host = uri.DnsSafeHost;
        return uri.HostNameType is (UriHostNameType.IPv4 or UriHostNameType.IPv6) &&
            !host.Contains('%') &&
            IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? ip) &&
            (ip.AddressFamily != AddressFamily.InterNetworkV6 || ip.ScopeId == 0) &&
            HostComparer.Equals(Host(address), NormalizeIp(ip));
    }

    public static bool SameSignedAddress(FdoRendezvousAddress first, FdoRendezvousAddress second) =>
        first.Protocol == second.Protocol && first.Port == second.Port &&
        string.Equals(first.DnsName, second.DnsName, StringComparison.Ordinal) &&
        (first.IpAddress is { } ip
            ? second.IpAddress is { } other && ip.Span.SequenceEqual(other.Span)
            : second.IpAddress is null);

    private static string Host(FdoRendezvousAddress address) => address.DnsName is { } dns
        ? NormalizeDns(dns) : NormalizeIp(new IPAddress(address.IpAddress!.Value.Span));

    private static string NormalizeDns(string dns) => new IdnMapping().GetAscii(dns);

    private static string NormalizeIp(IPAddress ip) => (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
}
