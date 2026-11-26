// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fdo.Rendezvous;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
public sealed class FdoRendezvousInfoTests
{
    [Test]
    public async Task ListsDeviceCandidatesInDirectiveOrderWithDnsBeforeIp()
    {
        IReadOnlyList<FdoRendezvousServerCandidate> candidates =
            FdoRendezvousInfo.Parse(MixedDirectives(), FdoRendezvousProtocol.DeviceLookup);

        await Assert.That(candidates.Select(candidate => candidate.BaseAddress.AbsoluteUri).SequenceEqual(
            new[]
            {
                "https://rvserver.local/",
                "http://rvserver.local:8080/",
                "https://fleet.example:8443/",
                "https://192.0.2.9:8443/",
            })).IsTrue();
        await Assert.That(candidates.Select(candidate => candidate.DirectiveIndex)
            .SequenceEqual(new[] { 0, 1, 3, 3 })).IsTrue();
    }

    [Test]
    public async Task ListsOwnerCandidatesUsingHttpsAndTheOwnerPort()
    {
        IReadOnlyList<FdoRendezvousServerCandidate> candidates =
            FdoRendezvousInfo.Parse(MixedDirectives(), FdoRendezvousProtocol.OwnerRegistration);

        await Assert.That(candidates.Select(candidate => candidate.BaseAddress.AbsoluteUri).SequenceEqual(
            new[]
            {
                "https://rvserver.local/",
                "https://owner.example/",
                "https://fleet.example:9443/",
                "https://192.0.2.9:9443/",
            })).IsTrue();
        await Assert.That(candidates.Select(candidate => candidate.DirectiveIndex)
            .SequenceEqual(new[] { 0, 2, 3, 3 })).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SkipsOppositeRoleDirectivesBeforeInterpretingTheirInstructions(bool markerFirst)
    {
        var device = new List<Instruction>
        {
            Dns("rvserver.local"), Value(9, writer => writer.WriteTextString("factory-wifi")), Unsigned(12, 3),
        };
        var owner = new List<Instruction> { Dns("owner.example"), Unsigned(4, 0), Marker(255) };
        device.Insert(markerFirst ? 0 : device.Count, Marker(0));
        owner.Insert(markerFirst ? 0 : owner.Count, Marker(1));
        byte[] forOwner = Info(device.ToArray(), [Marker(1), Dns("fleet.example"), Unsigned(4, 9443)]);
        byte[] forDevice = Info(owner.ToArray(), [Marker(0), Dns("rvserver.local")]);

        var ownerRoutes = FdoRendezvousInfo.ParseDirectives(forOwner, FdoRendezvousProtocol.OwnerRegistration);
        var deviceRoutes = FdoRendezvousInfo.ParseDirectives(forDevice, FdoRendezvousProtocol.DeviceLookup);
        await Assert.That(ownerRoutes.Directives.Single().DirectiveIndex).IsEqualTo(1);
        await Assert.That(ownerRoutes.Directives.Single().Candidates.Single().BaseAddress.AbsoluteUri)
            .IsEqualTo("https://fleet.example:9443/");
        await Assert.That(deviceRoutes.Directives.Single().DirectiveIndex).IsEqualTo(1);
        await Assert.That(deviceRoutes.Directives.Single().Candidates.Single().BaseAddress.AbsoluteUri)
            .IsEqualTo("https://rvserver.local/");
        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.ParseDirectives(forOwner, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            FdoRendezvousInfo.ParseDirectives(forDevice, FdoRendezvousProtocol.OwnerRegistration))).IsTrue();
    }

    [Test]
    [Arguments("duplicate-marker")]
    [Arguments("duplicate-tag")]
    [Arguments("invalid-marker")]
    [Arguments("conflicting")]
    [Arguments("embedded")]
    public async Task OppositeRoleDirectivesStillRequireValidStructure(string malformed)
    {
        Instruction[] skipped = malformed switch
        {
            "duplicate-marker" => [Marker(1), Marker(1)],
            "duplicate-tag" => [Marker(1), Marker(255), Marker(255)],
            "invalid-marker" => [Value(1, writer => writer.WriteBoolean(true))],
            "conflicting" => [Marker(1), Marker(0)],
            "embedded" => [Marker(1), new Instruction(255, [0x18])],
            _ => throw new ArgumentOutOfRangeException(nameof(malformed)),
        };
        await Assert.That(Throws<CborContentException>(() =>
            FdoRendezvousInfo.ParseDirectives(Info(skipped, [Dns("rvserver.local")]), FdoRendezvousProtocol.DeviceLookup)))
            .IsTrue();
    }

    [Test]
    [Arguments(3, false)]
    [Arguments(4, true)]
    [Arguments(12, false)]
    [Arguments(12, true)]
    public async Task SharedDirectiveInterpretsPortAndProtocolOnlyForTheirOwnRole(int variable, bool afterDns)
    {
        Instruction invalid = variable switch
        {
            3 => Unsigned(3, 0),
            4 => Unsigned(4, 65536),
            12 when afterDns => Value(12, writer => writer.WriteTextString("http")),
            _ => Unsigned(12, 3),
        };
        FdoRendezvousProtocol applicable = variable == 4
            ? FdoRendezvousProtocol.OwnerRegistration : FdoRendezvousProtocol.DeviceLookup;
        FdoRendezvousProtocol other = variable == 4
            ? FdoRendezvousProtocol.DeviceLookup : FdoRendezvousProtocol.OwnerRegistration;
        Instruction dns = Dns("rvserver.local");
        Instruction ownPort = variable == 4 ? Unsigned(3, 443) : Unsigned(4, 9443);
        Instruction delay = Unsigned(13, 30);
        byte[] encoded = Info(afterDns ? [dns, delay, invalid, ownPort] : [invalid, ownPort, dns, delay]);
        FdoRendezvousDirective route = FdoRendezvousInfo.ParseDirectives(encoded, other).Directives.Single();
        await Assert.That(route.Candidates.Single().BaseAddress.AbsoluteUri)
            .IsEqualTo(variable == 4 ? "https://rvserver.local/" : "https://rvserver.local:9443/");
        await Assert.That(route.DelaySeconds).IsEqualTo((uint?)30);
        await Assert.That(variable == 12 && !afterDns
            ? Throws<NotSupportedException>(() => FdoRendezvousInfo.ParseDirectives(encoded, applicable))
            : Throws<CborContentException>(() => FdoRendezvousInfo.ParseDirectives(encoded, applicable))).IsTrue();
    }

    [Test]
    [Arguments(false, 4)]
    [Arguments(true, 12)]
    [Arguments(true, 6)]
    [Arguments(true, 15)]
    public async Task IrrelevantVariablesStillRequireValidEncodingAndUniqueTags(bool owner, int tag)
    {
        ulong variable = (ulong)tag;
        FdoRendezvousProtocol role = owner ? FdoRendezvousProtocol.OwnerRegistration : FdoRendezvousProtocol.DeviceLookup;
        await Assert.That(Throws<CborContentException>(() => FdoRendezvousInfo.Parse(
            Info([Dns("rvserver.local"), new Instruction(variable, [0x18])]), role))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoRendezvousInfo.Parse(
            Info([Unsigned(variable, 1), Dns("rvserver.local"), Unsigned(variable, 2)]), role))).IsTrue();
    }

    [Test]
    [Arguments(-1, -1, "https://rvserver.local/")]
    [Arguments(0, -1, "https://rvserver.local/")]
    [Arguments(1, -1, "http://rvserver.local/")]
    [Arguments(2, -1, "https://rvserver.local/")]
    [Arguments(-1, 80, "http://rvserver.local/")]
    [Arguments(-1, 443, "https://rvserver.local/")]
    [Arguments(1, 8080, "http://rvserver.local:8080/")]
    [Arguments(2, 8443, "https://rvserver.local:8443/")]
    [Arguments(0, 80, "https://rvserver.local:80/")]
    public async Task SelectsThePairedDeviceProtocolAndPort(int protocol, int port, string expected)
    {
        var instructions = new List<Instruction> { Dns("rvserver.local") };
        if (protocol >= 0)
        {
            instructions.Add(Unsigned(12, (ulong)protocol));
        }

        if (port >= 0)
        {
            instructions.Add(Unsigned(3, (ulong)port));
        }

        IReadOnlyList<FdoRendezvousServerCandidate> candidates =
            FdoRendezvousInfo.Parse(Info(instructions.ToArray()), FdoRendezvousProtocol.DeviceLookup);

        await Assert.That(candidates.Count).IsEqualTo(1);
        await Assert.That(candidates[0].BaseAddress.AbsoluteUri).IsEqualTo(expected);
    }

    [Test]
    public async Task RequiresAnExplicitProtocolForANonstandardDevicePort()
    {
        byte[] encoded = Info([Dns("rvserver.local"), Unsigned(3, 8080)]);

        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        IReadOnlyList<FdoRendezvousServerCandidate> owner =
            FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.OwnerRegistration);
        await Assert.That(owner[0].BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local/");
    }

    [Test]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    [Arguments(13)]
    [Arguments(14)]
    [Arguments(15)]
    [Arguments(16)]
    [Arguments(255)]
    public async Task RejectsUnsupportedConditionsExceptKnownDeviceOnlyFieldsOnTheOwner(int variable)
    {
        byte[] encoded = Info([Dns("rvserver.local"), Marker((ulong)variable), Unsigned(4, 9443)]);

        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        if (variable is >= 6 and <= 11 or 14 or 15)
        {
            IReadOnlyList<FdoRendezvousServerCandidate> owner =
                FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.OwnerRegistration);
            await Assert.That(owner.Single().BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local:9443/");
        }
        else
        {
            await Assert.That(Throws<NotSupportedException>(() =>
                FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.OwnerRegistration))).IsTrue();
        }
    }

    [Test]
    [Arguments("missing-local")]
    [Arguments("owner-only-local")]
    [Arguments("conflicting-roles")]
    [Arguments("invalid-marker")]
    [Arguments("duplicate-dns")]
    [Arguments("duplicate-protocol")]
    [Arguments("invalid-dns")]
    [Arguments("dns-not-text")]
    [Arguments("short-ip")]
    [Arguments("zero-port")]
    [Arguments("large-port")]
    [Arguments("port-not-integer")]
    [Arguments("malformed-embedded")]
    [Arguments("no-address")]
    [Arguments("variable-overflow")]
    public async Task RejectsMalformedOrInapplicableDirectives(string scenario)
    {
        Instruction[] directive = scenario switch
        {
            "missing-local" => [Dns("other.example")],
            "owner-only-local" => [Marker(1), Dns("rvserver.local")],
            "conflicting-roles" => [Marker(0), Marker(1), Dns("rvserver.local")],
            "invalid-marker" => [Value(0, writer => writer.WriteBoolean(false)), Dns("rvserver.local")],
            "duplicate-dns" => [Dns("rvserver.local"), Dns("other.example")],
            "duplicate-protocol" => [Dns("rvserver.local"), Unsigned(12, 1), Unsigned(12, 2)],
            "invalid-dns" => [Dns("bad/name")],
            "dns-not-text" => [Unsigned(5, 1)],
            "short-ip" => [Dns("rvserver.local"), Ip([127, 0, 0])],
            "zero-port" => [Dns("rvserver.local"), Unsigned(3, 0)],
            "large-port" => [Dns("rvserver.local"), Unsigned(4, 65536)],
            "port-not-integer" => [Dns("rvserver.local"), Value(3, writer => writer.WriteTextString("80"))],
            "malformed-embedded" => [Dns("rvserver.local"), new Instruction(3, [0x18])],
            "no-address" => [Marker(0)],
            "variable-overflow" => [Dns("rvserver.local"), Marker(256)],
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };

        FdoRendezvousProtocol role = scenario == "large-port"
            ? FdoRendezvousProtocol.OwnerRegistration : FdoRendezvousProtocol.DeviceLookup;
        await Assert.That(Throws<CborContentException>(() =>
            FdoRendezvousInfo.Parse(Info(directive), role))).IsTrue();
    }

    [Test]
    public async Task RejectsUnsupportedProtocolAndMalformedOuterOrWrappedValues()
    {
        byte[] unsupported = Info([Dns("rvserver.local"), Unsigned(12, 3)]);
        byte[] unwrappedDns = [0x81, 0x81, 0x82, 0x05, 0x6E, .. "rvserver.local"u8.ToArray()];
        byte[] trailing = [.. Info([Dns("rvserver.local")]), 0x00];

        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(unsupported, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        foreach (byte[] encoded in new[]
        {
            Array.Empty<byte>(), new byte[] { 0x80 }, new byte[] { 0x81, 0x80 },
            new byte[] { 0x81, 0x81, 0x81, 0x05 }, unwrappedDns, trailing,
        })
        {
            await Assert.That(Throws<CborContentException>(() =>
                FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsInputsBeyondTheByteDirectiveAndInstructionLimits()
    {
        Instruction[][] maximumDirectives = Enumerable.Range(0, 256)
            .Select(_ => new[] { Dns("rvserver.local") }).ToArray();
        Instruction[][] tooManyDirectives = Enumerable.Range(0, 257)
            .Select(_ => new[] { Dns("rvserver.local") }).ToArray();
        Instruction[] maximumInstructions = new[] { Dns("rvserver.local"), Marker(0) }
            .Concat(Enumerable.Range(6, 14).Select(variable => Marker((ulong)variable))).ToArray();
        Instruction[] tooManyInstructions = Enumerable.Range(0, 17)
            .Select(_ => Dns("rvserver.local")).ToArray();
        byte[] maximumBytes = Info([Dns("rvserver.local"),
            Value(15, writer => writer.WriteByteString(new byte[65507]))]);
        byte[] tooManyBytes = Info([Dns("rvserver.local"),
            Value(15, writer => writer.WriteByteString(new byte[65508]))]);

        await Assert.That(FdoRendezvousInfo.Parse(
            Info(maximumDirectives), FdoRendezvousProtocol.DeviceLookup).Count).IsEqualTo(256);
        await Assert.That(maximumBytes.Length).IsEqualTo(65535);
        await Assert.That(tooManyBytes.Length).IsEqualTo(65536);
        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(maximumBytes, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(Info(maximumInstructions), FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        await Assert.That(FdoRendezvousInfo.Parse(
            Info(maximumInstructions, [Dns("owner.example")]), FdoRendezvousProtocol.OwnerRegistration).Count)
            .IsEqualTo(1);
        foreach (byte[] encoded in new[]
        {
            tooManyBytes, Info(tooManyDirectives), Info(tooManyInstructions),
        })
        {
            await Assert.That(Throws<CborContentException>(() =>
                FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        }
    }

    [Test]
    public async Task ReadsIpv6AndNoncanonicalEmbeddedValuesWithoutResolvingThem()
    {
        byte[] ipv6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        byte[] encoded = Info(
            [Dns("rvserver.local")],
            [Ip(ipv6), new Instruction(12, [0x18, 0x01]), Unsigned(3, 8080)]);

        IReadOnlyList<FdoRendezvousServerCandidate> candidates =
            FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup);
        Array.Clear(encoded);
        Array.Clear(ipv6);

        await Assert.That(candidates.Count).IsEqualTo(2);
        await Assert.That(candidates[1].DirectiveIndex).IsEqualTo(1);
        await Assert.That(candidates[1].BaseAddress.AbsoluteUri).IsEqualTo("http://[::1]:8080/");
    }

    [Test]
    public async Task ReadsTheSameRendezvousInfoFromAnOwnershipVoucherHeader()
    {
        using var fixture = new AuthenticationFixture();

        IReadOnlyList<FdoRendezvousServerCandidate> candidates = FdoRendezvousInfo.ParseVoucherHeader(
            fixture.Voucher.HeaderTag, FdoRendezvousProtocol.OwnerRegistration);

        await Assert.That(candidates.Count).IsEqualTo(1);
        await Assert.That(candidates[0].BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local/");
        await Assert.That(Throws<CborContentException>(() =>
            FdoRendezvousInfo.ParseVoucherHeader(new byte[] { 0x40 }, FdoRendezvousProtocol.OwnerRegistration))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoRendezvousInfo.Parse(MixedDirectives(), (FdoRendezvousProtocol)42))).IsTrue();
    }

    [Test]
    public async Task ParseStillRejectsADelayThatParseDirectivesAccepts()
    {
        byte[] encoded = Info([Dns("rvserver.local"), Unsigned(13, 30)]);

        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.Parse(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        FdoRendezvousDirectiveSet set = FdoRendezvousInfo.ParseDirectives(encoded, FdoRendezvousProtocol.DeviceLookup);
        await Assert.That(set.Protocol).IsEqualTo(FdoRendezvousProtocol.DeviceLookup);
        await Assert.That(set.Directives.Count).IsEqualTo(1);
        await Assert.That(set.Directives[0].DelaySeconds).IsEqualTo(30U);
        await Assert.That(FdoRendezvousInfo.ParseDirectives(
            Info([Dns("rvserver.local"), Unsigned(13, uint.MaxValue)]),
            FdoRendezvousProtocol.DeviceLookup).Directives[0].DelaySeconds).IsEqualTo(uint.MaxValue);
    }

    [Test]
    [Arguments(FdoRendezvousProtocol.DeviceLookup)]
    [Arguments(FdoRendezvousProtocol.OwnerRegistration)]
    public async Task ParseDirectivesGroupsTheSameCandidatesAsParse(FdoRendezvousProtocol role)
    {
        IReadOnlyList<FdoRendezvousServerCandidate> flat = FdoRendezvousInfo.Parse(MixedDirectives(), role);
        FdoRendezvousDirectiveSet set = FdoRendezvousInfo.ParseDirectives(MixedDirectives(), role);

        await Assert.That(set.Directives.SelectMany(directive => directive.Candidates)
            .Select(candidate => (candidate.DirectiveIndex, candidate.BaseAddress))
            .SequenceEqual(flat.Select(candidate => (candidate.DirectiveIndex, candidate.BaseAddress)))).IsTrue();
        await Assert.That(set.Directives.Select(directive => directive.DirectiveIndex).SequenceEqual(
            role == FdoRendezvousProtocol.DeviceLookup ? new[] { 0, 1, 3 } : new[] { 0, 2, 3 })).IsTrue();
        await Assert.That(set.Directives.All(directive =>
            directive.DelaySeconds is null &&
            directive.Candidates.All(candidate => candidate.DirectiveIndex == directive.DirectiveIndex))).IsTrue();
    }

    [Test]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    [Arguments(14)]
    [Arguments(15)]
    [Arguments(16)]
    public async Task ParseDirectivesKeepsDelayAndRoleSpecificConditionChecks(int variable)
    {
        byte[] encoded = Info([Dns("rvserver.local"), Unsigned(13, 5), Marker((ulong)variable)]);

        await Assert.That(Throws<NotSupportedException>(() =>
            FdoRendezvousInfo.ParseDirectives(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
        if (variable == 16)
        {
            await Assert.That(Throws<NotSupportedException>(() =>
                FdoRendezvousInfo.ParseDirectives(encoded, FdoRendezvousProtocol.OwnerRegistration))).IsTrue();
        }
        else
        {
            FdoRendezvousDirective owner =
                FdoRendezvousInfo.ParseDirectives(encoded, FdoRendezvousProtocol.OwnerRegistration).Directives.Single();
            await Assert.That(owner.Candidates.Single().BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local/");
            await Assert.That(owner.DelaySeconds).IsEqualTo((uint?)5);
        }
    }

    [Test]
    [Arguments("delay-only")]
    [Arguments("too-large")]
    [Arguments("marker")]
    [Arguments("duplicate")]
    public async Task ParseDirectivesRejectsAddresslessAndMalformedDelays(string scenario)
    {
        byte[] encoded = scenario switch
        {
            "delay-only" => Info([Dns("rvserver.local")], [Unsigned(13, 30)]),
            "too-large" => Info([Dns("rvserver.local"), Unsigned(13, (ulong)uint.MaxValue + 1)]),
            "marker" => Info([Dns("rvserver.local"), Marker(13)]),
            _ => Info([Dns("rvserver.local"), Unsigned(13, 1), Unsigned(13, 2)]),
        };

        await Assert.That(Throws<CborContentException>(() =>
            FdoRendezvousInfo.ParseDirectives(encoded, FdoRendezvousProtocol.DeviceLookup))).IsTrue();
    }

    private static byte[] MixedDirectives() => Info(
        [Dns("rvserver.local")],
        [Marker(0), Dns("rvserver.local"), Unsigned(12, 1), Unsigned(3, 8080)],
        [Marker(1), Dns("owner.example")],
        [Dns("fleet.example"), Ip([192, 0, 2, 9]), Unsigned(12, 2), Unsigned(3, 8443), Unsigned(4, 9443)]);

    internal static Instruction Dns(string name) => Value(5, writer => writer.WriteTextString(name));

    internal static Instruction Ip(byte[] address) => Value(2, writer => writer.WriteByteString(address));

    internal static Instruction Unsigned(ulong variable, ulong number) =>
        Value(variable, writer => writer.WriteUInt64(number));

    internal static Instruction Marker(ulong variable) => Value(variable, writer => writer.WriteNull());

    private static Instruction Value(ulong variable, Action<CborWriter> write)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        write(writer);
        return new Instruction(variable, writer.Encode());
    }

    internal static byte[] Info(params Instruction[][] directives)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(directives.Length);
        foreach (Instruction[] directive in directives)
        {
            writer.WriteStartArray(directive.Length);
            foreach (Instruction instruction in directive)
            {
                writer.WriteStartArray(2);
                writer.WriteUInt64(instruction.Variable);
                writer.WriteByteString(instruction.Value);
                writer.WriteEndArray();
            }

            writer.WriteEndArray();
        }

        writer.WriteEndArray();
        return writer.Encode();
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

    internal readonly record struct Instruction(ulong Variable, byte[] Value);
}
