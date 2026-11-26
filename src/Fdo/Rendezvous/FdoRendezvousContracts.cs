// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Rendezvous;

/// <summary>Messages supported by the paired TO0 and TO1 roles.</summary>
public enum FdoRendezvousMessageType : ushort
{
    /// <summary>Owner requests a TO0 challenge.</summary>
    OwnerHello = 20,

    /// <summary>Rendezvous returns a TO0 challenge.</summary>
    OwnerHelloAck = 21,

    /// <summary>Owner submits a voucher and signed redirect.</summary>
    OwnerSign = 22,

    /// <summary>Rendezvous accepts the Owner registration.</summary>
    AcceptOwner = 23,

    /// <summary>Device requests a TO1 challenge.</summary>
    DeviceHello = 30,

    /// <summary>Rendezvous returns a TO1 challenge.</summary>
    DeviceHelloAck = 31,

    /// <summary>Device proves possession of its attestation key.</summary>
    ProveToRendezvous = 32,

    /// <summary>Rendezvous returns the signed Owner redirect.</summary>
    Redirect = 33,

    /// <summary>Terminal response to an authenticated delegated OwnerSign without Redirect permission.</summary>
    Error = 255,
}

/// <summary>HTTP transports supported for a paired TO2 address.</summary>
public enum FdoRendezvousTransportProtocol
{
    /// <summary>HTTP over TCP.</summary>
    Http = 3,

    /// <summary>HTTP over TLS.</summary>
    Https = 5,
}

/// <summary>A single Owner or Delegate address.</summary>
public sealed class FdoRendezvousAddress
{
    private readonly byte[]? _ipAddress;

    /// <summary>
    /// Creates an address with an IPv4 or IPv6 byte string, a DNS name, or
    /// both. Port zero and protocols other than HTTP and HTTPS are rejected.
    /// </summary>
    /// <param name="ipAddress">The IP address in the advertised endpoint.</param>
    /// <param name="dnsName">The DNS name in the advertised address.</param>
    /// <param name="port">The advertised TCP port.</param>
    /// <param name="protocol">The selected FDO subprotocol.</param>
    public FdoRendezvousAddress(
        ReadOnlyMemory<byte>? ipAddress,
        string? dnsName,
        ushort port,
        FdoRendezvousTransportProtocol protocol)
    {
        if (ipAddress is ReadOnlyMemory<byte> ip && ip.Length is not (4 or 16))
        {
            throw new ArgumentException("The Owner IP address must contain 4 or 16 bytes.", nameof(ipAddress));
        }

        if (dnsName is not null && Uri.CheckHostName(dnsName) != UriHostNameType.Dns)
        {
            throw new ArgumentException("The Owner DNS address must be a DNS name.", nameof(dnsName));
        }

        if (ipAddress is null && dnsName is null)
        {
            throw new ArgumentException("An Owner IP address or DNS name is required.");
        }

        ArgumentOutOfRangeException.ThrowIfZero(port);
        if (protocol is not (FdoRendezvousTransportProtocol.Http or FdoRendezvousTransportProtocol.Https))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol));
        }

        _ipAddress = ipAddress?.ToArray();
        DnsName = dnsName;
        Port = port;
        Protocol = protocol;
    }

    /// <summary>The IP address in network byte order, if supplied.</summary>
    public ReadOnlyMemory<byte>? IpAddress =>
        _ipAddress is null ? (ReadOnlyMemory<byte>?)null : (byte[])_ipAddress.Clone();

    /// <summary>The DNS name, if supplied.</summary>
    public string? DnsName { get; }

    /// <summary>The explicitly supplied TCP port.</summary>
    public ushort Port { get; }

    /// <summary>The Owner's HTTP transport.</summary>
    public FdoRendezvousTransportProtocol Protocol { get; }
}

/// <summary>A detached TO0 or TO1 response.</summary>
public sealed class FdoRendezvousResponse
{
    private readonly byte[] _encodedBody;

    /// <summary>Snapshots one response received by a rendezvous transport.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    public FdoRendezvousResponse(
        ushort protocolVersion,
        FdoRendezvousMessageType messageType,
        ReadOnlyMemory<byte> encodedBody)
    {
        if (encodedBody.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedBody));
        }

        ProtocolVersion = protocolVersion;
        MessageType = messageType;
        _encodedBody = encodedBody.ToArray();
    }

    /// <summary>The FDO protocol version.</summary>
    public ushort ProtocolVersion { get; }

    /// <summary>The response message type.</summary>
    public FdoRendezvousMessageType MessageType { get; }

    /// <summary>The exact encoded response body.</summary>
    public ReadOnlyMemory<byte> EncodedBody => (byte[])_encodedBody.Clone();
}

/// <summary>Exchanges messages with one Rendezvous Server session.</summary>
/// <remarks>
/// The host selects the server, authenticates its transport as required by
/// its policy, binds requests to one server session, and bounds response
/// bodies while reading. It must not retry or redirect an uncertain request.
/// The FDO role does not own this transport.
/// </remarks>
public interface IFdoRendezvousTransport
{
    /// <summary>Sends one request and returns the Rendezvous Server response.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="messageType">The numeric type of the FDO message.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<FdoRendezvousResponse> SendAsync(
        ushort protocolVersion,
        FdoRendezvousMessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken);
}

/// <summary>The exact, expiring fields of an accepted Rendezvous registration.</summary>
/// <remarks>
/// The store must protect the integrity of every field and return only
/// registrations previously accepted by the Rendezvous Server. The public
/// constructor lets a store rehydrate a persisted record; constructing one
/// does not authenticate it.
/// </remarks>
public sealed class FdoRendezvousRegistration
{
    private readonly byte[] _deviceGuid;
    private readonly byte[] _manufacturerKey;
    private readonly byte[] _ownerKey;
    private readonly byte[] _certificateChain;
    private readonly byte[] _signedRedirect;

    /// <summary>Rehydrates the exact accepted registration fields.</summary>
    /// <param name="registrationId">The stable identifier of a stored registration.</param>
    /// <param name="deviceGuid">The 16-byte Device GUID in wire order.</param>
    /// <param name="encodedManufacturerKey">The encoded manufacturer public key from the voucher.</param>
    /// <param name="encodedOwnerKey">The encoded Owner public key used in this exchange.</param>
    /// <param name="encodedDeviceCertificateChain">The exact encoded Device attestation chain from the voucher.</param>
    /// <param name="signedRedirect">The encoded, signed Owner redirect.</param>
    /// <param name="expiresAt">The exclusive end of the record's validity.</param>
    public FdoRendezvousRegistration(
        Guid registrationId,
        ReadOnlyMemory<byte> deviceGuid,
        ReadOnlyMemory<byte> encodedManufacturerKey,
        ReadOnlyMemory<byte> encodedOwnerKey,
        ReadOnlyMemory<byte> encodedDeviceCertificateChain,
        ReadOnlyMemory<byte> signedRedirect,
        DateTimeOffset expiresAt)
    {
        if (registrationId == Guid.Empty || deviceGuid.Length != 16)
        {
            throw new ArgumentException("A registration requires an identifier and a 16-byte Device GUID.");
        }

        if (encodedManufacturerKey.IsEmpty || encodedManufacturerKey.Length > ushort.MaxValue ||
            encodedOwnerKey.IsEmpty || encodedOwnerKey.Length > ushort.MaxValue ||
            encodedDeviceCertificateChain.IsEmpty || encodedDeviceCertificateChain.Length > ushort.MaxValue ||
            signedRedirect.IsEmpty || signedRedirect.Length > ushort.MaxValue)
        {
            throw new ArgumentException("The registration's encoded fields are empty or too large.");
        }

        RegistrationId = registrationId;
        _deviceGuid = deviceGuid.ToArray();
        _manufacturerKey = encodedManufacturerKey.ToArray();
        _ownerKey = encodedOwnerKey.ToArray();
        _certificateChain = encodedDeviceCertificateChain.ToArray();
        _signedRedirect = signedRedirect.ToArray();
        ExpiresAt = expiresAt;
    }

    /// <summary>An identifier changed for every accepted replacement.</summary>
    public Guid RegistrationId { get; }

    /// <summary>The Device GUID in wire order.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>The voucher-bound encoded manufacturer public key.</summary>
    public ReadOnlyMemory<byte> EncodedManufacturerKey => (byte[])_manufacturerKey.Clone();

    /// <summary>The verified final Owner public key from the voucher.</summary>
    public ReadOnlyMemory<byte> EncodedOwnerKey => (byte[])_ownerKey.Clone();

    /// <summary>The voucher-bound encoded Device certificate chain.</summary>
    public ReadOnlyMemory<byte> EncodedDeviceCertificateChain => (byte[])_certificateChain.Clone();

    /// <summary>The exact Owner- or Delegate-signed TO1 blob.</summary>
    public ReadOnlyMemory<byte> SignedRedirect => (byte[])_signedRedirect.Clone();

    /// <summary>The exclusive UTC expiration time.</summary>
    public DateTimeOffset ExpiresAt { get; }
}

/// <summary>Host storage for expiring nondelegated Rendezvous registrations.</summary>
/// <remarks>
/// Writes atomically replace the registration for the Device GUID. Reads
/// return the current record or null. The host protects stored records,
/// limits storage, applies any additional Owner or replacement policy, and
/// reconciles writes whose outcome is uncertain. A successful write must be
/// durable before it returns.
/// </remarks>
public interface IFdoRendezvousRegistrationStore
{
    /// <summary>Durably inserts or replaces one accepted registration.</summary>
    /// <param name="registration">The registration associated with the Device GUID.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask StoreAsync(FdoRendezvousRegistration registration, CancellationToken cancellationToken);

    /// <summary>Reads the current registration for a Device GUID.</summary>
    /// <param name="deviceGuid">The 16-byte Device GUID in wire order.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<FdoRendezvousRegistration?> FindAsync(
        ReadOnlyMemory<byte> deviceGuid,
        CancellationToken cancellationToken);
}

/// <summary>Identifies which protocol a Rendezvous Server session accepts.</summary>
public enum FdoRendezvousProtocol
{
    /// <summary>One Owner registration using TO0.</summary>
    OwnerRegistration = 0,

    /// <summary>One Device lookup using TO1.</summary>
    DeviceLookup = 1,
}

/// <summary>Trust, storage, and resource limits for one Rendezvous Server session.</summary>
public sealed class FdoRendezvousServerOptions
{
    /// <summary>CBOR-encoded FDO manufacturer public key to trust.</summary>
    public required ReadOnlyMemory<byte> TrustedManufacturerKey { get; init; }

    /// <summary>DER trust anchor for Device attestation certificates.</summary>
    public required ReadOnlyMemory<byte> DeviceTrustAnchor { get; init; }

    /// <summary>Revocation behavior for the Device attestation chain.</summary>
    public required X509RevocationMode DeviceRevocationMode { get; init; }

    /// <summary>Host-owned durable registration store.</summary>
    public IFdoRendezvousRegistrationStore? RegistrationStore { get; init; }

    /// <summary>
    /// Alternative to the legacy store. Enables the paired single-blob delegated
    /// path and stores direct Owner records in a separate slot.
    /// </summary>
    public IFdoAtomicRendezvousRegistrationStore? AtomicRegistrationStore { get; init; }

    /// <summary>Allows up to eight blobs in a mutually opted-in delegated TO1 lookup.</summary>
    public bool AllowMultipleDelegatedRedirects { get; init; }

    /// <summary>Required for TO0 with the atomic store; admits authenticated direct and delegated writes.</summary>
    public IFdoRendezvousRegistrationAdmission? RegistrationAdmission { get; init; }

    /// <summary>Offline status required for delegated registrations and lookups; null selects no revocation check.</summary>
    public FdoDelegateOfflineRevocationPolicy? DelegateOfflineRevocation { get; init; }

    /// <summary>Maximum accepted lifetime in seconds, greater than zero.</summary>
    public required uint MaxWaitSeconds { get; init; }

    /// <summary>Maximum voucher entries accepted in one registration, from 1 to 255.</summary>
    public int MaxVoucherEntries { get; init; } = 10;

    /// <summary>Maximum encoded message body accepted or sent by the server.</summary>
    public ushort MaxMessageSize { get; init; } = ushort.MaxValue;

    /// <summary>The clock used to establish and check registration expiry.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Explicitly selects the provisional paired rendezvous wire choices.</summary>
    public required bool UseProvisionalPairedProfile { get; init; }
}
