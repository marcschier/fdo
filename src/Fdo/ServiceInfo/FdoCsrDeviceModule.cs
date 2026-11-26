using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>
/// Stages one enrollment, re-enrollment, or server-key response for the
/// selected paired profile. The caller must authenticate ServiceInfo and
/// later validate certificate trust, authorize installation, and enforce TO2
/// completion.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoCsrDeviceModule : IFdoDeviceServiceInfoModule, IDisposable
{
    private readonly object _sync = new();
    private readonly FdoCsrBase64TextCodec _requestCodec;
    private readonly FdoCsrBase64TextCodec _responseCodec;
    private readonly FdoCsrServerKeygenCodec _serverKeygenCodec;
    private readonly int _maxRequestBytes;
    private readonly bool _requestCaCertificates;
    private readonly bool _requestCsrAttributes;
    private readonly bool _isReenrollment;
    private readonly bool _isServerKeyGeneration;
    private byte[]? _request;
    private Entry? _encodedRequest;
    private byte[]? _certificate;
    private byte[]? _privateKey;
    private FdoCaCertificates? _caCertificates;
    private FdoCsrAttributes? _csrAttributes;
    private State _state;

    public FdoCsrDeviceModule(
        ReadOnlyMemory<byte> request,
        int maxPlaintextBytes,
        int? maxResponsePlaintextBytes = null,
        bool requestCaCertificates = false,
        bool isReenrollment = false,
        bool requestCsrAttributes = false,
        bool isServerKeyGeneration = false)
    {
        _requestCodec = new FdoCsrBase64TextCodec(maxPlaintextBytes);
        _responseCodec = new FdoCsrBase64TextCodec(maxResponsePlaintextBytes ?? maxPlaintextBytes);
        _serverKeygenCodec = new FdoCsrServerKeygenCodec(maxResponsePlaintextBytes ?? maxPlaintextBytes);
        _maxRequestBytes = maxPlaintextBytes;
        _requestCaCertificates = requestCaCertificates;
        _requestCsrAttributes = requestCsrAttributes;
        _isReenrollment = isReenrollment;
        _isServerKeyGeneration = isServerKeyGeneration;
        if (isReenrollment && isServerKeyGeneration)
        {
            throw new ArgumentException("Server key generation is separate from simple re-enrollment.");
        }

        if (requestCsrAttributes)
        {
            if (!request.IsEmpty)
            {
                throw new ArgumentException("CSR discovery cannot also use a configured request.", nameof(request));
            }
        }
        else
        {
            PrepareRequest(request);
        }
    }

    public string Name => "fdo.csr";

    /// <summary>
    /// Records that the prepared CA or enrollment request was sent. The role must abort the
    /// session instead if transmission fails or its outcome is ambiguous.
    /// </summary>
    public void MarkRequestSent()
    {
        lock (_sync)
        {
            if (_state == State.CaRequestPrepared)
            {
                _state = State.AwaitingCaResponse;
                return;
            }

            if (_state == State.AttributesRequestPrepared)
            {
                _state = State.AwaitingAttributesResponse;
                return;
            }

            if (_state != State.RequestPrepared)
            {
                _state = State.Failed;
                throw new InvalidOperationException("No enrollment request is ready to send.");
            }

            _state = State.AwaitingResponse;
        }
    }

    public ValueTask<IReadOnlyList<Entry>> ReceiveAsync(
        string messageName,
        ReadOnlyMemory<byte> encodedValue,
        CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_state == State.Failed)
            {
                throw new InvalidOperationException("The Device enrollment module has failed.");
            }

            bool completed = false;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                IReadOnlyList<Entry> response = Process(messageName, encodedValue);
                completed = true;
                return ValueTask.FromResult(response);
            }
            finally
            {
                if (!completed)
                {
                    _state = State.Failed;
                    ClearPrivateKey();
                }
            }
        }
    }

    /// <summary>
    /// Returns a copy of the pending certificate, not an installed credential
    /// or evidence of completed onboarding.
    /// </summary>
    public ReadOnlyMemory<byte> CopyPendingCertificate()
    {
        lock (_sync)
        {
            if (_state == State.Failed || _certificate is null)
            {
                throw new InvalidOperationException("No usable enrollment response is pending.");
            }

            return (byte[])_certificate.Clone();
        }
    }

    /// <summary>Transfers the pending private key to the caller for installation.</summary>
    public byte[] TakePendingPrivateKey()
    {
        lock (_sync)
        {
            if (_state == State.Failed || _privateKey is null)
            {
                throw new InvalidOperationException("No usable server-generated key is pending.");
            }

            byte[] result = _privateKey;
            _privateKey = null;
            return result;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            ClearPrivateKey();
            _state = State.Failed;
        }
    }

    /// <summary>Returns detached CA material, not established trust.</summary>
    public FdoCaCertificates CopyPendingCaCertificates()
    {
        lock (_sync)
        {
            if (_state == State.Failed || _caCertificates is null)
            {
                throw new InvalidOperationException("No usable CA certificate response is pending.");
            }

            return _caCertificates;
        }
    }

    /// <summary>Returns the attributes staged from the Owner response.</summary>
    public FdoCsrAttributes CopyPendingCsrAttributes()
    {
        lock (_sync)
        {
            if (_state == State.Failed || _csrAttributes is null)
            {
                throw new InvalidOperationException("No usable CSR attributes response is pending.");
            }

            return _csrAttributes;
        }
    }

    /// <summary>Validates and prepares the host-selected CSR after discovery.</summary>
    public Entry PrepareEnrollmentRequest(ReadOnlyMemory<byte> request)
    {
        lock (_sync)
        {
            bool completed = false;
            try
            {
                if (_state != State.AttributesReceived)
                {
                    throw new InvalidOperationException("The Device is not awaiting a CSR after attribute discovery.");
                }

                PrepareRequest(request);
                _state = State.RequestPrepared;
                Entry result = CopyEncodedRequest();
                completed = true;
                return result;
            }
            finally
            {
                if (!completed)
                {
                    _state = State.Failed;
                }
            }
        }
    }

    /// <summary>Returns the exact validated request for the current enrollment.</summary>
    public ReadOnlyMemory<byte> CopyEnrollmentRequest()
    {
        lock (_sync)
        {
            if (_state == State.Failed || _request is null)
            {
                throw new InvalidOperationException("No usable enrollment request is available.");
            }

            return (byte[])_request.Clone();
        }
    }

    private IReadOnlyList<Entry> Process(string messageName, ReadOnlyMemory<byte> encodedValue)
    {
        if (string.Equals(messageName, "active", StringComparison.Ordinal))
        {
            bool active = ReadBoolean(encodedValue);
            if (active && _state == State.Inactive)
            {
                if (_requestCaCertificates)
                {
                    _state = State.CaRequestPrepared;
                    return [FdoCsrCaCertificatesCodec.EncodeRequest()];
                }

                return [PrepareNextRequest()];
            }

            if (!active && (_state == State.AwaitingCaResponse ||
                _state == State.AwaitingAttributesResponse || _state == State.AttributesReceived ||
                _state == State.AwaitingResponse || _state == State.ResponseReceived))
            {
                _state = State.Disabled;
                return Array.Empty<Entry>();
            }

            throw new InvalidOperationException("The enrollment module activation is out of order.");
        }

        if (_state != State.AwaitingCaResponse && _state != State.AwaitingAttributesResponse &&
            _state != State.AwaitingResponse)
        {
            throw new InvalidOperationException("The enrollment module is not awaiting a response.");
        }

        if (string.Equals(messageName, "error", StringComparison.Ordinal))
        {
            throw new FdoCsrModuleException(ReadErrorCode(encodedValue));
        }

        if (_state == State.AwaitingCaResponse &&
            string.Equals(messageName, "cacerts-res", StringComparison.Ordinal))
        {
            _caCertificates = _responseCodec.DecodeCaCertificates(new Entry("fdo.csr:cacerts-res", encodedValue));
            return [PrepareNextRequest()];
        }

        if (_state == State.AwaitingAttributesResponse &&
            string.Equals(messageName, "csrattrs-res", StringComparison.Ordinal))
        {
            _csrAttributes = _responseCodec.DecodeCsrAttributes(new Entry("fdo.csr:csrattrs-res", encodedValue));
            _state = State.AttributesReceived;
            return Array.Empty<Entry>();
        }

        string responseName = _isServerKeyGeneration ? "serverkeygen-res" :
            _isReenrollment ? "simplereenroll-res" : "simpleenroll-res";
        if (_state == State.AwaitingResponse &&
            string.Equals(messageName, responseName, StringComparison.Ordinal))
        {
            var entry = new Entry("fdo.csr:" + responseName, encodedValue);
            if (_isServerKeyGeneration)
            {
                (_certificate, _privateKey) = _serverKeygenCodec.DecodeResponse(entry);
            }
            else
            {
                _certificate = _responseCodec.DecodeResponse(
                    entry,
                    _request ?? throw new InvalidOperationException("The enrollment request is missing."),
                    _isReenrollment);
            }
            _state = State.ResponseReceived;
            return Array.Empty<Entry>();
        }

        throw new NotSupportedException("The paired Device enrollment module does not support this response.");
    }

    private Entry PrepareNextRequest()
    {
        if (_requestCsrAttributes && _csrAttributes is null)
        {
            _state = State.AttributesRequestPrepared;
            return FdoCsrAttributesRequestCodec.Encode();
        }

        _state = State.RequestPrepared;
        return CopyEncodedRequest();
    }

    private void PrepareRequest(ReadOnlyMemory<byte> request)
    {
        if (request.Length > _maxRequestBytes)
        {
            throw new CborContentException("The enrollment request exceeds the TO2 plaintext limit.");
        }

        byte[] snapshot = request.ToArray();
        _encodedRequest = _requestCodec.EncodeRequest(snapshot, _isReenrollment, _isServerKeyGeneration);
        _request = snapshot;
    }

    private Entry CopyEncodedRequest()
    {
        Entry entry = _encodedRequest ?? throw new InvalidOperationException("The enrollment request is missing.");
        return new Entry(entry.Key, entry.EncodedValue.ToArray());
    }

    private void ClearPrivateKey()
    {
        if (_privateKey is not null)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            _privateKey = null;
        }
    }

    private static bool ReadBoolean(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.Boolean)
        {
            throw new CborContentException("The enrollment activation must be a CBOR boolean.");
        }

        bool value = reader.ReadBoolean();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The enrollment activation has trailing data.");
        }

        return value;
    }

    private static ulong ReadErrorCode(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The enrollment error must be an unsigned integer.");
        }

        ulong code = reader.ReadUInt64();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The enrollment error has trailing data.");
        }

        return code;
    }

    private enum State
    {
        Inactive,
        CaRequestPrepared,
        AwaitingCaResponse,
        AttributesRequestPrepared,
        AwaitingAttributesResponse,
        AttributesReceived,
        RequestPrepared,
        AwaitingResponse,
        ResponseReceived,
        Disabled,
        Failed,
    }
}

internal sealed class FdoCsrModuleException(ulong errorCode)
    : Exception("The Owner returned fdo.csr error " + errorCode.ToString(CultureInfo.InvariantCulture) + ".")
{
    public ulong ErrorCode { get; } = errorCode;
}
