using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.ServiceInfo;

/// <summary>
/// Checks ServiceInfo turns and the disposition-specific Done20 body for one
/// paired TO2 run. The role must authenticate and decrypt received messages
/// before passing them here, and must close the channel after any failure.
/// </summary>
internal sealed class FdoTo2ServiceInfoState
{
    /// <summary>
    /// The most ServiceInfo request/response rounds one TO2 session accepts,
    /// including empty polls and keepalives after the Owner finishes.
    /// </summary>
    public const int MaxRounds = 256;
    private const int NonceLength = 16;
    private readonly object _sync = new();
    private readonly FdoTo2ServiceInfoCodec _deviceCodec;
    private readonly FdoTo2ServiceInfoCodec _ownerCodec;
    private readonly FdoTo2CompletionCodec _completion = new();
    private readonly byte[] _doneNonce;
    private Turn _turn;
    private int _rounds;
    private bool _deviceHasMore;
    private bool _ownerHasMore;
    private bool _ownerIsDone;

    public FdoTo2ServiceInfoState(
        ReadOnlyMemory<byte> doneNonce,
        int maxDevicePlaintextBytes = ushort.MaxValue,
        int maxOwnerPlaintextBytes = ushort.MaxValue)
    {
        if (doneNonce.Length != NonceLength)
        {
            throw new ArgumentException("The Done20 challenge must contain exactly 16 bytes.", nameof(doneNonce));
        }

        _doneNonce = doneNonce.ToArray();
        _deviceCodec = new FdoTo2ServiceInfoCodec(maxEncodedBytes: maxDevicePlaintextBytes);
        _ownerCodec = new FdoTo2ServiceInfoCodec(maxEncodedBytes: maxOwnerPlaintextBytes);
    }

    /// <summary>
    /// Records the Device half of the next round. The round limit is checked
    /// before decoding, so the caller neither sends nor processes a message
    /// beyond it.
    /// </summary>
    public FdoTo2ServiceInfoCodec.DeviceServiceInfo RecordDevice(ReadOnlyMemory<byte> plaintext)
    {
        lock (_sync)
        {
            bool completed = false;
            try
            {
                RequireTurn(Turn.Device);
                if (_rounds >= MaxRounds)
                {
                    throw new CborContentException("The ServiceInfo exchange exceeds the round limit.");
                }

                FdoTo2ServiceInfoCodec.DeviceServiceInfo message = _deviceCodec.DecodeDevice(plaintext);
                if ((_ownerHasMore || _ownerIsDone) &&
                    (message.IsMoreServiceInfo || message.ServiceInfo.Count != 0))
                {
                    throw new CborContentException("The Device must send an empty ServiceInfo message in this turn.");
                }

                _rounds++;
                _deviceHasMore = message.IsMoreServiceInfo;
                _turn = Turn.Owner;
                completed = true;
                return message;
            }
            finally
            {
                if (!completed)
                {
                    _turn = Turn.Failed;
                }
            }
        }
    }

    public FdoTo2ServiceInfoCodec.OwnerServiceInfo RecordOwner(ReadOnlyMemory<byte> plaintext)
    {
        lock (_sync)
        {
            bool completed = false;
            try
            {
                RequireTurn(Turn.Owner);
                FdoTo2ServiceInfoCodec.OwnerServiceInfo message = _ownerCodec.DecodeOwner(plaintext);
                if (_deviceHasMore &&
                    (message.IsMoreServiceInfo || message.IsDone || message.ServiceInfo.Count != 0))
                {
                    throw new CborContentException("The Owner must send an empty ServiceInfo message in this turn.");
                }

                if (_ownerIsDone &&
                    (message.IsMoreServiceInfo || !message.IsDone || message.ServiceInfo.Count != 0))
                {
                    throw new CborContentException("The Owner must continue sending empty completed ServiceInfo messages.");
                }

                if (message.IsMoreServiceInfo && message.IsDone)
                {
                    throw new CborContentException("The Owner cannot finish while it has more ServiceInfo to send.");
                }

                _ownerHasMore = message.IsMoreServiceInfo;
                _ownerIsDone |= message.IsDone;
                _turn = Turn.Device;
                completed = true;
                return message;
            }
            finally
            {
                if (!completed)
                {
                    _turn = Turn.Failed;
                }
            }
        }
    }

    /// <summary>
    /// Checks the Done20 body after an Owner-done message. A null replacement
    /// algorithm requires a null HMAC; otherwise the selected algorithm is
    /// required. This does not commit enrollment or establish DoneAck20 delivery.
    /// </summary>
    public FdoHashValue? RecordDone(
        ReadOnlyMemory<byte> plaintext, FdoHashAlgorithm? replacementAlgorithm = null)
    {
        lock (_sync)
        {
            bool completed = false;
            try
            {
                RequireTurn(Turn.Device);
                if (!_ownerIsDone)
                {
                    throw new InvalidOperationException("The Owner has not finished ServiceInfo.");
                }

                FdoTo2CompletionCodec.Done20 done = _completion.DecodeDone(plaintext);
                if (replacementAlgorithm is null && done.ReplacementHmac is not null)
                {
                    throw new CborContentException("Credential reuse requires a null replacement HMAC.");
                }

                if (replacementAlgorithm is not null &&
                    (done.ReplacementHmac is null || done.ReplacementHmac.Algorithm != replacementAlgorithm))
                {
                    throw new CborContentException("Credential replacement requires the selected HMAC algorithm.");
                }

                if (!CryptographicOperations.FixedTimeEquals(_doneNonce, done.Nonce.Span))
                {
                    throw new CryptographicException("The Done20 nonce does not match the Owner challenge.");
                }

                _turn = Turn.Done;
                completed = true;
                return done.ReplacementHmac;
            }
            finally
            {
                if (!completed)
                {
                    _turn = Turn.Failed;
                }
            }
        }
    }

    private void RequireTurn(Turn expected)
    {
        if (_turn == Turn.Failed)
        {
            throw new InvalidOperationException("The ServiceInfo state has failed.");
        }

        if (_turn != expected)
        {
            throw new InvalidOperationException("The ServiceInfo message is out of order.");
        }
    }

    private enum Turn
    {
        Device,
        Owner,
        Done,
        Failed,
    }
}
