// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>
/// Receives one message for a Device module and returns its outbound entries.
/// The processor owns activation responses; modules must not emit active keys.
/// </summary>
internal interface IFdoDeviceServiceInfoModule
{
    string Name { get; }

    ValueTask<IReadOnlyList<Entry>> ReceiveAsync(
        string messageName,
        ReadOnlyMemory<byte> encodedValue,
        CancellationToken cancellationToken);
}

/// <summary>
/// Processes Owner ServiceInfo in order for one Device TO2 session.
/// The caller must authenticate and decrypt the message before invoking it.
/// The processor does not transmit messages or authenticate a peer.
/// </summary>
internal sealed class FdoDeviceServiceInfoProcessor
{
    private static readonly byte[] EncodedTrue = [0xF5];
    private static readonly byte[] EncodedFalse = [0xF4];

    private readonly Dictionary<string, Module> _modules = new(StringComparer.Ordinal);
    private readonly FdoServiceInfoCodec _codec;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;
    private int _busy;
    private volatile bool _faulted;

    public FdoDeviceServiceInfoProcessor(
        IReadOnlyList<IFdoDeviceServiceInfoModule> modules,
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        ArgumentNullException.ThrowIfNull(modules);
        _codec = new FdoServiceInfoCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;

        foreach (IFdoDeviceServiceInfoModule? implementation in modules)
        {
            if (implementation is null || string.IsNullOrEmpty(implementation.Name) ||
                implementation.Name.Contains(':', StringComparison.Ordinal))
            {
                throw new ArgumentException("Module names must be nonempty and cannot contain a colon.", nameof(modules));
            }

            if (!_modules.TryAdd(implementation.Name, new Module(implementation)))
            {
                throw new ArgumentException("Device module names must be unique.", nameof(modules));
            }
        }
    }

    /// <summary>
    /// True after an input, module, output-limit, or cancellation failure.
    /// A faulted processor cannot be used for another message.
    /// </summary>
    public bool IsFaulted => _faulted;

    /// <summary>
    /// Interprets every entry before returning one encoded response. A response
    /// that exceeds the configured limit is rejected rather than split.
    /// </summary>
    public async Task<ReadOnlyMemory<byte>> ProcessAsync(
        ReadOnlyMemory<byte> encodedServiceInfo,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("A ServiceInfo message is already being processed.");
        }

        bool completed = false;
        try
        {
            if (_faulted)
            {
                throw new InvalidOperationException("The ServiceInfo processor has failed.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<Entry> entries = _codec.Decode(encodedServiceInfo);
            var responses = new List<Entry>();
            long encodedEntriesSize = 0;
            foreach (Entry entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                (string moduleName, string messageName) = SplitKey(entry.Key);
                if (!_modules.TryGetValue(moduleName, out Module? module))
                {
                    AppendResponses(responses, [new Entry(moduleName + ":active", EncodedFalse)], ref encodedEntriesSize);
                    continue;
                }

                if (messageName == "active")
                {
                    bool activate = ReadBoolean(entry.EncodedValue);
                    if ((activate && module.State == ModuleState.Active) ||
                        (!activate && module.State == ModuleState.Disabled))
                    {
                        continue;
                    }

                    if ((activate && module.State == ModuleState.Disabled) ||
                        (!activate && module.State == ModuleState.Inactive))
                    {
                        throw new CborContentException("The Owner sent an invalid module activation transition.");
                    }

                    module.State = activate ? ModuleState.Active : ModuleState.Disabled;
                    if (activate)
                    {
                        AppendResponses(responses, [new Entry(moduleName + ":active", EncodedTrue)], ref encodedEntriesSize);
                    }
                }
                else if (module.State != ModuleState.Active)
                {
                    throw new CborContentException("The Owner referenced a module that is not active.");
                }

                IReadOnlyList<Entry> produced = await module.Implementation.ReceiveAsync(
                    messageName, entry.EncodedValue, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                AppendResponses(responses, produced, ref encodedEntriesSize, rejectActiveKeys: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            ReadOnlyMemory<byte> result = _codec.Encode(responses);
            completed = true;
            return result;
        }
        finally
        {
            if (!completed)
            {
                _faulted = true;
            }

            Volatile.Write(ref _busy, 0);
        }
    }

    private void AppendResponses(
        List<Entry> destination,
        IReadOnlyList<Entry> produced,
        ref long encodedEntriesSize,
        bool rejectActiveKeys = false)
    {
        ArgumentNullException.ThrowIfNull(produced);
        ReadOnlyMemory<byte> encoded = _codec.Encode(produced);
        IReadOnlyList<Entry> snapshot = _codec.Decode(encoded);
        foreach (Entry entry in snapshot)
        {
            (_, string messageName) = SplitKey(entry.Key);
            if (rejectActiveKeys && messageName == "active")
            {
                throw new CborContentException("Device modules cannot emit activation responses directly.");
            }
        }

        long count = (long)destination.Count + snapshot.Count;
        long entriesSize = encodedEntriesSize + encoded.Length -
            FdoCborCodec.GetHeaderSize((ulong)snapshot.Count);
        if (1L + (3L * count) > _maxItems ||
            FdoCborCodec.GetHeaderSize((ulong)count) + entriesSize > _maxEncodedBytes)
        {
            throw new CborContentException("Device ServiceInfo responses exceed the configured limit.");
        }

        destination.AddRange(snapshot);

        encodedEntriesSize = entriesSize;
    }

    private static (string Module, string Message) SplitKey(string key)
    {
        int separator = key.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == key.Length - 1)
        {
            throw new CborContentException("A ServiceInfo key must contain a module and message name.");
        }

        return (key[..separator], key[(separator + 1)..]);
    }

    private static bool ReadBoolean(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.Boolean)
        {
            throw new CborContentException("A module activation value must be a CBOR boolean.");
        }

        return reader.ReadBoolean();
    }

    private enum ModuleState
    {
        Inactive = 0,
        Active = 1,
        Disabled = 2,
    }

    private sealed class Module(IFdoDeviceServiceInfoModule implementation)
    {
        public IFdoDeviceServiceInfoModule Implementation { get; } = implementation;

        public ModuleState State { get; set; }
    }
}
