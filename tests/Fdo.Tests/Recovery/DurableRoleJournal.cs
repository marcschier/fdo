using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Fdo.Tests.Recovery;

// Test adapter. Reopening must read the journal from disk; the lock models
// one storage authority in this process, not cross-process or power-loss safety.
internal sealed class DurableRoleJournal : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"fdo-role-{Guid.NewGuid():N}.json");
    private readonly object _gate = new();

    public Writer FenceAndOpen()
    {
        lock (_gate)
        {
            State current = Read();
            long fence = checked(current.Fence + 1);
            Write(current with { Fence = fence });
            return new Writer(this, fence);
        }
    }

    public Effect[] ReadEffects()
    {
        lock (_gate)
        {
            return Read().Effects.ToArray();
        }
    }

    private State Read()
    {
        try
        {
            using FileStream stream = File.OpenRead(_path);
            return JsonSerializer.Deserialize<State>(stream) ?? throw new InvalidDataException("Null recovery journal.");
        }
        catch (FileNotFoundException)
        {
            return new State(0, []);
        }
    }

    private void Write(State state)
    {
        using (var stream = new FileStream(_path + ".next", FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, state);
            stream.Flush(flushToDisk: true);
        }

        File.Move(_path + ".next", _path, overwrite: true);
    }

    public void Dispose()
    {
        File.Delete(_path);
        File.Delete(_path + ".next");
    }

    private sealed record State(long Fence, List<Effect> Effects);

    internal sealed record Effect(Guid RunId, string Operation, string Input);

    internal sealed class Writer(DurableRoleJournal journal, long fence)
    {
        public void Record(Guid runId, string operation, string input, int expectedVersion)
        {
            lock (journal._gate)
            {
                State state = journal.Read();
                if (state.Fence != fence)
                {
                    throw new InvalidOperationException("The writer was fenced.");
                }

                Effect? prior = state.Effects.Find(effect => effect.RunId == runId && effect.Operation == operation);
                if (prior is not null)
                {
                    if (prior.Input != input)
                    {
                        throw new InvalidOperationException("The effect identifier already has different inputs.");
                    }

                    return;
                }

                if (state.Effects.Count != expectedVersion)
                {
                    throw new InvalidOperationException("The resource version changed.");
                }

                state.Effects.Add(new Effect(runId, operation, input));
                journal.Write(state);
            }
        }
    }
}
