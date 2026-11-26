using System;
using Fdo.Rendezvous;

namespace Fdo.Transport.Http;

/// <summary>The outcome of one host-stepped Rendezvous call.</summary>
/// <typeparam name="T">The role result type.</typeparam>
public sealed class FdoRendezvousStepResult<T>
{
    internal FdoRendezvousStepResult(
        FdoRendezvousPlanStep step,
        FdoRendezvousAttemptResult? reported = null,
        T? value = default,
        bool hasValue = false,
        Exception? error = null)
    {
        Step = step;
        Reported = reported;
        Value = value;
        HasValue = hasValue;
        Error = error;
    }

    /// <summary>
    /// The plan step that drove the call. A step other than an attempt is
    /// returned without any action; the host waits, reconciles, or stops.
    /// </summary>
    public FdoRendezvousPlanStep Step { get; }

    /// <summary>The outcome reported to the plan, or null when no attempt was offered.</summary>
    public FdoRendezvousAttemptResult? Reported { get; }

    /// <summary>Whether the role run completed and <see cref="Value"/> holds its result.</summary>
    public bool HasValue { get; }

    /// <summary>The role result when <see cref="HasValue"/> is true.</summary>
    public T? Value { get; }

    /// <summary>
    /// The failure of an attempted run that was reported rather than thrown,
    /// such as a transport failure or an unfollowed TO1 redirect.
    /// </summary>
    public Exception? Error { get; }
}
