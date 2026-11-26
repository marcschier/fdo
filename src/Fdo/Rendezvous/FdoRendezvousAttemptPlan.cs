using System;
using System.Collections.Generic;

namespace Fdo.Rendezvous;

/// <summary>Identifies what the host does next under an attempt plan.</summary>
public enum FdoRendezvousPlanStepKind
{
    /// <summary>Authorize and, if permitted, try the attempt's candidate now.</summary>
    Attempt,

    /// <summary>Call <see cref="FdoRendezvousAttemptPlan.Next"/> again at or after the step's not-before time.</summary>
    Wait,

    /// <summary>An uncertain attempt must be resolved through <see cref="FdoRendezvousAttemptPlan.Reconcile"/>.</summary>
    ReconciliationRequired,

    /// <summary>An attempt succeeded. The plan is finished.</summary>
    Succeeded,

    /// <summary>The host stopped the plan. The plan is finished.</summary>
    Stopped,

    /// <summary>A bound was reached before an attempt succeeded. The plan is finished.</summary>
    Exhausted,
}

/// <summary>Identifies the bound that finished an exhausted plan.</summary>
public enum FdoRendezvousExhaustion
{
    /// <summary>The plan is not exhausted.</summary>
    None,

    /// <summary>No directive applies to the plan's role.</summary>
    NoApplicableDirective,

    /// <summary>Every permitted attempt was offered.</summary>
    AttemptBudget,

    /// <summary>The next attempt could not start before the deadline.</summary>
    Deadline,
}

/// <summary>The host's report of one offered attempt.</summary>
public enum FdoRendezvousAttemptResult
{
    /// <summary>The role run completed. The plan finishes as succeeded.</summary>
    Succeeded,

    /// <summary>Host policy refused the destination; nothing was sent.</summary>
    Declined,

    /// <summary>The run failed and the peer is known not to hold new state from it.</summary>
    Failed,

    /// <summary>The run ended without establishing whether the peer processed it.</summary>
    Uncertain,

    /// <summary>The host ends the plan without a further attempt.</summary>
    Stop,
}

/// <summary>Bounds for one <see cref="FdoRendezvousAttemptPlan"/>.</summary>
public sealed class FdoRendezvousAttemptPlanOptions
{
    /// <summary>The largest permitted value of <see cref="MaxAttempts"/>.</summary>
    public const int MaxAttemptLimit = 65_536;

    /// <summary>
    /// The number of attempts the plan offers, from 1 to 65,536. Every offered
    /// attempt counts, including one the host declines.
    /// </summary>
    public required int MaxAttempts { get; init; }

    /// <summary>
    /// The absolute time after which the plan offers no attempt. A delay that
    /// ends after the deadline exhausts the plan instead of being shortened.
    /// The deadline controls admission only: the plan does not cancel an
    /// attempt that is already running, so the host bounds in-flight I/O
    /// with its own cancellation.
    /// </summary>
    public required DateTimeOffset Deadline { get; init; }

    /// <summary>The clock for not-before and deadline decisions. The default is the system clock.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>The jitter source. The default is <see cref="System.Random.Shared"/>.</summary>
    public Random? Random { get; init; }
}

/// <summary>One destination the plan offers to the host.</summary>
public sealed class FdoRendezvousAttempt
{
    internal FdoRendezvousAttempt(
        FdoRendezvousServerCandidate candidate,
        int attemptNumber,
        int pass,
        int directivePosition,
        int candidatePosition)
    {
        Candidate = candidate;
        AttemptNumber = attemptNumber;
        Pass = pass;
        DirectivePosition = directivePosition;
        CandidatePosition = candidatePosition;
    }

    /// <summary>The untrusted endpoint the host must authorize before any connection.</summary>
    public FdoRendezvousServerCandidate Candidate { get; }

    /// <summary>The one-based number of this attempt within the plan.</summary>
    public int AttemptNumber { get; }

    /// <summary>The one-based pass over the applicable directives.</summary>
    public int Pass { get; }

    internal int DirectivePosition { get; }

    internal int CandidatePosition { get; }
}

/// <summary>The host's next action under an attempt plan.</summary>
public sealed class FdoRendezvousPlanStep
{
    internal FdoRendezvousPlanStep(
        FdoRendezvousPlanStepKind kind,
        FdoRendezvousAttempt? attempt,
        DateTimeOffset? notBefore,
        FdoRendezvousExhaustion exhaustion)
    {
        Kind = kind;
        Attempt = attempt;
        NotBefore = notBefore;
        Exhaustion = exhaustion;
    }

    /// <summary>The action the host takes.</summary>
    public FdoRendezvousPlanStepKind Kind { get; }

    /// <summary>
    /// The offered attempt for <see cref="FdoRendezvousPlanStepKind.Attempt"/>,
    /// the attempt to reconcile, or the attempt that finished the plan as
    /// succeeded or stopped; otherwise null.
    /// </summary>
    public FdoRendezvousAttempt? Attempt { get; }

    /// <summary>
    /// The earliest time of the next attempt for an attempt, a wait, or an
    /// attempt-budget or deadline exhaustion; otherwise null. For a deadline
    /// exhaustion this is the unshortened time, which can be later than the
    /// deadline.
    /// </summary>
    public DateTimeOffset? NotBefore { get; }

    /// <summary>The bound that finished an exhausted plan.</summary>
    public FdoRendezvousExhaustion Exhaustion { get; }

    /// <summary>Whether the plan is finished and returns this step from then on.</summary>
    public bool IsTerminal => Kind is FdoRendezvousPlanStepKind.Succeeded or
        FdoRendezvousPlanStepKind.Stopped or FdoRendezvousPlanStepKind.Exhausted;
}

/// <summary>
/// Steps bounded Rendezvous attempts over the role-applicable directives of
/// one RendezvousInfo without waiting, resolving, or connecting.
/// </summary>
/// <remarks>
/// <para>
/// The host calls <see cref="Next"/>, authorizes the offered destination,
/// runs at most one role session with fresh session and HTTP state, and
/// reports the outcome through <see cref="Report"/>. The plan never sleeps,
/// starts background work, resolves a name, follows a redirect, or changes a
/// scheme. A wait step returns the time to call <see cref="Next"/> again.
/// </para>
/// <para>
/// Candidates within a directive follow without delay, DNS before IP. The
/// provisional delay rules apply once per exhausted directive, not per
/// resolved address: after a directive other than the last, the plan waits
/// for its jittered RVDelaysec, or not at all without one. After the last
/// applicable directive it waits for that directive's jittered RVDelaysec,
/// or a jittered 120 seconds without one, and starts the next pass. Jitter
/// is uniform within plus or minus 25 percent. Directives for the other role
/// are not in the set and add no delay.
/// </para>
/// <para>
/// An uncertain attempt blocks the plan until the host reconciles it, for
/// example by establishing whether a TO0 registration was stored. TO0
/// refresh, post-TO2 recovery, and redirect following stay with the host.
/// Members are serialized, but the plan models one sequential host loop.
/// </para>
/// </remarks>
public sealed class FdoRendezvousAttemptPlan
{
    private const uint DefaultPassDelaySeconds = 120;

    private readonly object _lock = new();
    private readonly TimeProvider _time;
    private readonly Random _random;
    private readonly int _maxAttempts;
    private readonly DateTimeOffset _deadline;
    private int _directive;
    private int _candidate;
    private int _pass = 1;
    private int _attempts;
    private DateTimeOffset _notBefore;
    private FdoRendezvousAttempt? _outstanding;
    private FdoRendezvousAttempt? _uncertain;
    private FdoRendezvousPlanStep? _terminal;

    /// <summary>Creates a plan whose first attempt is available immediately.</summary>
    /// <param name="directives">The directives from <see cref="FdoRendezvousInfo.ParseDirectives"/>.</param>
    /// <param name="options">The attempt and deadline bounds.</param>
    public FdoRendezvousAttemptPlan(FdoRendezvousDirectiveSet directives, FdoRendezvousAttemptPlanOptions options)
    {
        ArgumentNullException.ThrowIfNull(directives);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.TimeProvider, nameof(options));
        if (options.MaxAttempts is < 1 or > FdoRendezvousAttemptPlanOptions.MaxAttemptLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxAttempts must be from 1 to 65,536.");
        }

        Directives = directives;
        _time = options.TimeProvider;
        _random = options.Random ?? Random.Shared;
        _maxAttempts = options.MaxAttempts;
        _deadline = options.Deadline;
        _notBefore = _time.GetUtcNow();
    }

    /// <summary>The directives and role the plan steps through.</summary>
    public FdoRendezvousDirectiveSet Directives { get; }

    /// <summary>The number of attempts offered so far.</summary>
    public int AttemptsOffered
    {
        get
        {
            lock (_lock)
            {
                return _attempts;
            }
        }
    }

    /// <summary>Returns the host's next action.</summary>
    /// <exception cref="InvalidOperationException">An offered attempt has not been reported.</exception>
    public FdoRendezvousPlanStep Next()
    {
        lock (_lock)
        {
            if (_terminal is not null)
            {
                return _terminal;
            }

            if (_outstanding is not null)
            {
                throw new InvalidOperationException("The offered attempt must be reported first.");
            }

            if (_uncertain is not null)
            {
                return new FdoRendezvousPlanStep(
                    FdoRendezvousPlanStepKind.ReconciliationRequired, _uncertain, null, FdoRendezvousExhaustion.None);
            }

            IReadOnlyList<FdoRendezvousDirective> directives = Directives.Directives;
            if (directives.Count == 0)
            {
                return Finish(FdoRendezvousPlanStepKind.Exhausted, null, null, FdoRendezvousExhaustion.NoApplicableDirective);
            }

            if (_attempts >= _maxAttempts)
            {
                return Finish(FdoRendezvousPlanStepKind.Exhausted, null, _notBefore, FdoRendezvousExhaustion.AttemptBudget);
            }

            DateTimeOffset now = _time.GetUtcNow();
            if (now >= _deadline || _notBefore >= _deadline)
            {
                return Finish(FdoRendezvousPlanStepKind.Exhausted, null, _notBefore, FdoRendezvousExhaustion.Deadline);
            }

            if (now < _notBefore)
            {
                return new FdoRendezvousPlanStep(
                    FdoRendezvousPlanStepKind.Wait, null, _notBefore, FdoRendezvousExhaustion.None);
            }

            _attempts++;
            _outstanding = new FdoRendezvousAttempt(
                directives[_directive].Candidates[_candidate], _attempts, _pass, _directive, _candidate);
            return new FdoRendezvousPlanStep(
                FdoRendezvousPlanStepKind.Attempt, _outstanding, _notBefore, FdoRendezvousExhaustion.None);
        }
    }

    /// <summary>Reports the outcome of the outstanding attempt.</summary>
    /// <param name="attempt">The attempt from the most recent attempt step.</param>
    /// <param name="result">The outcome. Uncertain requires a later <see cref="Reconcile"/>.</param>
    /// <exception cref="InvalidOperationException">The attempt is not the outstanding attempt.</exception>
    public void Report(FdoRendezvousAttempt attempt, FdoRendezvousAttemptResult result)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        if (result is < FdoRendezvousAttemptResult.Succeeded or > FdoRendezvousAttemptResult.Stop)
        {
            throw new ArgumentOutOfRangeException(nameof(result));
        }

        lock (_lock)
        {
            if (!ReferenceEquals(attempt, _outstanding))
            {
                throw new InvalidOperationException("The attempt is not the outstanding attempt of this plan.");
            }

            _outstanding = null;
            switch (result)
            {
                case FdoRendezvousAttemptResult.Succeeded:
                    Finish(FdoRendezvousPlanStepKind.Succeeded, attempt, null, FdoRendezvousExhaustion.None);
                    break;
                case FdoRendezvousAttemptResult.Stop:
                    Finish(FdoRendezvousPlanStepKind.Stopped, attempt, null, FdoRendezvousExhaustion.None);
                    break;
                case FdoRendezvousAttemptResult.Uncertain:
                    _uncertain = attempt;
                    break;
                default:
                    Advance(attempt);
                    break;
            }
        }
    }

    /// <summary>Resolves an uncertain attempt after the host has established its outcome.</summary>
    /// <param name="resolvedResult">Succeeded, Failed to continue with the next candidate, or Stop.</param>
    /// <exception cref="InvalidOperationException">No attempt is awaiting reconciliation.</exception>
    public void Reconcile(FdoRendezvousAttemptResult resolvedResult)
    {
        if (resolvedResult is not (FdoRendezvousAttemptResult.Succeeded or
            FdoRendezvousAttemptResult.Failed or FdoRendezvousAttemptResult.Stop))
        {
            throw new ArgumentOutOfRangeException(nameof(resolvedResult));
        }

        lock (_lock)
        {
            FdoRendezvousAttempt attempt = _uncertain ??
                throw new InvalidOperationException("No attempt is awaiting reconciliation.");
            _uncertain = null;
            _outstanding = attempt;
            Report(attempt, resolvedResult);
        }
    }

    private FdoRendezvousPlanStep Finish(
        FdoRendezvousPlanStepKind kind,
        FdoRendezvousAttempt? attempt,
        DateTimeOffset? notBefore,
        FdoRendezvousExhaustion exhaustion) =>
        _terminal = new FdoRendezvousPlanStep(kind, attempt, notBefore, exhaustion);

    private void Advance(FdoRendezvousAttempt attempt)
    {
        IReadOnlyList<FdoRendezvousDirective> directives = Directives.Directives;
        FdoRendezvousDirective directive = directives[attempt.DirectivePosition];
        DateTimeOffset now = _time.GetUtcNow();
        if (attempt.CandidatePosition + 1 < directive.Candidates.Count)
        {
            _directive = attempt.DirectivePosition;
            _candidate = attempt.CandidatePosition + 1;
            _notBefore = now;
            return;
        }

        _candidate = 0;
        uint? delaySeconds = directive.DelaySeconds;
        if (attempt.DirectivePosition + 1 < directives.Count)
        {
            _directive = attempt.DirectivePosition + 1;
        }
        else
        {
            _directive = 0;
            _pass++;
            delaySeconds ??= DefaultPassDelaySeconds;
        }

        _notBefore = delaySeconds is uint seconds ? AddClamped(now, Jitter(seconds)) : now;
    }

    private TimeSpan Jitter(uint seconds)
    {
        if (seconds == 0)
        {
            return TimeSpan.Zero;
        }

        double factor = 1 + ((_random.NextDouble() * 0.5) - 0.25);
        return TimeSpan.FromTicks((long)Math.Round(seconds * factor * TimeSpan.TicksPerSecond));
    }

    private static DateTimeOffset AddClamped(DateTimeOffset time, TimeSpan delay) =>
        DateTimeOffset.MaxValue - time < delay ? DateTimeOffset.MaxValue : time + delay;
}
