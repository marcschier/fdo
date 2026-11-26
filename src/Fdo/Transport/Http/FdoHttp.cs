using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Rendezvous;

namespace Fdo.Transport.Http;

/// <summary>Identifies the HTTP endpoint selected for a paired role run.</summary>
/// <remarks>
/// The address records the host's selection; it is not proof of the peer's
/// identity. HTTPS checks the name and chain with the platform TLS stack.
/// </remarks>
public interface IFdoHttpPeer
{
    /// <summary>The selected absolute HTTP or HTTPS base address.</summary>
    Uri BaseAddress { get; }
}

/// <summary>Runs the paired FDO roles over a direct HTTP or HTTPS connection.</summary>
/// <remarks>
/// Each call creates a single-use client session. Redirects, proxies, and
/// automatic cookies are disabled. The host chooses the endpoint and applies
/// its own network policy. The client resolves names without exposing or
/// pinning the resulting addresses. A failure ends the role run; it does not
/// authorize a retry or establish whether the peer processed the last request.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public static class FdoHttp
{
    /// <summary>Runs one paired Device TO2 enrollment.</summary>
    public static ValueTask<FdoDeviceEnrollment> RunDeviceAsync(
        FdoDeviceSession device,
        Uri baseAddress,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunDeviceAsync(device, baseAddress, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Runs one Device TO2 enrollment with optional private CA trust for HTTPS.</summary>
    public static async ValueTask<FdoDeviceEnrollment> RunDeviceAsync(
        FdoDeviceSession device, Uri baseAddress, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ArgumentNullException.ThrowIfNull(device);
        using FdoHttpClient client = CreateClient(baseAddress, privateTrust);
        IFdoDeviceTransport transport = CreateSession(
            client, baseAddress, FdoProtocolKind.TransferOwnership2, maxResponseBytes).CreateDeviceTransport();
        return await device.RunAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs one paired Device Initialize exchange.</summary>
    /// <remarks>
    /// The Device authorization callback can inspect the selected address
    /// through <see cref="IFdoHttpPeer"/> on the supplied transport. It must
    /// still authorize the station and Device relationship independently.
    /// </remarks>
    public static ValueTask<FdoDeviceInitializeCredential> RunDeviceInitializeAsync(
        FdoDeviceInitializeSession device,
        Uri baseAddress,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunDeviceInitializeAsync(device, baseAddress, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Runs one Device Initialize exchange with optional private CA trust for HTTPS.</summary>
    public static async ValueTask<FdoDeviceInitializeCredential> RunDeviceInitializeAsync(
        FdoDeviceInitializeSession device, Uri baseAddress, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ArgumentNullException.ThrowIfNull(device);
        using FdoHttpClient client = CreateClient(baseAddress, privateTrust);
        IFdoDeviceInitializeTransport transport = CreateSession(
            client, baseAddress, FdoProtocolKind.DeviceInitialize, maxResponseBytes).CreateInitializeTransport();
        return await device.RunAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs one paired Owner TO0 registration.</summary>
    public static ValueTask<uint> RunOwnerRendezvousAsync(
        FdoOwnerRendezvousSession owner,
        Uri baseAddress,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunOwnerRendezvousAsync(owner, baseAddress, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Runs one Owner TO0 registration with optional private CA trust for HTTPS.</summary>
    public static async ValueTask<uint> RunOwnerRendezvousAsync(
        FdoOwnerRendezvousSession owner, Uri baseAddress, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ArgumentNullException.ThrowIfNull(owner);
        using FdoHttpClient client = CreateClient(baseAddress, privateTrust);
        IFdoRendezvousTransport transport = CreateSession(
            client, baseAddress, FdoProtocolKind.TransferOwnership0, maxResponseBytes).CreateRendezvousTransport();
        return await owner.RunAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs one paired Device TO1 lookup.</summary>
    /// <remarks>
    /// A redirect ends this run without being followed. Its untrusted target
    /// is available on the resulting <see cref="FdoTransportException"/>.
    /// The host decides whether to start a new session after applying its
    /// endpoint, TLS, and redirect-loop policies.
    /// </remarks>
    public static ValueTask<FdoDeviceRendezvousResult> RunDeviceRendezvousAsync(
        FdoDeviceRendezvousSession device,
        Uri baseAddress,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunDeviceRendezvousAsync(device, baseAddress, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Runs one Device TO1 lookup with optional private CA trust for HTTPS.</summary>
    public static async ValueTask<FdoDeviceRendezvousResult> RunDeviceRendezvousAsync(
        FdoDeviceRendezvousSession device, Uri baseAddress, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ArgumentNullException.ThrowIfNull(device);
        using FdoHttpClient client = CreateClient(baseAddress, privateTrust);
        IFdoRendezvousTransport transport = CreateSession(
            client, baseAddress, FdoProtocolKind.TransferOwnership1, maxResponseBytes).CreateRendezvousTransport();
        return await device.RunAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Caches all pages from one delegated TO1 lookup over a single HTTP session.</summary>
    public static async ValueTask<IReadOnlyList<FdoDeviceRendezvousResult>> RunDeviceRendezvousBatchAsync(
        FdoDeviceRendezvousSession device, Uri baseAddress, int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default, FdoHttpPrivateTrust? privateTrust = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        using FdoHttpClient client = CreateClient(baseAddress, privateTrust);
        IFdoRendezvousTransport transport = CreateSession(
            client, baseAddress, FdoProtocolKind.TransferOwnership1, maxResponseBytes).CreateRendezvousTransport();
        return await device.RunBatchAsync(transport, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Takes one step of a Device TO1 attempt plan over HTTP or HTTPS.</summary>
    /// <remarks>
    /// <para>
    /// The method calls <see cref="FdoRendezvousAttemptPlan.Next"/> once and
    /// returns any step other than an attempt without waiting. For an attempt
    /// it asks <paramref name="authorizeDestination"/> about the candidate
    /// URI; a refusal is reported as declined without a connection. Otherwise
    /// it runs a new session from <paramref name="createSession"/> on a new
    /// HTTP client, as <see cref="RunDeviceRendezvousAsync(FdoDeviceRendezvousSession,Uri,int,CancellationToken)"/> does.
    /// </para>
    /// <para>
    /// Authorization is URI-only: the client resolves the name through the
    /// system resolver and neither exposes nor pins the resulting address.
    /// A host that must control DNS, SNI, or the admitted address implements
    /// <see cref="IFdoRendezvousTransport"/> and drives the plan's
    /// <see cref="FdoRendezvousAttemptPlan.Next"/> and
    /// <see cref="FdoRendezvousAttemptPlan.Report"/> members directly.
    /// </para>
    /// <para>
    /// A completed lookup reports success. A network failure or an HTTP status
    /// that the binding does not permit reports failed and is returned in
    /// <see cref="FdoRendezvousStepResult{T}.Error"/>; the method does not
    /// retry, and a later candidate needs another call and authorization. A
    /// redirect is a terminal handoff: it reports stop and is returned
    /// unfollowed. A malformed or oversized response, an authorization-token
    /// violation, an invalid local request, or any other failure also reports
    /// stop and is returned, so the plan does not advance past a failure it
    /// cannot classify as ordinary. Cancellation, a callback exception, or a
    /// session that has already started reports stop and rethrows without a
    /// request; cancellation requested inside a callback is checked before the
    /// run begins.
    /// </para>
    /// </remarks>
    /// <param name="plan">A Device lookup plan.</param>
    /// <param name="createSession">Creates a new, unstarted session for each attempt.</param>
    /// <param name="authorizeDestination">Returns whether host policy permits the candidate.</param>
    /// <param name="maxResponseBytes">The largest accepted response body, from 1 to 65,535 bytes.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    public static ValueTask<FdoRendezvousStepResult<FdoDeviceRendezvousResult>> RunDeviceRendezvousStepAsync(
        FdoRendezvousAttemptPlan plan,
        Func<FdoDeviceRendezvousSession> createSession,
        Func<FdoRendezvousAttempt, bool> authorizeDestination,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunDeviceRendezvousStepAsync(plan, createSession, authorizeDestination, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Takes one Device TO1 plan step with optional private CA trust for this HTTPS attempt.</summary>
    public static async ValueTask<FdoRendezvousStepResult<FdoDeviceRendezvousResult>> RunDeviceRendezvousStepAsync(
        FdoRendezvousAttemptPlan plan, Func<FdoDeviceRendezvousSession> createSession,
        Func<FdoRendezvousAttempt, bool> authorizeDestination, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ValidateStep(plan, createSession, authorizeDestination, maxResponseBytes, FdoRendezvousProtocol.DeviceLookup);
        FdoRendezvousPlanStep step = plan.Next();
        if (step.Kind != FdoRendezvousPlanStepKind.Attempt)
        {
            return new FdoRendezvousStepResult<FdoDeviceRendezvousResult>(step);
        }

        FdoRendezvousAttempt attempt = step.Attempt!;
        FdoDeviceRendezvousSession session;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!authorizeDestination(attempt))
            {
                plan.Report(attempt, FdoRendezvousAttemptResult.Declined);
                return new FdoRendezvousStepResult<FdoDeviceRendezvousResult>(step, FdoRendezvousAttemptResult.Declined);
            }

            RequireHttpsForPrivateTrust(attempt.Candidate.BaseAddress, privateTrust);
            cancellationToken.ThrowIfCancellationRequested();
            session = createSession() ?? throw new InvalidOperationException("The session factory returned null.");
            if (session.IsStarted)
            {
                throw new InvalidOperationException("Each attempt requires a new, unstarted session.");
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            plan.Report(attempt, FdoRendezvousAttemptResult.Stop);
            throw;
        }

        try
        {
            FdoDeviceRendezvousResult value = await RunDeviceRendezvousAsync(
                session, attempt.Candidate.BaseAddress, maxResponseBytes, cancellationToken, privateTrust).ConfigureAwait(false);
            plan.Report(attempt, FdoRendezvousAttemptResult.Succeeded);
            return new FdoRendezvousStepResult<FdoDeviceRendezvousResult>(
                step, FdoRendezvousAttemptResult.Succeeded, value, hasValue: true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            plan.Report(attempt, FdoRendezvousAttemptResult.Stop);
            throw;
        }
        catch (Exception exception)
        {
            FdoRendezvousAttemptResult result = exception is FdoTransportException
            {
                Failure: FdoTransportFailure.Network or FdoTransportFailure.UnexpectedStatus,
            }
                ? FdoRendezvousAttemptResult.Failed
                : FdoRendezvousAttemptResult.Stop;
            plan.Report(attempt, result);
            return new FdoRendezvousStepResult<FdoDeviceRendezvousResult>(step, result, error: exception);
        }
    }

    /// <summary>Takes one step of an Owner TO0 attempt plan over HTTPS.</summary>
    /// <remarks>
    /// <para>
    /// The method follows the Device lookup runner for
    /// non-attempt steps, URI-only authorization, declined destinations, and
    /// fresh session and HTTP state. A completed registration reports success
    /// and returns the accepted wait in seconds.
    /// </para>
    /// <para>
    /// Once the TO0 run starts, a failure or cancellation cannot prove that
    /// the Rendezvous Server stored no registration, so it reports uncertain.
    /// The plan then returns a reconciliation step until the host calls
    /// <see cref="FdoRendezvousAttemptPlan.Reconcile"/>. Cancellation still
    /// rethrows. Cancellation known before the run starts, including
    /// cancellation requested inside the authorization or session callback,
    /// a callback exception, or a started session reports stop and rethrows
    /// without a request. TO0 refresh before the accepted wait ends stays with
    /// the host.
    /// </para>
    /// </remarks>
    /// <param name="plan">An Owner registration plan.</param>
    /// <param name="createSession">Creates a new, unstarted session for each attempt.</param>
    /// <param name="authorizeDestination">Returns whether host policy permits the candidate.</param>
    /// <param name="maxResponseBytes">The largest accepted response body, from 1 to 65,535 bytes.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    public static ValueTask<FdoRendezvousStepResult<uint>> RunOwnerRendezvousStepAsync(
        FdoRendezvousAttemptPlan plan,
        Func<FdoOwnerRendezvousSession> createSession,
        Func<FdoRendezvousAttempt, bool> authorizeDestination,
        int maxResponseBytes = ushort.MaxValue,
        CancellationToken cancellationToken = default) =>
        RunOwnerRendezvousStepAsync(plan, createSession, authorizeDestination, maxResponseBytes, cancellationToken, privateTrust: null);

    /// <summary>Takes one Owner TO0 plan step with optional private CA trust for this HTTPS attempt.</summary>
    public static async ValueTask<FdoRendezvousStepResult<uint>> RunOwnerRendezvousStepAsync(
        FdoRendezvousAttemptPlan plan, Func<FdoOwnerRendezvousSession> createSession,
        Func<FdoRendezvousAttempt, bool> authorizeDestination, int maxResponseBytes, CancellationToken cancellationToken,
        FdoHttpPrivateTrust? privateTrust)
    {
        ValidateStep(plan, createSession, authorizeDestination, maxResponseBytes, FdoRendezvousProtocol.OwnerRegistration);
        FdoRendezvousPlanStep step = plan.Next();
        if (step.Kind != FdoRendezvousPlanStepKind.Attempt)
        {
            return new FdoRendezvousStepResult<uint>(step);
        }

        FdoRendezvousAttempt attempt = step.Attempt!;
        FdoOwnerRendezvousSession session;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!authorizeDestination(attempt))
            {
                plan.Report(attempt, FdoRendezvousAttemptResult.Declined);
                return new FdoRendezvousStepResult<uint>(step, FdoRendezvousAttemptResult.Declined);
            }

            RequireHttpsForPrivateTrust(attempt.Candidate.BaseAddress, privateTrust);
            cancellationToken.ThrowIfCancellationRequested();
            session = createSession() ?? throw new InvalidOperationException("The session factory returned null.");
            if (session.IsStarted)
            {
                throw new InvalidOperationException("Each attempt requires a new, unstarted session.");
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            plan.Report(attempt, FdoRendezvousAttemptResult.Stop);
            throw;
        }

        try
        {
            uint wait = await RunOwnerRendezvousAsync(
                session, attempt.Candidate.BaseAddress, maxResponseBytes, cancellationToken, privateTrust).ConfigureAwait(false);
            plan.Report(attempt, FdoRendezvousAttemptResult.Succeeded);
            return new FdoRendezvousStepResult<uint>(step, FdoRendezvousAttemptResult.Succeeded, wait, hasValue: true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            plan.Report(attempt, FdoRendezvousAttemptResult.Uncertain);
            throw;
        }
        catch (Exception exception)
        {
            plan.Report(attempt, FdoRendezvousAttemptResult.Uncertain);
            return new FdoRendezvousStepResult<uint>(step, FdoRendezvousAttemptResult.Uncertain, error: exception);
        }
    }

    private static void ValidateStep(
        FdoRendezvousAttemptPlan plan,
        object createSession,
        object authorizeDestination,
        int maxResponseBytes,
        FdoRendezvousProtocol protocol)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(createSession);
        ArgumentNullException.ThrowIfNull(authorizeDestination);
        if (plan.Directives.Protocol != protocol)
        {
            throw new ArgumentException("The plan was created for the other Rendezvous role.", nameof(plan));
        }

        if (maxResponseBytes is <= 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        }
    }

    private static FdoHttpClient CreateClient(Uri baseAddress, FdoHttpPrivateTrust? privateTrust)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        RequireHttpsForPrivateTrust(baseAddress, privateTrust);
        return FdoHttpClient.CreatePaired(privateTrust);
    }

    private static void RequireHttpsForPrivateTrust(Uri baseAddress, FdoHttpPrivateTrust? privateTrust)
    {
        if (privateTrust is not null && (!baseAddress.IsAbsoluteUri || baseAddress.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Private CA trust requires an absolute HTTPS endpoint.", nameof(baseAddress));
        }
    }

    private static FdoHttpClientSession CreateSession(
        FdoHttpClient client, Uri baseAddress, FdoProtocolKind protocol, int maxResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        if (baseAddress.IsAbsoluteUri && baseAddress.UserInfo.Length != 0)
        {
            throw new ArgumentException("The HTTP base address must not contain user information.", nameof(baseAddress));
        }

        if (maxResponseBytes is <= 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes));
        }

        return new FdoHttpClientSession(
            client, baseAddress, protocol, FdoProtocolVersion.V20, maxResponseBytes);
    }

}
