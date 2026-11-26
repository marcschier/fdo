# FDO host recovery

The host must reconcile uncertain durable effects before starting a fresh
authenticated FDO session. Session objects, HTTP tokens, nonces, and protected
message counters are not recoverable state. A callback exception, cancellation,
or a lost response does not establish that the callback or the peer rolled
back. The library's in-memory progress properties are diagnostic observations,
not a durable log.

## What the host records

Before any durable effect, record the local run ID, the role, the operation,
the authenticated Device or provisioning identity, the expected version of
the affected resource, and a reference to the exact intended effect. An
idempotency key combines the local run ID and operation; include an effect
identifier where a run can issue more than one artifact. Peer run IDs are
independent. Correlate across hosts only through authenticated evidence
already available to those hosts, not through an assumption that local run
IDs or timestamps match.

The resource owner must check the expected version and a writer fence in the
same transaction as the effect and receipt. After handing a resource to a
new writer, the old writer must no longer be able to commit. A receipt must
identify the exact inputs and outcome; a reused idempotency key with changed
inputs must not authorize another write. For an external issuer that cannot
share the transaction, persist the intent before calling it and reconcile
against its own idempotency key or durable record. If the external system
cannot confirm the outcome, retain the uncertainty rather than issuing again.

Store references to durable protected key handles, not HMAC secrets or
exported private keys. Do not retain reusable tokens, protected messages, or
session keys in the ledger. Keep receipts accessible while any associated
write is uncertain, even if a newer record replaced the affected resource.

## Evidence by operation

| Operation | Record separately | Reconciliation rule |
|---|---|---|
| DI on the Device | Reservation of the protected secret, staged credential, receipt of DI.Done, installation of that credential | A staged credential is not active. Resolve the reservation and read the actual active credential before another DI or TO2 run. A station voucher alone cannot justify installation. |
| DI on the station | Authorized proposal, voucher commit, DI.Done produced, DI.Done handed to transport | Handoff is not Device receipt. A durable voucher can exist while the Device still has no active credential. Preserve the voucher and mark Device activation unconfirmed until independently reconciled. |
| TO0 Rendezvous admission | Exact mutation, revision and expiry, durable receipt, AcceptOwner handoff | Reconcile the exact mutation even if the record expired or was replaced. Without a receipt, fence the prior writer before a fresh TO0 run. Do not replay OwnerSign or renew another record implicitly. |
| Voucher transfer | Expected source voucher and current Owner, exact successor voucher, commit receipt | An appended entry is not a storage commit. Check the latest durable voucher and its predecessor before publishing or extending another successor. Do not infer Device activation from voucher persistence. |
| TO2 on the Owner | Issued enrollment artifact, authenticated Done20, replacement voucher commit if applicable, enrollment commit, DoneAck20 produced and handed off | The paired role commits the replacement voucher before its separate enrollment commit. If the first effect committed and the second is uncertain, reconcile each receipt separately. Neither Owner commit nor handoff proves Device receipt. |
| TO2 on the Device | Validated enrollment artifact, staged replacement and protected secret if applicable, Done20 dispatch, authenticated DoneAck20, replacement activation, enrollment installation | Before authenticated DoneAck20 the replacement remains staged in the paired path. After DoneAck20, replacement activation precedes enrollment installation. Read both active stores after an interruption; either effect can have committed before the other returned. Do not overwrite or discard the old credential based on the Owner's result. |

`Done20` and `DoneAck20` above describe the current paired behavior,
including its provisional replacement activation point, not a resolution of
the specification's wire and transition discrepancies.

## Starting again

1. Stop the interrupted session and fence its durable writers.
2. Read the actual resource state and verify each receipt against its original intent.
3. If an effect remains uncertain, leave the resource unavailable for a new run until the host resolves it. Do not infer success or rollback from network status.
4. Choose the active credential or voucher from durable evidence. Retain the staged state needed for reconciliation and keep inactive secrets inaccessible to new runs.
5. If host policy authorizes another attempt, create new session objects, tokens, nonces, and session keys. Reauthenticate the peer. Do not resend a prior protected message or synthesize an acknowledgment.

The test adapter reopens separate file-backed journals after either role
ends. In DI it fences the old writers, quarantines the unused staged
credential and station voucher, and starts fresh role sessions only after
that explicit reconciliation. In TO2 it distinguishes a lost acknowledgment,
interruption between Owner commits, interruption after credential activation,
and completion. The tests read the active Device identity from the reopened
journal rather than from Owner commit state. These tests use in-process
locking and host-supplied test keys; they do not prove cross-process
fencing, physical power-loss safety, or production secret persistence.

The existing paired tests identify interruption points to reuse in that
harness. `LostDoneRetainsBothSidesForReconciliationWithoutRegenerating`
leaves the DI voucher persisted and the Device credential staged.
`ReplacementLostOrTamperedDoneAckLeavesDeviceInactive` keeps the
replacement inactive without an authenticated acknowledgment. Those tests
observe in-process state; neither reopens a durable repository. A restarted
host must make the same distinction using receipts and the actual active
credential rather than reconstructed session progress flags.
