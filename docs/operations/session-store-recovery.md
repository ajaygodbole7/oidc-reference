# Session Store Recovery

This note complements `production-hardening.md`.

## Scope

The local reference stores OAuth transactions and authenticated sessions in a
Redis-compatible state store. In production, that store is a dependency for:

- login transactions: `tx:{state}`;
- authenticated sessions: `sess:{sid}`;
- session revocation indexes;
- refresh locks when distributed locking is enabled;
- logout continuation and replay-prevention keys.

## Decisions Required Before Production

- Define RTO: maximum acceptable time to restore the state store.
- Define RPO: maximum acceptable session data loss.
- Decide whether losing the store is an acceptable fleet-wide logout.
- Decide whether session persistence is required across store restarts.
- Decide whether backups include session data, or whether sessions are treated as
  disposable security state.

## Practical Guidance

- For most deployments, treat `tx:*` and `sess:*` as disposable security state:
  restoring stale sessions from backup can be worse than forcing users to log in.
- Prefer HA/failover for continuity over backup restore for active sessions.
- If persistence is enabled, validate that TTLs survive restart and failover.
- Test store failover during:
  - login before callback;
  - normal `/internal/resolve`;
  - token refresh;
  - logout;
  - back-channel logout.

## Failure Behavior To Document

- State store unavailable: login and authenticated API traffic fail.
- State store data lost: users must log in again.
- Refresh interrupted during failover: session must fail closed, not resurrect
  old refresh-token state.
