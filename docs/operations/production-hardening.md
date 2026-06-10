# Production Hardening Notes

This repository is a local reference, not a drop-in production deployment. The
architecture is intended to be copied and hardened for a specific platform.

## Required Before Non-Local Use

- Terminate TLS at the real browser ingress and preserve `X-Forwarded-*`
  headers only from trusted proxies.
- Use `__Host-sid; Secure; HttpOnly; SameSite=Lax; Path=/` on HTTPS.
- Replace all `CHANGE_BEFORE_DEPLOY` and zero-byte HMAC sentinels.
- Store Auth Service, Gateway, and IdP secrets in a secret manager.
- Set explicit non-local Spring profiles and verify the sentinel guard fails
  closed if any local-dev secret remains.
- Protect the Redis-compatible state store with network isolation, AUTH or
  equivalent credentials, TLS where supported, and single-tenant keyspace
  ownership.
- Add a dual-key grace-window rotation procedure for `CSRF_SIGNING_KEY`.
  The reference implementation is single-key hard cutover.
- Enable structured audit log retention for login, callback, refresh, logout,
  401, 403, and `refresh_token_rejected`.
- Add OpenTelemetry traces and metrics across APISIX, Auth Service, Resource
  Server, Keycloak/IdP calls, and Redis-compatible state-store calls.
- Configure provider-specific rate limits for `/auth/login`,
  `/auth/callback/idp`, `/auth/logout`, and `/internal/refresh`.
- Decide whether local logout or upstream RP-initiated logout is the correct
  user experience for the chosen IdP.
- Keep `SESSION_MAX_TTL` less than or equal to the IdP SSO max session
  lifespan.

## Scale-Out Decisions

### Distributed refresh lock (required before running more than one instance)

`InternalRefreshController` serializes concurrent refreshes for one session with
a **process-local** `ReentrantLock`. That is correct for a single Auth Service
instance only. With two or more instances, two can refresh the same session at
the same time: both present the same refresh token to the IdP, and because the
reference realm enables refresh-token **rotation + reuse detection**, the second
is rejected as `invalid_grant` and the session is invalidated. In other words,
naive horizontal scaling logs active users out. The lock is deliberately
in-process for the single-instance reference; making it cross-instance is a
scale-out step, not a bug.

Before scaling out, replace (or layer a distributed lock under) the in-process
lock, in the shared state store:

- **Acquire**: `SET refresh_lock:{sid} <token> NX PX <ttl>`, with `ttl` a few
  seconds above the IdP read timeout. The holder refreshes; a loser waits
  briefly, re-reads `sess:{sid}`, and returns the holder's already-rotated
  session without calling the IdP (so callers never see a spurious error).
- **Release**: compare-and-delete (`if GET == <token> then DEL`, atomically) so
  an instance never deletes a lock it no longer owns after a TTL expiry.
- **Fail closed**: never refresh if the lock cannot be acquired or the store
  errors.

(Alternatively, disable refresh-token rotation — weaker, since you lose reuse
detection.) This concern lives entirely in the Auth Service and the state store;
it is independent of which gateway fronts `/internal/refresh`.

### Token-endpoint load

- Tune the IdP **access-token lifespan** against refresh load. The reference
  realm uses a short (~120 s) access token, so every active session refreshes
  roughly every two minutes through the synchronous gateway → `/internal/refresh`
  → IdP chain. At scale that is significant IdP token-endpoint traffic and added
  request tail latency; lengthen it (5–15 min is typical) and treat the IdP
  token endpoint as a capacity dimension.

### Other

- Preserve trusted `X-Forwarded-Proto` semantics end to end when TLS is
  terminated before APISIX/Auth Service.
- Keep `sess:{sid}` as the session contract; do not let additional services
  write that keyspace unless the ownership model is redesigned.
- Run Resource Servers behind the gateway and keep direct browser CORS denied.
- Add a gateway allowlist entry deliberately for each new API surface.

## Security Enhancements To Consider

- `private_key_jwt` or mTLS client authentication to the Authorization Server.
- Sender-constrained tokens with DPoP or mTLS where the Resource Server is
  exposed outside a trusted service boundary.
- PAR/JAR for higher-assurance authorization request handling.
- A trusted provider-to-Auth-Service route for the implemented Back-Channel
  Logout endpoint.

These are not required for the local reference to be correct, but they are
normal review topics for regulated or high-risk deployments.
