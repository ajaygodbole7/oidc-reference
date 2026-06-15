# Production Hardening Notes

What this is: the gap list between the local reference and a real deployment.
This repository is a local reference, not a drop-in production deployment; the
architecture is meant to be copied and hardened for a specific platform.

## Required Before Non-Local Use

- Terminate TLS at the real browser ingress and preserve `X-Forwarded-*`
  headers only from trusted proxies.
- Use `__Host-sid; Secure; HttpOnly; SameSite=Lax; Path=/` on HTTPS.
- Replace all `CHANGE_BEFORE_DEPLOY` and zero-byte keyed-hash message authentication code (HMAC) sentinels.
- Store Auth Service, Gateway, and Identity Provider (IdP) secrets in a secret manager.
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
  `/auth/callback/idp`, `/auth/logout`, and `/internal/resolve`.
- Decide whether local logout or upstream Relying Party (RP)-initiated logout is the correct
  user experience for the chosen IdP.
- Keep `SESSION_MAX_TTL` less than or equal to the IdP single sign-on (SSO) max session
  lifespan.

## Scale-Out Decisions

### Distributed refresh lock (required before running more than one instance)

`InProcessRefreshLock` — the default `RefreshLock` behind `InternalResolveController`
— serializes concurrent refreshes for one session with a process-local
`ReentrantLock`. That is correct for a single Auth Service instance only.

With two or more instances, two can refresh the same session at the same time.
Both present the same refresh token to the IdP. The reference realm enables
refresh-token rotation and reuse detection, so the second is rejected as
`invalid_grant` and the session is invalidated. Naive horizontal scaling logs
active users out. Making the lock cross-instance is a scale-out step, not a bug.

**A cross-instance implementation ships and is opt-in.** Set
`app.refresh-lock=distributed` to select `DistributedRefreshKeyLock` instead of
the in-process default; the default stays in-process for the single-instance
reference. It is built on the vendor-neutral `StateStore` (no Redis/Valkey client
in the lock itself), so it follows whatever store backs `StateStore`. Knobs:
`app.refresh-lock-ttl` (lease time-to-live (TTL), default `10s` — above the IdP connect+read
budget so the lease covers a full refresh), `app.refresh-lock-max-wait`
(default `12s`, above the TTL so a crashed holder's lease always lapses within a
contender's wait), `app.refresh-lock-poll` (default `50ms`). These relationships
(max-wait > ttl, poll < max-wait, every duration positive) are validated by
`RefreshLockProperties` at boot, so a violating override fails closed loudly
rather than booting a misconfigured lock.

The algorithm (`DistributedRefreshKeyLock`, proven by `DistributedRefreshKeyLockTest`
and the `compareAndDelete` parity cases in `RedisStateStoreParityTest`):

- **Acquire**: `SET refresh_lock:{sid} <token> NX PX <ttl>` (`StateStore.putIfAbsent`).
- **Contend**: a loser polls until it can acquire, then runs the same action — which
  re-reads `sess:{sid}`, finds the holder's already-rotated token (following the
  `rotated:{sid}` breadcrumb on a sid rotation), and returns it without calling the
  IdP. The two callers collapse to one upstream refresh.
- **Release**: compare-and-delete (`StateStore.compareAndDelete`: `if GET == <token>
  then DEL`) so an instance never deletes a lease another acquired after ours
  expired by TTL.
- **Fail closed**: if the lease cannot be acquired within `max-wait` (or the store
  errors), throw rather than refresh unguarded. The controller maps the throw to a
  deliberate, audited (`refresh_failed` / `refresh_lock_unavailable`),
  `Cache-Control: no-store` `503` response (not an unmapped 500), so the gateway
  keeps the session cookie and retries.

**Proof (two real replicas).** `scripts/e2e-distributed-lock.sh` with
`compose.distributed-lock.yml` runs **two** `auth-service` replicas on one shared
Valkey + Keycloak and fires concurrent `/internal/resolve` for the same session at
each replica. With `app.refresh-lock=distributed` the two collapse to one upstream
refresh — both return `200`, no `invalid_grant`. Flip both to `in-process` and the
uncoordinated replicas trip Keycloak's reuse detection: a `409 invalid_grant` on a
real overlap = the cross-instance logout the lock exists to prevent. It is a manual
harness (seeds the session from ROPC-issued **real** tokens and toggles Keycloak
direct-grant at runtime — both ephemeral), not part of the default gate; run it on
the two-replica stack to reproduce the contrast.

(Alternatively, disable refresh-token rotation. This is weaker, since you lose
reuse detection.) This concern lives entirely in the Auth Service and the state
store. It is independent of which gateway fronts `/internal/resolve`.

### Token-endpoint load

- Tune the IdP access-token lifespan against refresh load. The reference
  realm uses a short (~120 s) access token, so every active session refreshes
  roughly every two minutes through the synchronous gateway → `/internal/resolve`
  → IdP chain. At scale that is significant IdP token-endpoint traffic and added
  request tail latency. Lengthen it (5–15 min is typical) and treat the IdP
  token endpoint as a capacity dimension.

### Other

- Preserve trusted `X-Forwarded-Proto` semantics end to end when TLS is
  terminated before APISIX/Auth Service.
- Keep `sess:{sid}` as the session contract; do not let additional services
  write that keyspace unless the ownership model is redesigned.
- Run Resource Servers behind the gateway and keep direct browser Cross-Origin Resource Sharing (CORS) denied.
- Add a gateway allowlist entry deliberately for each new API surface.

## Security Enhancements To Consider

- `private_key_jwt` or mutual TLS (mTLS) client authentication to the Authorization Server (AS).
- Sender-constrained tokens with Demonstrating Proof-of-Possession (DPoP) or mTLS where the Resource Server is
  exposed outside a trusted service boundary.
- Pushed Authorization Requests (PAR)/JWT-Secured Authorization Request (JAR) for higher-assurance authorization request handling.
- A trusted provider-to-Auth-Service route for the implemented Back-Channel
  Logout endpoint.

These are not required for the local reference to be correct, but they are
normal review topics for regulated or high-risk deployments.

## Operational Fundamentals Not Built Here

The items above cover the secret cutover and the refresh-lock scale-out step in
detail. The operational concerns below are equally load-bearing for a real
rollout and are deliberately absent from this reference. They are documented so
this checklist reads as a starting subset, not a complete path to production.

### Session-store HA and the single-Valkey SPOF

Compose runs a single `valkey` service. There is no replica, no Sentinel, no
Cluster, and the Auth Service has no Lettuce failover configuration. Valkey is a
hard single point of failure for the entire authenticated surface: every
`/internal/resolve` reads `sess:{sid}`, and the login leg's `tx:{state}` lives
there too. If it is unreachable, both new logins and every authenticated `/api`
request fail.

Sessions are externalized into Valkey, which is the reassuring half of the same
fact: APISIX and the Auth Service hold no session state, so they are horizontally
stateless and need no sticky sessions or session affinity at the load balancer.
The state lives in one place by design — that place just has to be made highly
available.

The phantom-token split adds a second hot-path dependency: the **Auth Service is
now itself a hard SPOF for all `/api` traffic**, because every `/api/**` request
calls `/internal/resolve`. Pre-split, a gateway holding a cached session and a
still-valid token could serve `/api` even while the Auth Service was down;
post-split it cannot. Auth Service HA is therefore now as load-bearing as Valkey
HA (previously it mattered only at login frequency) — run it replicated, and front
`/internal/resolve` with HTTP connection pooling (the gateway currently opens a
fresh connection per request) and a circuit breaker so a slow Auth Service fails
fast instead of stalling the whole `/api` surface.

The obvious lever to cut that per-request call — a short-TTL access-token cache at
the gateway, keyed by sid — is **not free**, and is intentionally omitted from the
reference. It trades away instant revocation: today a `DEL sess:{sid}` (logout,
back-channel logout, refresh-reuse invalidation) is observed on the very next
`/api/**` request because the gateway always re-resolves; with a cache, a
logged-out or revoked session keeps serving `/api` until its cache entry expires. A
small TTL (1–5 s) bounds the staleness and is acceptable in some production systems
as a throughput-vs-revocation-latency trade, but the reference keeps the no-cache
phantom-token path because instant revocation is the property it exists to
demonstrate and is easier to reason about. Don't reach for this without a measured
`/internal/resolve` latency cost — and if you add it, document the revocation
window.

Before a real deployment:

- Run a replicated single-primary topology (Sentinel, or a managed
  Redis-compatible service with automatic primary failover). Do not use a
  sharded Redis Cluster: the atomic sid-rotation script (`rotateIfPresent`)
  moves `sess:{old}` to `sess:{new}` and writes the `rotated:{old}` breadcrumb
  in one Lua call across three keys, and a sharded cluster cannot keep three
  keys built from independent random sids in one hash slot, so the call returns
  CROSSSLOT. A single primary keeps the whole keyspace in one slot space, so the
  multi-key scripts hold; hash tags cannot fix this because the old and new sids
  share no common entity to tag. The per-user index sets (`idp_sid:{idp_sid}`,
  `sub_sessions:{sub}`) hold only one user's live session ids, so the
  logout-time `SMEMBERS` enumeration stays cheap.
- Decide the failover behavior for in-flight refreshes explicitly. A failover
  mid-refresh can lose the rotated token before it is persisted; pair this with
  the graceful-shutdown and distributed-lock decisions below so an interrupted
  refresh fails closed rather than orphaning the session.

### Observability and cross-tier correlation IDs

Neither service pulls Micrometer or OpenTelemetry; there are no tracing or
metrics-registry dependencies, and no `traceId` / `X-Request-Id` is propagated
across the gateway → Auth Service → Resource Server chain. The Resource Server
exposes `metrics`/`prometheus` actuator endpoints, but with no registry
dependency behind them they carry nothing. The audit log is structured and
useful within the Auth Service, but it carries no correlation id, so a single
browser request cannot be stitched across tiers from the logs alone. When the
multi-instance refresh contention described above plays out in production, there
is no metric or trace to observe it.

Before a real deployment:

- Establish a correlation-ID contract: the gateway mints an `X-Request-Id` (or
  W3C `traceparent`) if absent, forwards it on every hop, and both services log
  it on every line including the audit events. It is also a precondition for the
  distributed tracing this document already calls for.
- Add RED metrics (rate, errors, duration) per route and an explicit SLO for the
  IdP token-endpoint dependency, since refresh latency and availability are
  bounded by the IdP, not by this stack.

### Graceful shutdown

Neither `auth-service` nor `backend-resource-server` sets
`server.shutdown: graceful` or `spring.lifecycle.timeout-per-shutdown-phase` in
its `application.yml`. On `SIGTERM` the JVM stops immediately and drops in-flight
requests. The dangerous case is a refresh interrupted after Keycloak has rotated
the token but before `putIfPresent` persists the new session: the old refresh
token is now spent, the new one was never stored, and the next refresh earns an
`invalid_grant` and logs the user out. This compounds the in-process-lock
limitation during any rolling deploy, where instances are terminated by design.

Graceful shutdown is a near-free config win this reference could even adopt
(`server.shutdown: graceful` plus a bounded
`spring.lifecycle.timeout-per-shutdown-phase`), and it must be paired with a
container/orchestrator `terminationGracePeriod` long enough to drain a refresh.

### Dependency-checked readiness probes

Both services set `management.endpoint.health.probes.enabled: true`, which
auto-creates `/actuator/health/readiness`. With default content that group
reflects only Spring application lifecycle — it does **not** check Valkey or IdP
reachability. A replica whose Valkey connection is dead still reports `READY` and
takes traffic, then fails every request. The Compose healthcheck compounds the
gap: it probes the aggregate `/actuator/health`, not `/readiness`.

Before a real deployment, add a custom readiness `HealthIndicator` (or readiness
health group) that checks the session store and the IdP discovery endpoint, and
point the orchestrator's readiness probe at `/actuator/health/readiness` so a
broken-dependency replica is pulled from rotation.

### Valkey eviction policy and durability

The Valkey container runs with no `maxmemory` and no `maxmemory-policy`, so it
uses the default `noeviction`. Under memory pressure that **rejects writes** —
including refresh-token writes — which surfaces to the user as a forced logout. A
naive switch to `allkeys-lru` is worse: it would evict *live* sessions to make
room. Persistence is also explicitly off (`--save "" --appendonly no`), so a
Valkey restart is a fleet-wide logout. The transport-security guidance above
covers AUTH/TLS but not durability or eviction.

Before a real deployment:

- Set `maxmemory` with headroom and a `volatile-ttl` (or `volatile-lru`) policy.
  Every key this stack writes carries a TTL, so a volatile policy evicts the
  nearest-to-expiry session under pressure rather than rejecting writes or
  dropping an arbitrary live one.
- Decide the durability posture deliberately. A Valkey restart with persistence
  off logs every active user out; persistence or a replicated failover topology
  is the remedy.

### Supply-chain pinning

Container images use mutable tags with no `@sha256` digest pinning
(`eclipse-temurin:25-jre-jammy`, `apache/apisix:3.16.0-debian`,
`valkey/valkey:9.1-alpine`, `quay.io/keycloak/keycloak:26.6.1`). The build stage
downloads the Maven distribution over the network with no checksum or signature
verification. There is no image signing. (Credit where due: the images are
pinned to specific minor tags rather than `:latest`, and the runtime images are
non-root JRE-only layers. The Maven build also already emits a CycloneDX SBOM at
`verify`, so the *application* bill of materials exists — the gap is at the
container and download layer.)

Before a real deployment:

- Pin base images by digest (`image@sha256:…`) so a re-pushed tag cannot change
  the bits.
- Verify the Maven download against a published checksum/signature, or vendor the
  build toolchain into a trusted base image.
- Sign and verify the produced images (e.g. Cosign) and publish a
  container-level SBOM alongside the existing application SBOM.

### Rate-limit coverage and IdP refresh amplification

`limit-req` is applied only to `/auth/login` and `/auth/callback/idp`. The
`/api/**` routes have no rate limit. Post-phantom-token, every `/api/**` request
makes a synchronous gateway → `/internal/resolve` call, and when the access token
is near expiry that call drives a refresh through
gateway → `/internal/resolve` → Keycloak. An authenticated client looping a
single `/api` endpoint inside that near-expiry window therefore amplifies load
directly onto the IdP token endpoint — the rate-limited login edge does not
constrain it at all.

Before a real deployment:

- Add a limit on the refresh-driving path (the `/api/**` routes, or a limit keyed
  on the session) so a near-expiry loop cannot fan out into IdP token-endpoint
  traffic. This complements lengthening the access-token lifespan (see
  Token-endpoint load above), which shrinks the window but does not bound it.
- Note the keying caveat already flagged in the route template: `remote_addr`
  collapses to the load balancer's address behind a real LB, so per-client
  limits must key on a trusted forwarded-IP header with the proxy's trusted-IP
  list pinned.

### Zero-downtime deployment is not possible today

State this plainly because it is the compound conclusion of four separate gaps
and is easy to miss when each is read in isolation: **do not run this stack with
more than one replica, and do not attempt a rolling or blue-green deploy, until
the in-process refresh lock, a shared/HA session store, dual-key signing
rotation, and graceful shutdown are all in place.** The first `kubectl rollout`
against this architecture as shipped logs every active user out.

The four preconditions:

- the refresh lock is in-process (`InProcessRefreshLock`), so two instances
  refreshing one session race to `invalid_grant` (see the distributed-lock
  section above);
- the session store is a single Valkey with no HA (see the SPOF section above);
- the signing key is a single hard-cutover key — and it is shared by **both** the
  double-submit Cross-Site Request Forgery (CSRF) cookie and the `oauth_tx` login-state value, so rotating it
  does not merely break CSRF validation, it also breaks every login already in
  flight at rotation time (blast radius wider than a CSRF-only framing implies);
- there is no graceful shutdown, so the terminations a rolling deploy performs by
  design interrupt in-flight refreshes mid-rotation (see the graceful-shutdown
  section above).
