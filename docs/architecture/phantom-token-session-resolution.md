# Phantom-token session resolution (gateway de-coupled from the store)

> How the API Gateway stays storage-agnostic: it resolves the session through
> the Auth Service (`/internal/resolve`) and holds no session-store handle.

## The change

The API Gateway used to read `sess:{sid}` **directly from Valkey** (a tolerant
reader over a shared JSON schema), slide the idle TTL with its own `EXPIRE`, and
call the Auth Service only to refresh a near-expiry token. The gateway now holds
**only the opaque session id**. It has no Redis client and no knowledge of the
session schema. On every `/api/**` request it calls a new Auth Service endpoint,
`POST /internal/resolve {sid}`, which looks up the session, slides the idle
window, refreshes the access token if it is near expiry, and returns the current
token. The gateway injects that token upstream.

**The Auth Service is now the single component that touches the session store.**

## This is the phantom-token pattern

What we built has a name. The edge holds an opaque by-reference token (the sid)
and **introspects it** via a token service (the Auth Service) to obtain the
by-value JWT it forwards upstream.

- This is Curity's **phantom-token pattern**; conceptually, RFC 7662 token
  introspection applied to the session reference.
- It is a conformant implementation of the IETF BFF BCP, which specifies the
  *behavior* (the BFF "removes the cookie, attaches the access token, and
  forwards it") but deliberately does **not** prescribe the internal mechanics.
- Both "gateway reads the store directly" and "gateway introspects via a
  service" satisfy the BCP. The introspection variant is the one the industry
  pattern catalog documents.
- The previous direct-read was a valid but non-canonical performance shortcut;
  this moves the reference *toward* the standard shape.

## Why — two wins

1. **Decoupling: data coupling → API coupling.** Sharing a Redis *schema* across
   two services is the worst kind of coupling — a storage change ripples across
   both, and the gateway needs Valkey host/port/credentials. A versioned internal
   API lets the Auth Service change its store (Redis → DynamoDB → encrypted-at-
   rest → add an entitlements service that shares Redis) with **zero gateway
   changes**.
2. **Security: smaller edge blast radius.** A compromised gateway used to have
   direct read access to the **entire** session keyspace — it could dump every
   user's tokens out of Valkey. It now has **no store access**; it can only
   resolve a sid presented to it, through an API the Auth Service can rate-limit,
   audit, and scope. Removing store credentials from the edge is a real
   attack-surface reduction.

## The cost — the Auth Service is now on the hot path

The Auth Service used to be off the hot path (the gateway read Valkey directly so
the Auth Service stayed login-frequency only). With introspection, **every
`/api/**` request** hits `/internal/resolve`. Its scaling profile changes: it now
also takes high-frequency, small-payload resolve traffic and must be HA and scale
with API throughput. There is one extra internal RPC of latency per call (cheap
on a local network, non-zero).

## The cache decision — we deliberately do NOT cache

The phantom-token guidance explicitly recommends **caching** the introspection
result ("a by-value token can be cached until it expires"). We deliberately do
**not** cache at the gateway, because a gateway cache keyed by the token lifetime
would break **instant revocation** — the property where deleting `sess:{sid}`
server-side makes the very next request 401 (covered by e2e story 12). The
tradeoff, stated plainly:

| | No gateway cache (chosen) | Short-TTL cache |
|---|---|---|
| Revocation | instant (next request 401) | stale for the cache TTL |
| Auth Service load | one RPC per `/api` request | amortized |

Recommendation if load ever forces it: add a *short* TTL cache (a few seconds)
and document the revocation window as a deliberate dial. Not now.

## JWKS cost accounting (a common misconception)

- The per-request **JWT signature validation (JWKS) lives at the Resource Server
  in both designs** — it never lived at the gateway, and the redesign does not
  move it. The RS verifies the signature against a *cached* JWKS (refresh-ahead,
  local RSA verify).
- The Auth Service uses JWKS only at login and refresh (id-token validation),
  not per `/api` call. So the redesign **adds no JWKS cost**.
- What relocates is the **session lookup**: the Valkey `GET` moves from the
  gateway into the Auth Service, behind the resolve RPC.
- The resolve endpoint does **not** re-validate the access token's signature;
  that would be redundant with the RS, and the phantom-token pattern leaves
  authoritative validation at the API/RS.

## Distributed-lock analysis

The per-session refresh lock stays in the Auth Service, around the refresh
portion of resolve.

- The phantom-token move adds **no new concurrency hazard**: the lock is
  engaged only near expiry (a fresh-token resolve is lock-free — read, slide,
  return), exactly as before.
- The reference stays **single-instance**, so the in-process `ReentrantLock` is
  correct and sufficient. We do **not** add a distributed lock now: unexercised,
  with no multi-instance deployment to test it against, it is unvalidated
  complexity.
- The hot-path move makes horizontal scaling of the Auth Service more likely in
  production, so the distributed lock (`SET NX PX refresh_lock:{sid}` +
  compare-and-delete release) becomes a **more pressing** production requirement
  than before. The recipe is in `docs/operations/production-hardening.md`.
- Single-instance serialization (two concurrent resolves on one sid → exactly
  one upstream refresh) is proven by
  `InternalResolveControllerTest.concurrentResolveCallsForSameSidSerializeOnLock`.

## `/auth/me` vs `/internal/resolve` — shared core, two projections

Both look up `sess:{sid}` and enforce the absolute ceiling, so they reuse one
lookup core rather than duplicating it. But they are two distinct projections and
stay separate endpoints:

| | `/auth/me` | `/internal/resolve` |
|---|---|---|
| Output | claims only — **never a token** (the headline invariant) | the access token |
| Refresh | never (pure read) | refreshes near expiry |
| Idle slide | never (non-extending liveness probe — the C9.3 property) | slides (`/api` activity) |
| Trust | browser-facing, session-cookie-auth | internal, Client-Credentials-auth |

Merging them would be one config slip from the access token riding the
browser-facing `/auth/me` path — the exact leak the BFF exists to prevent.

## Sources

- [draft-ietf-oauth-browser-based-apps (IETF, OAuth 2.0 for Browser-Based Apps)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [Phantom Token pattern — Curity](https://curity.io/resources/learn/phantom-token-pattern/)
- [API Token Handler pattern — bff-patterns.com](https://bff-patterns.com/patterns/api-token-handler)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/rfc9700/)
