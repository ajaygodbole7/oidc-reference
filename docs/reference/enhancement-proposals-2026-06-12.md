# Enhancement proposals — 2026-06-12

**Status:** proposed, awaiting review.
**Purpose:** four candidate auth-substance enhancements, each evaluated against a
single question — **does it genuinely belong in the *core reference*?** — vs. the
downstream eCommerce clone, or a documented non-goal.

> **Reviewer:** please challenge the *verdicts* (the "belongs in" column), not just
> the implementations. The whole point of this doc is to agree where the line sits
> between "auth substance the reference should teach" and "application/topology that
> dilutes it." If you disagree with a verdict, say so and why.

---

## The decision lens — what the core reference *is*

The reference exists to teach the **BFF / OIDC identity pattern** correctly and
auditably: tokens off the browser, the Auth Service (OIDC client), the gateway
(phantom-token `/internal/resolve`), the opaque session cookie, signed CSRF, PKCE/
state/nonce, sid rotation on refresh, the distributed refresh lock, step-up, and
back-channel logout. Its value is that a reader sees the *auth substance*
end-to-end without wading through unrelated code.

Three lines follow from that:

1. **Swappable infra is not the reference.** APISIX/Lua is replaceable by Kong, AWS
   API Gateway, Envoy. We do not harden or expand it; we keep its contract clean.
2. **Domain logic is not the reference.** Orders, payments, carts, inventory belong
   in the **eCommerce clone** (a downstream consumer demo built on a tagged release).
   The reference shows the *seams* an app plugs into, not the app.
3. **Topology that teaches no new auth is not the reference.** Running a second
   process to "look like microservices" adds ops surface, not auth substance, if the
   auth control it demonstrates is already provable in one process.

An enhancement belongs in the **core reference** only if it is auth substance, is
copyable independent of the swappable gateway, and carries no domain logic.

---

## Current state (grounded)

| Area | Today | File |
|---|---|---|
| Step-up | Recency only: `/auth/step-up` sends `prompt=login`; callback checks `auth_time` freshness; RS enforces `auth_time` on `POST /api/admin` | `AuthController.java`, `ApiController.java:124-127` |
| `acr` | Captured + surfaced on `/auth/me`, **never requested as `acr_values`, never enforced** (🟡 in the matrix) | `JwtOidcIdTokenValidator.java:156`; `OIDC-compliance.md:45` |
| Authorize request | Front-channel **GET** with every param (`scope/state/redirect_uri/code_challenge/...`) in the browser URL | `AuthController.java:147-153` |
| Least-privilege | Per-route via **scopes/role** under a **single audience** (`SCOPE_api.read`, `SCOPE_service.jobs`, `ROLE_admin`) | `SecurityConfig.java:70-75,91` |
| Token exchange | **None** (the one `token_exchange` string is an audit label for the authz-code→token step) | — |
| `/internal/resolve` | Returns the one session access token; **no per-route audience awareness** | `InternalResolveController.java` |
| Gateway | `/api/**` → a **single** RS upstream | `api-gateway/apisix.yaml*` |

---

## E1 — ACR-based step-up (assurance, not just recency)

**What.** Today step-up proves *recency* (`prompt=login` + `auth_time`). It does not
prove *strength* (MFA). Add: request `acr_values=<configured LoA>` on the step-up
authorize, and have the RS verify the token's `acr` meets the required level —
mirroring the existing `auth_time` gate. Flips `acr` 🟡→✅.

**Auth substance.** Authentication-context-class enforcement (OIDC Core §2 / §3.1.2.1,
RFC 9470). The "MFA before a sensitive action" control, distinct from "logged in
recently."

**Scope / e2e honesty.** The **request → `acr` claim → RS-enforce** chain is fully
deterministic to prove via a realm ACR→LoA mapping (the step-up login yields the
required `acr` value). *Real* conditional-OTP/MFA enrollment is documented as the
production step, not forced into the e2e — the same way step-up *freshness* is proven
without real re-auth friction.

**Size.** Small (~0.5–0.7× the distributed lock). RS check mirrors `auth_time`;
auth-service adds one param; realm gains an ACR→LoA mapping; one new e2e story.

**Belongs in: CORE REFERENCE.** Pure auth substance, completes a feature already
shipped, no domain, gateway-agnostic.

---

## E2 — PAR: Pushed Authorization Requests (RFC 9126)

**What.** Instead of a front-channel GET carrying every authorize param, POST them to
the IdP's PAR endpoint over the back channel, receive a `request_uri`, and redirect
the browser with only `client_id` + `request_uri`. Nothing tamperable or loggable in
the URL; the authorize request is integrity-protected.

**Auth substance.** Front-channel hardening mandated/recommended by **OAuth 2.1** and
**FAPI 2.0**. Protects `state`, `redirect_uri`, `code_challenge`, `scope` (and any
`acr_values` from E1) from browser-history / Referer / proxy-log exposure and
tampering.

**Scope / e2e honesty.** Most self-contained of the four: a contained change to
`beginLogin`, enable PAR on the realm client, one e2e story asserting the PAR endpoint
is hit and the redirect carries `request_uri` while login still completes end-to-end.
Fully deterministic — no MFA, no extra process.

**Size.** Small (~0.5× the distributed lock).

**Belongs in: CORE REFERENCE.** Auth substance, gateway-agnostic, no domain. Arguably
the highest "modern-OAuth credibility per line" item.

---

## E3 — Audience isolation + RFC 8693 token exchange (the *core-reference* half of "multiple audiences")

**What.** Add a second **audience-gated** route group (e.g. `/api/payments`) on the
**same** RS requiring `aud=payments-api`, distinct from the session token's `aud=api`.
The BFF mints a **down-scoped, per-service** token via **RFC 8693 token exchange**
(cached per `sid`+audience) so the broad session token is *rejected* at the payments
route and only the narrow exchanged token reaches it.

**Auth substance.** **Cross-service token isolation** — the least-privilege control
that scopes alone do *not* give: a scoped token for service A (`aud=api`) could still
be replayed at service B if B also trusts `aud=api`; distinct audiences + per-service
down-scoping (RFC 9700 §2.3, RFC 8693) prevent that. This is the real mechanism a
payments service needs.

**Scope / design.** `/internal/resolve` gains a target-audience hint (the gateway
already names the route); the auth-service performs + caches the exchange; the RS
configures a second audience-gated matcher. **No domain code, one RS process.** The
gateway change is a per-route hint only — it does not move auth substance into the
swappable layer.

**Note on the one-process simplification.** Two audiences on one RS is a *reference
simplification* — in production these are two services. The auth substance (audience
restriction + exchange) is identical either way; the second process adds only
topology. **Reviewer: is one-process acceptable, or does it read as artificial?**

**Size.** Largest core-reference item (~1.5× the distributed lock).

**Belongs in: CORE REFERENCE** (the audience-isolation + exchange substance).
*Highest real-world value of the four for the eCommerce narrative.*

---

## E4 — Multi-process gateway fan-out (second RS instance, two upstreams)

**What.** Run a second RS *instance* and have the gateway fan `/api/orders/**` and
`/api/payments/**` out to two real upstreams.

**Auth substance.** **None beyond E3.** The audience restriction + token exchange is
identical; the only addition is *topology* — fan-out across real processes.

**Size.** Compose 2nd instance + gateway 2nd upstream. Ops surface, not auth.

**Belongs in: eCommerce CLONE (not the core reference).** This is exactly the
dilution line: adding a service/instance teaches no new auth once E3 exists, and
fan-out across real services is the clone's job. Demonstrate it there, on top of a
tagged reference release.

---

## Summary

| # | Enhancement | Auth substance | Size (vs. dist. lock) | **Belongs in** |
|---|---|---|---|---|
| E1 | ACR-based step-up | ACR/LoA enforcement (RFC 9470) | ~0.6× | **Core reference** |
| E2 | PAR (RFC 9126) | Front-channel hardening (OAuth 2.1/FAPI) | ~0.5× | **Core reference** |
| E3 | Audience isolation + RFC 8693 | Cross-service token isolation | ~1.5× | **Core reference** |
| E4 | Multi-process fan-out | None beyond E3 (topology) | n/a | **eCommerce clone** |

**Composition note.** E1 + E3 compose into one coherent demo: a single realistic
`/api/payments` endpoint requiring **fresh + strong `acr` (E1) AND a down-scoped
audience (E3)** — three controls (recency, assurance, audience) on one sensitive
route, no domain. That is the strongest single eCommerce-backend story.

---

## Non-goals (documented, not implemented)

- **DPoP (RFC 9449) / mTLS-bound tokens (RFC 8705).** Sender-constrained tokens guard
  bearer-token *replay after theft* — a threat largely contained in a BFF because
  tokens never reach the browser. Proposed as a **documented non-goal with rationale**
  (like the existing `typ=at+JWT` note in `SecurityConfig.java`), not an
  implementation. *Reviewer: agree this stays a non-goal?*
- **RFC 7009 token revocation on logout.** RP-initiated `end_session` + local session
  delete + back-channel logout already terminate the IdP session; an explicit revoke
  call is largely redundant. Stays out.

---

## Questions for the reviewer

1. **Verdicts:** Do you agree E1/E2/E3 are core-reference and E4 is clone-only? Where
   would you move the line?
2. **E3 realism:** Is two audiences on one RS an acceptable reference simplification,
   or does it need the second process to be honest (pushing it toward the clone)?
3. **Priority/sequencing:** Smallest-first (E2 → E1 → E3) for momentum, or go straight
   for the highest-value E3 (or the E1+E3 composition)?
4. **Non-goals:** Agree DPoP/mTLS and RFC 7009 stay documented non-goals?
5. **Anything missing** from the auth-substance gap list that a staff/security
   engineer would expect in a world-class BFF/OIDC reference?
