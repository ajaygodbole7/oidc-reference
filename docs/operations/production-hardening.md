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

- Replace the local per-session `ReentrantLock` with a distributed lock before
  running more than one Auth Service instance.
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
- Back-channel logout if the IdP can reach the Auth Service through a trusted
  internal route.

These are not required for the local reference to be correct, but they are
normal review topics for regulated or high-risk deployments.
