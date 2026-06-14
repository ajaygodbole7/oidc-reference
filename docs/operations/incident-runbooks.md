# Incident Runbook Starters

This note complements `production-hardening.md`.

These are starting points. Each deployment should adapt them to its IdP, gateway,
state store, secret manager, and incident process.

## CSRF Signing Key Compromise

- Rotate `CSRF_SIGNING_KEY`.
- If dual-key rotation is implemented, add the new key as primary and retain the
  old key only for the shortest safe grace window.
- If dual-key rotation is not implemented, expect active sessions and in-flight
  login transactions to fail.
- Review logs for CSRF validation failures and suspicious state-changing
  requests.

## Auth Service Client Secret Compromise

- Rotate the Auth Service OIDC client secret at the IdP.
- Redeploy Auth Service with the new secret.
- Revoke suspicious sessions if token misuse is suspected.
- Review callback, token exchange, and refresh audit events.

## Gateway Client Secret Compromise

- Rotate the gateway client-credentials secret at the IdP.
- Redeploy gateway configuration.
- Review `/internal/resolve` caller failures and unusual gateway token issuance.
- Confirm Auth Service still rejects wrong `azp` / `client_id` and wrong
  audience.

## Refresh Token Reuse Spike

- Check IdP token endpoint health and configuration.
- Check whether multiple Auth Service instances are running without distributed
  refresh locking.
- Check for replay or store rollback.
- Invalidate affected sessions when reuse is confirmed.
- Preserve audit logs and IdP token endpoint logs.

## IdP Outage

- Existing sessions with fresh access tokens may continue until refresh is
  required.
- New logins and refreshes fail while the IdP is unavailable.
- Confirm `/internal/resolve` returns transient failures without deleting valid
  sessions on IdP transport errors.
- Communicate expected user impact based on access-token lifetime.

## State Store Outage

- Login and authenticated API traffic fail.
- Do not fall back to accepting unsigned or client-held state.
- Restore HA/failover first.
- Treat lost session data as logout unless the deployment has explicitly tested
  safe persistence and TTL restoration.
