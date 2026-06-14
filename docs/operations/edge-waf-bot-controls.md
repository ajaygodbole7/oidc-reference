# Edge WAF And Bot Controls

This note complements `production-hardening.md`.

## Scope

The reference includes basic local rate limiting. A production edge may also need
WAF and bot controls, especially for authentication entry points.

## Candidate Protected Paths

- `/auth/login`
- `/auth/callback/idp`
- `/auth/logout`
- `/auth/logout/continue`
- `/backchannel-logout`
- `/api/**` when authenticated request volume can amplify refresh traffic

## Controls To Consider

- trusted client IP extraction at the edge;
- per-IP and per-session rate limits;
- bot detection on login initiation;
- request size limits;
- method allowlists;
- path allowlists;
- anomaly alerts for callback error spikes;
- stricter controls for admin or high-value API paths.

## Notes

- Do not rate-limit solely on the load balancer's source IP.
- Do not block legitimate IdP callback traffic with browser-only bot checks.
- Protect `/backchannel-logout` as an IdP-to-Auth-Service route. If the IdP uses
  fixed egress ranges or private networking, enforce that at the edge.
- WAF rules are deployment-specific; keep application code independent of them.
