# Security Audit And SIEM Export

This note complements `production-hardening.md`.

## Required Events

Export structured security events for at least:

- login started;
- login rejected;
- callback succeeded;
- callback failed;
- token refresh succeeded;
- refresh token rejected;
- logout succeeded;
- back-channel logout succeeded;
- back-channel logout rejected;
- 401 authentication failures;
- 403 authorization failures;
- step-up authentication required.

## Correlation

Each event should carry:

- request id or trace id;
- timestamp;
- service name;
- route;
- outcome;
- reason code;
- hashed subject when available;
- hashed local sid when available;
- client id / authorized party when relevant;
- remote address after trusted-proxy normalization.

Do not log access tokens, refresh tokens, ID tokens, authorization codes, raw
session ids, client secrets, CSRF tokens, or request bodies.

## Alert Examples

Create SIEM alerts for:

- spike in `refresh_token_rejected`;
- repeated callback `invalid_state`;
- repeated callback `iss_mismatch`;
- repeated back-channel logout rejection;
- gateway client-credentials failures on `/internal/resolve`;
- login rejection rate above baseline;
- 403 rate above baseline for sensitive routes;
- IdP token endpoint failures above baseline.

## Retention

Choose retention based on regulatory and incident-response needs. The reference
does not prescribe a retention period.
