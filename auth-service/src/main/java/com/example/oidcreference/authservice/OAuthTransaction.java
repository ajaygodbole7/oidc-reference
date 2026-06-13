package com.example.oidcreference.authservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import org.jspecify.annotations.Nullable;

// In-flight OAuth transaction, keyed by state in `tx:{state}`. The
// txCookieHash field is the HMAC of the oauth_tx browser-binding
// cookie value issued at /auth/login; the callback re-hashes the
// cookie it receives and rejects on mismatch. See OAuthTxBinding
// for the rationale.
record OAuthTransaction(
    @JsonProperty("verifier") String verifier,
    @JsonProperty("nonce") String nonce,
    @JsonProperty("saved_request") String savedRequest,
    @JsonProperty("created_at") Instant createdAt,
    @JsonProperty("tx_cookie_hash") String txCookieHash,
    // Step-up marker. Persisted so the callback knows to enforce auth_time
    // freshness when the IdP redirects back. Tolerant-read: existing tx:{state}
    // records written before this field decode to null (treated as no step-up).
    @JsonProperty("step_up") @Nullable Boolean stepUp) {

  // Ordinary (non-step-up) login. Unlike the removed 4-arg constructor — which
  // produced an INVALID null txCookieHash the callback fail-closes on — a false
  // stepUp is the correct, valid default: a login with no freshness requirement.
  OAuthTransaction(
      String verifier,
      String nonce,
      String savedRequest,
      Instant createdAt,
      String txCookieHash) {
    this(verifier, nonce, savedRequest, createdAt, txCookieHash, false);
  }

  // True when this flow is a step-up: the callback must then enforce that the
  // returned id_token's auth_time is at or after createdAt — proof that a
  // genuine re-authentication happened during this transaction rather than the
  // IdP silently reusing an older SSO session.
  boolean isStepUp() {
    return Boolean.TRUE.equals(stepUp);
  }
}
