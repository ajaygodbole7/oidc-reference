package com.example.oidcreference.authservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

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
    @JsonProperty("tx_cookie_hash") String txCookieHash) {
  // The 4-arg compat constructor was removed: it produced records with
  // txCookieHash=null, which the callback's fail-closed binding check
  // unconditionally rejects (400 missing_tx_binding). Keeping it would
  // have meant ship-able production code that only works in tests.
}
