package com.example.oidcreference.authservice;

import java.util.Map;

interface IdTokenValidator {
  /**
   * Validates an OIDC ID token. Implementations must enforce all the checks
   * required by OIDC Core §3.1.3.7 including, when the ID token carries an
   * {@code at_hash} claim, the access-token hash check at step 7 — which is
   * why {@code accessToken} is part of the signature.
   *
   * @param accessToken the access token returned alongside this ID token in
   *     the same token-endpoint response; used only when the ID token
   *     carries an {@code at_hash} claim, but supplied in every call so the
   *     check cannot be silently skipped.
   */
  Map<String, Object> validate(String idToken, String accessToken, OAuthTransaction transaction);

  /**
   * Re-validates an ID token returned by a refresh-token grant and returns its
   * user claims. Enforces the same checks as {@link #validate} (signature,
   * issuer, audience, expiry, and {@code at_hash} when present) <em>minus</em>
   * the nonce binding — a refresh response does not echo the login nonce.
   * Used to refresh the session's identity/roles so IdP-side changes (e.g. a
   * revoked role) take effect on the next refresh instead of lingering for the
   * full absolute-session TTL.
   *
   * <p>Default throws: only the real JWKS-backed validator implements it; the
   * many in-test doubles that exercise the login/callback path never reach a
   * refresh and inherit this body.
   */
  default Map<String, Object> validateRefreshed(String idToken, String accessToken) {
    throw new UnsupportedOperationException("validateRefreshed not implemented");
  }
}
