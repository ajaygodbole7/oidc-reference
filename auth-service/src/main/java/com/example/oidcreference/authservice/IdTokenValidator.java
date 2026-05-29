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
}
