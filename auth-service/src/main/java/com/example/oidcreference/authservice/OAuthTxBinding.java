package com.example.oidcreference.authservice;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

// Browser-bound OAuth transaction cookie. PKCE binds the callback to
// the *client* (only the originator of the code_verifier can redeem),
// state binds it to the *redirect URL*, and nonce binds it to the
// *issued id_token*. None of these binds the callback to the *browser*
// that initiated /auth/login. An attacker who exfiltrates (code, state)
// from a victim's user-agent (e.g. via a referrer leak, logs, or a
// shared CI capture) could otherwise complete the callback in their
// own browser and graft the victim's session onto themselves.
//
// Fix: at /auth/login we mint a random per-state `oauth_tx_<hash>`
// cookie, store its HMAC in tx:{state}, set it HttpOnly + SameSite=Lax
// + Path=/auth/callback/idp (tight scope so it only ever rides the
// callback) on the 302 to the IdP. At /auth/callback/idp we compute the
// cookie name from state, re-hash the cookie value, and
// constant-time-compare with the stored hash. Cookie missing or
// mismatch → 400. The transaction cookie is cleared on every callback
// (success or failure) so a single login transaction can be redeemed at
// most once, while concurrent login tabs do not clobber each other.
final class OAuthTxBinding {
  static final String COOKIE_PREFIX = "oauth_tx_";
  static final String COOKIE_PATH = "/auth/callback/idp";

  private OAuthTxBinding() {}

  static String cookieName(String state) {
    if (state == null || state.isBlank()) {
      throw new IllegalArgumentException("state is required");
    }
    return COOKIE_PREFIX + shortHash(state);
  }

  // 32 bytes from a CSPRNG — same shape as state/nonce so the audit
  // log line widths stay comparable.
  static String issueCookieValue() {
    return CryptoSupport.randomUrlToken(32);
  }

  // HMAC-SHA256 of the cookie value under the shared signing key.
  // Returns base64-url (no padding). Delegates to SignedCsrfSupport
  // so the key-decode + Mac dance lives in one place; if the HMAC
  // scheme (key encoding, MAC algorithm, output encoding) ever
  // changes, both signed-cookie features rotate together.
  static String hash(String cookieValue, String signingKey) {
    if (cookieValue == null || signingKey == null) {
      throw new IllegalArgumentException("cookieValue and signingKey are required");
    }
    return SignedCsrfSupport.hmacSha256(cookieValue, signingKey);
  }

  // Constant-time check. Returns false on null inputs rather than
  // throwing — the caller wants a yes/no for "is the request bound to
  // the originating browser," not a security exception that could
  // create a side channel.
  static boolean verify(String suppliedCookieValue, String storedHash, String signingKey) {
    if (suppliedCookieValue == null || storedHash == null || signingKey == null) {
      return false;
    }
    String computed;
    try {
      computed = hash(suppliedCookieValue, signingKey);
    } catch (RuntimeException e) {
      return false;
    }
    return MessageDigest.isEqual(
        computed.getBytes(StandardCharsets.UTF_8),
        storedHash.getBytes(StandardCharsets.UTF_8));
  }

  private static String shortHash(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 22);
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
