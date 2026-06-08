package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Verifies the HMAC-signed double-submit CSRF contract from SPEC-0001 §7.3.
 *
 * <p>Naive double-submit ("compare cookie value to header value") is
 * vulnerable to a cookie-injection attacker on a sibling subdomain who can
 * pin a matching pair into the victim's browser. The signed form binds the
 * token value to a server-controlled HMAC key; an attacker without the key
 * cannot forge a token that survives validation.
 *
 * <p>Each test below is written so the green outcome <em>requires</em> the
 * SUT to actually verify the HMAC — a naive equality-only implementation
 * would fail {@code validateRejectsTokenWithForgedHmac} and
 * {@code validateRejectsTokenWithModifiedValue}.
 */
class SignedCsrfSupportTest {

  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Encoder BASE64_STD = Base64.getEncoder();

  // 32 bytes of zero is a deliberately simple, well-known signing key — its
  // *content* is irrelevant; only that the SUT use it consistently to sign
  // and verify. Tests that need to model a "wrong key" use a distinct byte
  // pattern below.
  private static final byte[] KEY_BYTES = new byte[32];
  private static final byte[] OTHER_KEY_BYTES = new byte[32];

  static {
    // populate the foreign key with a non-zero pattern so two HMACs over the
    // same input genuinely differ
    for (int i = 0; i < OTHER_KEY_BYTES.length; i++) {
      OTHER_KEY_BYTES[i] = (byte) (i + 1);
    }
  }

  private String signingKey;
  private String sid;

  @BeforeEach
  void setUp() {
    signingKey = BASE64_STD.encodeToString(KEY_BYTES);
    sid = "sid-test";
  }

  @Test
  void validateAcceptsTokenThatMatchesItsSignature() {
    String value = "random-128bit-value";
    String hmac = hmac(value + ":" + sid, KEY_BYTES);
    String token = value + "." + hmac;

    assertThat(SignedCsrfSupport.validate(token, token, signingKey, sid)).isTrue();
  }

  @Test
  void validateRejectsTokenFromDifferentSession() {
    String value = "random-128bit-value";
    String token = value + "." + hmac(value + ":" + sid, KEY_BYTES);

    assertThat(SignedCsrfSupport.validate(token, token, signingKey, "sid-other")).isFalse();
  }

  @Test
  void validateRejectsTokenWithModifiedValue() {
    // attacker swaps the value half but keeps the original HMAC; HMAC over
    // the new value differs from the supplied HMAC, so verification must
    // fail. A naive cookie==header check would *pass* here — this asserts
    // the SUT recomputes the HMAC.
    String value = "random-128bit-value";
    String hmac = hmac(value + ":" + sid, KEY_BYTES);
    String tampered = "random-128bit-VALUE" + "." + hmac;

    assertThat(SignedCsrfSupport.validate(tampered, tampered, signingKey, sid)).isFalse();
  }

  @Test
  void validateRejectsTokenWithForgedHmac() {
    // attacker keeps the value half but signs with a foreign key; the
    // supplied HMAC differs from what the SUT recomputes under the real
    // key. Load-bearing for the entire signed-double-submit threat model.
    String value = "random-128bit-value";
    String forged = hmac(value + ":" + sid, OTHER_KEY_BYTES);
    String token = value + "." + forged;

    assertThat(SignedCsrfSupport.validate(token, token, signingKey, sid)).isFalse();
  }

  @Test
  void validateRejectsTokenWithoutDotSeparator() {
    // No `.` means no separable value/hmac halves — must reject before
    // attempting HMAC recomputation. A naive split-on-dot implementation
    // could blow up with IndexOutOfBounds; the SUT must defend.
    assertThat(SignedCsrfSupport.validate("not-a-signed-token", "not-a-signed-token", signingKey, sid))
        .isFalse();
  }

  @Test
  void validateRejectsWhenCookieAndHeaderDiffer() {
    // The constant-time cookie==header check still runs first; mismatched
    // pairs must be rejected before HMAC recomputation, both because they
    // can never be legitimate and because the cheap check shrinks the
    // attack surface for timing oracles on the HMAC step.
    String value = "random-128bit-value";
    String hmac = hmac(value + ":" + sid, KEY_BYTES);
    String token = value + "." + hmac;
    String otherValue = "different-128bit-value";
    String otherToken = otherValue + "." + hmac(otherValue + ":" + sid, KEY_BYTES);

    assertThat(SignedCsrfSupport.validate(token, otherToken, signingKey, sid)).isFalse();
  }

  @Test
  void validateRejectsBothNullCookieAndHeader() {
    // Defensive null handling: neither half present means the request is
    // unauthenticated as CSRF goes; the SUT must not throw NPE.
    assertThat(SignedCsrfSupport.validate(null, null, signingKey, sid)).isFalse();
    assertThat(SignedCsrfSupport.validate("anything", null, signingKey, sid)).isFalse();
    assertThat(SignedCsrfSupport.validate(null, "anything", signingKey, sid)).isFalse();
    assertThat(SignedCsrfSupport.validate("anything", "anything", signingKey, null)).isFalse();
  }

  // -- helpers --------------------------------------------------------------

  private static String hmac(String value, byte[] key) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      byte[] sig = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
      return BASE64_URL.encodeToString(sig);
    } catch (Exception e) {
      throw new IllegalStateException("HmacSHA256 unavailable", e);
    }
  }
}
