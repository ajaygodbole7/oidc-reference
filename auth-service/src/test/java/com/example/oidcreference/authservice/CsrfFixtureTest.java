package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Cross-language HMAC parity check anchored at {@code schema/csrf-fixture.json}.
 *
 * <p>The fixture documents a known-good (signing_key, token_value,
 * signed_token) triple per SPEC-0001 §7.3. This test asserts that
 * {@link SignedCsrfSupport#validate} accepts the fixture's signed token —
 * if any change to the Java implementation drifts the algorithm (key
 * encoding, value bytes, HMAC output encoding), this test goes red.
 *
 * <p>The same fixture is the canonical reference for any other
 * implementation (the Lua {@code bff-session} plugin, or a future
 * Quarkus / Micronaut variant). Their tests should produce the same
 * {@code hmac_base64url} for the same inputs.
 */
class CsrfFixtureTest {

  @Test
  void signedCsrfSupportAcceptsFixtureToken() throws Exception {
    Path fixture = repoRoot().resolve("schema/csrf-fixture.json");
    String json = Files.readString(fixture);

    String keyB64 = extract(json, "signing_key_base64");
    String signedToken = extract(json, "signed_token");
    String sid = extract(json, "sid");

    assertThat(SignedCsrfSupport.validate(signedToken, signedToken, keyB64, sid))
        .as("SignedCsrfSupport must accept the fixture's signed token — "
            + "the schema/csrf-fixture.json contract has drifted from "
            + "SignedCsrfSupport's HMAC algorithm or encoding")
        .isTrue();
  }

  private static String extract(String json, String key) {
    Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"")
        .matcher(json);
    if (!m.find()) {
      throw new IllegalStateException("fixture key missing: " + key);
    }
    return m.group(1);
  }

  private static Path repoRoot() {
    Path p = Paths.get("").toAbsolutePath();
    while (p != null && !Files.exists(p.resolve("schema/csrf-fixture.json"))) {
      p = p.getParent();
    }
    if (p == null) {
      throw new IllegalStateException("schema/csrf-fixture.json not found from "
          + Paths.get("").toAbsolutePath());
    }
    return p;
  }
}
