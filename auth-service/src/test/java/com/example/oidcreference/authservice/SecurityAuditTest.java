package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Coverage for the structured-audit sweep across login, callback, logout,
 * /auth/me 401, and logout 403. Each test drives a real request through
 * the full MockMvc + filter chain and asserts the dedicated
 * "security.audit" logger emits a parseable {@code security_audit
 * event=...} line.
 *
 * <p>Refresh-token-reuse audit is covered by {@code
 * InternalResolveControllerTest.resolveReturns409OnInvalidRefreshToken};
 * see SPEC-0001 §7.1.
 */
@SpringBootTest(properties = {
    "spring.main.allow-bean-definition-overriding=true",
    "app.oauth-registration-id=idp",
    "app.issuer-uri=http://idp.example",
    "app.client-id=oidc-reference-auth",
    "app.client-secret=test-secret",
    "app.scopes=openid,profile,email,roles,api.audience,api.read",
    "app.session-refresh-window=60s",
    "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class SecurityAuditTest {

  private static final byte[] CSRF_KEY_BYTES = new byte[32];
  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

  @jakarta.annotation.Resource
  private MockMvc mockMvc;

  @jakarta.annotation.Resource
  private InMemoryStateStore stateStore;

  @BeforeEach
  void clearState() {
    stateStore.clear();
  }

  @Test
  void loginStartedEmitsAudit(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/auth/login")
            .param("return_to", "/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound());

    assertThat(output.getOut())
        .contains("security_audit")
        .contains("event=login_started")
        .contains("status=302")
        .contains("reason=ok");
  }

  @Test
  void loginRejectedEmitsAudit(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/auth/login")
            .param("return_to", "https://evil.example/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isBadRequest());

    assertThat(output.getOut())
        .contains("event=login_rejected")
        .contains("status=400")
        .contains("reason=invalid_return_to");
  }

  @Test
  void callbackSucceededEmitsAudit(CapturedOutput output) throws Exception {
    String state = "state-audit-ok";
    storeTransaction(state, "/api/me");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound());

    assertThat(output.getOut())
        .contains("event=callback_succeeded")
        .contains("status=302")
        .contains("sub_hash=" + sha256Prefix("alice"))
        .doesNotContain("sub=alice");
  }

  @Test
  void callbackInvalidStateEmitsAudit(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", "state-not-in-store"))
        .andExpect(status().isBadRequest());

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=invalid_state");
  }

  @Test
  void callbackTokenExchangeFailureEmitsAudit(CapturedOutput output) throws Exception {
    String state = "state-audit-reject";
    storeTransaction(state, "/");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "reject-code")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isUnauthorized());

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=token_exchange_failed");
  }

  @Test
  void meWithNoSessionEmitsAudit(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/auth/me"))
        .andExpect(status().isUnauthorized());

    assertThat(output.getOut())
        .contains("event=auth_denied")
        .contains("status=401")
        .contains("reason=no_session")
        .contains("path=/auth/me");
  }

  @Test
  void logoutWithNoSessionEmitsAudit(CapturedOutput output) throws Exception {
    mockMvc.perform(post("/auth/logout"))
        .andExpect(status().isFound());

    assertThat(output.getOut())
        .contains("event=logout_succeeded")
        .contains("status=302")
        .contains("reason=no_local_session")
        .contains("path=/auth/logout");
  }

  @Test
  void logoutWithBadCsrfEmitsAudit(CapturedOutput output) throws Exception {
    Cookie sid = createSessionCookie();
    String forged = "tampered-value." + hmacUnderForeignKey("tampered-value", sid.getValue());

    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", forged))
            .header("X-XSRF-TOKEN", forged))
        .andExpect(status().isForbidden());

    assertThat(output.getOut())
        .contains("event=auth_denied")
        .contains("status=403")
        .contains("reason=csrf_invalid");
  }

  @Test
  void logoutSucceededEmitsAudit(CapturedOutput output) throws Exception {
    Cookie sid = createSessionCookie();
    String csrf = signCsrfToken("audit-logout-value", sid.getValue());

    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", csrf))
            .header("X-XSRF-TOKEN", csrf)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound());

    assertThat(output.getOut())
        .contains("event=logout_succeeded")
        .contains("sub_hash=" + sha256Prefix("alice"))
        .doesNotContain("sub=alice");
  }

  // -- wire-format invariant -----------------------------------------------

  // This single test OWNS the exact rendered audit shape. The ~20 substring
  // assertions elsewhere in the suite ("event=", "reason=") survive a format
  // change because they pin fragments; this one pins the full line, so a
  // future move (e.g. to JSON structured logging) updates SecurityAudit.FORMAT
  // + SecurityAudit.FORMAT_WITH_SUBJECT and THIS test, not 20 sites.
  @Test
  void wireFormatRendersExactShape(CapturedOutput output) {
    org.springframework.mock.web.MockHttpServletRequest request =
        new org.springframework.mock.web.MockHttpServletRequest();
    request.setMethod("POST");
    request.setRequestURI("/auth/logout");
    request.setRemoteAddr("198.51.100.7");

    SecurityAudit.event(request, 403, "auth_denied", "csrf_invalid");

    // Build the expected line FROM the constant (rendered by the same SLF4J
    // MessageFormatter the logger uses), so the wire literal lives in exactly one
    // place: a format change to SecurityAudit.FORMAT updates this assertion
    // automatically. The test still pins event()'s argument ORDER + values: if
    // event() filled the placeholders out of order the rendered line would differ.
    String expected = org.slf4j.helpers.MessageFormatter.arrayFormat(
        SecurityAudit.FORMAT,
        new Object[] {"auth_denied", 403, "POST", "/auth/logout", "csrf_invalid", "198.51.100.7"})
        .getMessage();
    assertThat(output.getOut()).contains(expected);
  }

  @Test
  void wireFormatWithSubjectRendersExactShape(CapturedOutput output) {
    org.springframework.mock.web.MockHttpServletRequest request =
        new org.springframework.mock.web.MockHttpServletRequest();
    request.setMethod("POST");
    request.setRequestURI("/auth/logout");
    request.setRemoteAddr("198.51.100.7");

    SecurityAudit.event(request, 302, "logout_succeeded", "ok", "alice");

    // Same single-source build for the with-subject format. The subject arg is
    // the HASHED value (sha256Prefix), so this also proves event() hashes `sub`
    // before logging — a regression that logged the raw subject would render
    // sub_hash=alice and fail this comparison.
    String expected = org.slf4j.helpers.MessageFormatter.arrayFormat(
        SecurityAudit.FORMAT_WITH_SUBJECT,
        new Object[] {"logout_succeeded", 302, "POST", "/auth/logout", "ok",
            sha256Prefix("alice"), "198.51.100.7"})
        .getMessage();
    assertThat(output.getOut()).contains(expected);
  }

  // -- helpers --------------------------------------------------------------

  // Same fixed cookie/hash pair as AuthControllerTest so happy-path
  // callback audits exercise the browser-binding check.
  private static final String TX_COOKIE_VALUE = "fixed-test-oauth-tx-value";
  private static final String COOKIE_SIGNING_KEY =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

  static Cookie txCookie(String state) {
    return new Cookie(OAuthTxBinding.cookieName(state), TX_COOKIE_VALUE);
  }

  private void storeTransaction(String state, String savedRequest) {
    String hash = OAuthTxBinding.hash(TX_COOKIE_VALUE, COOKIE_SIGNING_KEY);
    OAuthTransaction transaction = new OAuthTransaction(
        "verifier",
        "nonce",
        savedRequest,
        Instant.now(),
        hash);
    stateStore.put("tx:" + state, TestBeans.JSON.encode(transaction), Duration.ofMinutes(5));
  }

  private Cookie createSessionCookie() {
    String sidValue = "audit-sid";
    Instant created = Instant.now();
    SessionRecord session = new SessionRecord(
        "access-token-1",
        "refresh-token-1",
        "id-token-1",
        created.plusSeconds(300),
        created.plusSeconds(1800),
        created,
        created.plus(Duration.ofHours(12)),
        created,
        Map.of("sub", "alice"));
    stateStore.put("sess:" + sidValue, TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    return new Cookie("sid", sidValue);
  }

  private static String signCsrfToken(String value, String sid) {
    return value + "." + hmac(value + ":" + sid, CSRF_KEY_BYTES);
  }

  private static String hmacUnderForeignKey(String value, String sid) {
    byte[] foreign = new byte[32];
    for (int i = 0; i < foreign.length; i++) {
      foreign[i] = (byte) (i + 11);
    }
    return hmac(value + ":" + sid, foreign);
  }

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

  // Mirrors SecurityAudit.hashSubject: first 8 bytes of SHA-256(sub), hex.
  private static String sha256Prefix(String sub) {
    try {
      java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(sub.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(16);
      // Mirrors SecurityAudit.SUB_HASH_HEX_CHARS / 2 = 12 bytes (24 hex chars).
      for (int i = 0; i < 12; i++) {
        sb.append(String.format("%02x", digest[i] & 0xff));
      }
      return sb.toString();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  // -- test config ---------------------------------------------------------

  @TestConfiguration
  static class TestBeans {
    static final JsonCodec JSON = new JsonCodec(tools.jackson.databind.json.JsonMapper.builder()
        .findAndAddModules()
        .build());

    @Bean
    @Primary
    InMemoryStateStore stateStore() {
      return new InMemoryStateStore();
    }

    @Bean
    @Primary
    TokenExchangeClient tokenExchangeClient() {
      return (code, state, redirectUri, transaction) -> {
        if ("reject-code".equals(code)) {
          throw new org.springframework.security.authentication.BadCredentialsException(
              "id token rejected");
        }
        return new SessionRecord(
            "access-token-1",
            "refresh-token-1",
            "id-token-1",
            Instant.now().plusSeconds(300),
            Instant.now().plusSeconds(1800),
            Map.of("sub", "alice", "preferred_username", "alice"));
      };
    }

    @Bean
    @Primary
    TokenRefreshClient tokenRefreshClient() {
      return session -> {
        throw new UnsupportedOperationException("refresh path is not exercised in SecurityAuditTest");
      };
    }

    @Bean
    @Primary
    IdTokenValidator idTokenValidator() {
      return (idToken, accessToken, transaction) -> Map.of(
          "sub", "alice",
          "preferred_username", "alice",
          "roles", List.of("user"));
    }

    @Bean
    @Primary
    OidcProviderMetadata oidcProviderMetadata() {
      return new OidcProviderMetadata(
          "oidc-reference-auth",
          "test-secret",
          URI.create("http://idp.example/authorize"),
          URI.create("http://idp.example/token"),
          URI.create("http://idp.example/jwks"),
          URI.create("http://idp.example/logout"),
          "http://idp.example",
          Set.of("openid", "profile", "email", "roles", "api.audience", "api.read"));
    }

    @Bean
    @Primary
    IDTokenValidator nimbusIdTokenValidator() {
      return new IDTokenValidator(
          new Issuer("http://idp.example"),
          new ClientID("oidc-reference-auth"));
    }

    @Bean
    @Primary
    JwtDecoder internalJwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException(
            "test stub — /auth/** flows do not invoke the /internal JWT decoder");
      };
    }
  }

}
