package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.boot.test.system.CapturedOutput;
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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * End-to-end coverage for {@code AuthController} after the Frame B
 * reshape:
 *
 * <ul>
 *   <li><strong>B2 reversal:</strong> callback is a direct {@code 302} to
 *       the saved-request URL; no intermediate landing page, no CSP
 *       nonce, no {@code window.location.replace} body. Session cookie
 *       is {@code SameSite=Lax} (the OAuth redirect chain originates
 *       cross-site from the IdP; a Strict sid would not be sent on the
 *       final hop to the protected URL).
 *   <li><strong>Browser binding (oauth_tx):</strong> login mints a short-
 *       lived HttpOnly {@code oauth_tx_<state-hash>} cookie scoped to
 *       {@code /auth/callback/idp} and stores its HMAC in
 *       {@code tx:{state}}. The callback rejects when the cookie is
 *       missing or its hash doesn't match the transaction. PKCE +
 *       state + nonce do not bind the callback to the originating
 *       browser; this does. See OAuthTxBinding.
 *   <li><strong>Signed CSRF:</strong> logout requires a {@code .}-shaped
 *       token whose HMAC matches the server-side signing key. A naive
 *       cookie==header match without signature verification would let
 *       tampered values through; the tests below explicitly assert that
 *       does NOT happen.
 * </ul>
 *
 * <p>The signing key in {@code @SpringBootTest} properties is a known
 * Base64-encoded 32-zero-byte value so {@link #signCsrfToken(String, String)} can
 * compute a valid token in-test. The Auth Service cookie name is {@code
 * sid} (not {@code __Host-sid}) on plain-HTTP test requests because the
 * production prefix requires {@code Secure}, which MockMvc cannot emit.
 */
@SpringBootTest(properties = {
    "spring.main.allow-bean-definition-overriding=true",
    "app.oauth-registration-id=idp",
    "app.issuer-uri=http://idp.example",
    "app.client-id=oidc-reference-auth",
    "app.client-secret=test-secret",
    "app.scopes=openid,profile,email,roles,api.audience,api.read",
    "app.session-refresh-window=60s",
    // 32 zero bytes Base64-encoded. The test helper signs CSRF tokens with
    // the matching raw key so request-time validation succeeds.
    "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
@org.junit.jupiter.api.extension.ExtendWith(
    org.springframework.boot.test.system.OutputCaptureExtension.class)
class AuthControllerTest {

  // Raw key bytes that match the Base64 cookie-signing-key above.
  private static final byte[] CSRF_KEY_BYTES = new byte[32];
  // String form of the same key. OAuthTxBinding hashes the cookie value
  // with this exact key, so tests can pre-seed transactions whose
  // tx_cookie_hash will validate against a cookie the test constructs.
  private static final String COOKIE_SIGNING_KEY =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

  @jakarta.annotation.Resource
  private MockMvc mockMvc;

  @jakarta.annotation.Resource
  private InMemoryStateStore stateStore;

  @BeforeEach
  void clearState() {
    stateStore.clear();
  }

  // -- login ---------------------------------------------------------------

  @Test
  void loginRequiresReturnTo() throws Exception {
    // Happy-path login with an explicit return_to=/. /auth/login without
    // return_to is no longer valid (see loginRejectsMissingReturnTo).
    MvcResult result = mockMvc.perform(get("/auth/login")
            .param("return_to", "/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION,
            org.hamcrest.Matchers.containsString("code_challenge_method=S256")))
        .andExpect(cookie().doesNotExist("sid"))
        .andReturn();

    String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
    String txCookieName = OAuthTxBinding.cookieName(queryParam(location, "state"));
    // Browser binding: login MUST set a per-state oauth_tx_<hash> cookie,
    // scoped to /auth/callback/idp, and the transaction record MUST carry
    // its HMAC. sid + XSRF-TOKEN appear on callback success, not here.
    assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE))
        .hasSize(1)
        .first().asString().contains(txCookieName + "=").contains("HttpOnly")
        .contains("Path=/auth/callback/idp").contains("SameSite=Lax");

    assertThat(stateStore.keys()).hasSize(1);
    String txKey = stateStore.keys().iterator().next();
    assertThat(txKey).startsWith("tx:");
    String txJson = stateStore.get(txKey).orElseThrow();
    // Wire shape: snake_case per @JsonProperty on OAuthTransaction.
    assertThat(txJson).contains("\"saved_request\":\"/\"");
    // The HMAC of the cookie value is in tx:{state}; the raw cookie
    // value is NOT (we'd lose the browser-binding security property).
    assertThat(txJson).contains("\"tx_cookie_hash\":\"");
    assertThat(location)
        .contains("redirect_uri=http://127.0.0.1:5173/auth/callback/idp");
  }

  @Test
  void loginUsesForwardedPortWhenForwardedHostOmitsPort() throws Exception {
    MvcResult result = mockMvc.perform(get("/auth/login")
            .param("return_to", "/")
            .header("Host", "127.0.0.1:8081")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1")
            .header("X-Forwarded-Port", "5173"))
        .andExpect(status().isFound())
        .andReturn();

    assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION))
        .contains("redirect_uri=http://127.0.0.1:5173/auth/callback/idp");
  }

  @Test
  void loginWithReturnToQueryParamPersistsSavedRequest() throws Exception {
    // Browser-driven entry: the React app navigates to
    // /auth/login?return_to=<current route>. The Auth Service must
    // persist that URL on the tx:{state} record so the callback can 302
    // back to it.
    mockMvc.perform(get("/auth/login")
            .param("return_to", "/api/user-data")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound());

    assertThat(stateStore.keys()).hasSize(1);
    String txKey = stateStore.keys().iterator().next();
    assertThat(stateStore.get(txKey).orElseThrow())
        .contains("\"saved_request\":\"/api/user-data\"");
  }

  // -- login: return_to validation negatives -------------------------------

  @Test
  void loginRejectsMissingReturnTo() throws Exception {
    // Bare /auth/login (no return_to) is now invalid — the contract
    // requires return_to so a missing value cannot silently default.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsEmptyReturnTo() throws Exception {
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsAbsoluteHttpsReturnTo() throws Exception {
    // Absolute URL — weaponizes the callback as an open redirect.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "https://evil.example/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsJavaScriptSchemeReturnTo() throws Exception {
    // javascript: scheme — XSS payload via Location header.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "javascript:alert(1)")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsProtocolRelativeReturnTo() throws Exception {
    // //host/path — browser interprets as absolute under current scheme.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "//evil.example/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsReturnToWithoutLeadingSlash() throws Exception {
    // Relative-but-no-slash — ambiguous and not a valid absolute path.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "evil/path")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsOverlongReturnTo() throws Exception {
    // Decoded length must be <= 2048. 2049-char value rejected.
    StringBuilder sb = new StringBuilder("/");
    for (int i = 0; i < 2048; i++) {
      sb.append('a');
    }
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", sb.toString())
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsBackslashEncodedReturnTo() throws Exception {
    // %5C is an encoded backslash. Some browsers normalise \ to / in
    // Location headers, turning /\\evil.example/ into //evil.example/.
    // Use URI.create so Tomcat's wire-level decode runs — MockMvc's
    // .param() bypasses that decode and would let the bug through.
    assertReturnToRejected(mockMvc.perform(get(
                java.net.URI.create("/auth/login?return_to=/%5C%5Cevil.example/"))
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsLiteralBackslashInReturnTo() throws Exception {
    // Defense in depth: a caller that supplies the already-decoded
    // form (literal backslash) must also be rejected. Covers the
    // production wire path the percent-encoded variant exercises.
    assertReturnToRejected(mockMvc.perform(get("/auth/login")
            .param("return_to", "/\\evil.example/")
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  @Test
  void loginRejectsControlCharactersInReturnTo() throws Exception {
    // CR/LF in the value would split the Location header on the
    // callback — classic HTTP-response-splitting. Reject at validation.
    assertReturnToRejected(mockMvc.perform(get(java.net.URI.create(
                "/auth/login?return_to=/api/me%0d%0aLocation:%20http://evil/"))
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andReturn());
    assertThat(stateStore.keys()).isEmpty();
  }

  private static void assertReturnToRejected(MvcResult result) throws Exception {
    assertThat(result.getResponse().getStatus()).isEqualTo(400);
    String contentType = result.getResponse().getContentType();
    assertThat(contentType)
        .as("400 response must use application/problem+json")
        .isNotNull()
        .startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    String body = result.getResponse().getContentAsString();
    assertThat(body)
        .as("problem+json body must contain a non-empty detail")
        .contains("\"detail\"")
        .doesNotContain("\"detail\":\"\"")
        .doesNotContain("\"detail\":null");
  }

  // -- callback ------------------------------------------------------------

  @Test
  void callbackCreatesSessionCookieAndRedirectsToSavedRequest() throws Exception {
    // B2: the callback responds with a direct 302 to the saved-request
    // URL — NO HTML body, NO CSP nonce, NO window.location.replace.
    String state = "state-direct-302";
    storeTransaction(state, "/api/user-data");

    MvcResult result = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/api/user-data"))
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
            org.hamcrest.Matchers.containsString("no-store")))
        .andReturn();

    assertThat(result.getResponse().getContentAsString())
        .as("B2: no HTML body — direct 302 only")
        .isEmpty();
    assertThat(result.getResponse().getHeader("Content-Security-Policy"))
        .as("B2: no CSP nonce because there's no inline script anymore")
        .isNull();
    assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE))
        .anySatisfy(c -> assertThat(c)
            .contains("sid=")
            .contains("HttpOnly")
            // sid is Lax (not Strict) because the OAuth callback redirect
            // chain originates cross-site from Keycloak; a Strict sid would
            // not be sent on the final 302 hop to the protected URL.
            // State-changing protection lives in the signed CSRF, not in
            // sid's SameSite. See AuthController#sidCookie.
            .contains("SameSite=Lax"))
        .anySatisfy(c -> assertThat(c)
            .contains("XSRF-TOKEN=")
            // XSRF cookie is JS-readable but only ever needs to be SENT
            // on same-origin XHR requests from the SPA. Strict prevents
            // it from riding cross-site top-level navigations where it
            // has no legitimate use. The HMAC defeats cookie injection;
            // Strict tightens further. See AuthController#xsrfCookie.
            .contains("SameSite=Strict"));
    assertThat(stateStore.get("tx:" + state)).isEmpty();
    assertThat(stateStore.keys()).anyMatch(key -> key.startsWith("sess:"));
  }

  @Test
  void sessionCookiesLiveUntilTheAbsoluteCeilingNotTheIdleWindow() throws Exception {
    // The browser cookie is a bearer handle, not the enforcement point —
    // session lifetime is enforced server-side by the sliding sess:{sid}
    // TTL and the absolute ceiling. A cookie Max-Age equal to the INITIAL
    // idle TTL is never re-issued (the gateway slides only the Valkey key),
    // so every real browser session would hard-stop 30 minutes after login
    // and the documented sliding-idle/8h-absolute design could never take
    // effect. The cookies must live until the absolute ceiling; an idle
    // death server-side just means the next /api request 302s to login.
    String state = "state-cookie-max-age";
    storeTransaction(state, "/");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(cookie().maxAge("sid", 28800))
        .andExpect(cookie().maxAge("XSRF-TOKEN", 28800));
  }

  @Test
  void backChannelLogoutIndexesLiveForTheRemainingAbsoluteTtl() throws Exception {
    // The gateway slides only sess:{sid} and /internal/refresh rewrites only
    // the session key — nothing ever re-extends the back-channel-logout
    // index keys. If they carry the idle TTL they expire ~30 minutes after
    // login and IdP-initiated logout silently degrades to a 200
    // "no_matching_session" for any longer-lived session. The index keys
    // must therefore be written with the session's remaining ABSOLUTE TTL;
    // an index entry outliving a dead sess: key is harmless (the delete
    // paths tolerate a missing session), the reverse is a logout bypass.
    String state = "state-index-ttl";
    storeTransaction(state, "/");

    MvcResult result = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andReturn();

    String sid = result.getResponse().getCookie("sid").getValue();
    assertThat(stateStore.ttl("sess:" + sid))
        .as("the session key itself keeps the sliding idle TTL")
        .isEqualTo(Duration.ofSeconds(1800));
    assertThat(stateStore.ttl("logout_hint:" + sid))
        .as("logout-hint index must survive until the absolute ceiling")
        .isBetween(Duration.ofSeconds(28790), Duration.ofSeconds(28800));
    assertThat(stateStore.ttl("sub_sessions:alice"))
        .as("subject index must survive until the absolute ceiling")
        .isBetween(Duration.ofSeconds(28790), Duration.ofSeconds(28800));
  }

  @Test
  void callbackCollapsesProtocolRelativeSavedRequestToRoot() throws Exception {
    // Protocol-relative URLs (//host/path) are absolute under URI.create
    // and must collapse to "/". The callback 302 then targets /, not the
    // attacker-supplied host.
    String state = "state-protocol-relative";
    storeTransaction(state, "//evil.example/path");

    MvcResult callback = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/"))
        .andReturn();

    assertThat(callback.getResponse().getContentAsString()).doesNotContain("evil.example");
  }

  @Test
  void rejectedCallbackClearsTransactionWithoutCreatingSession() throws Exception {
    // The TokenExchangeClient throws on the sentinel code; per the spec
    // §Test Plan, tx:{state} is deleted before the exchange attempt so
    // the rejection path leaves no orphan tx record AND no session.
    String state = "state-rejected";
    storeTransaction(state, "/api/user-data");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "reject-code")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
            org.hamcrest.Matchers.containsString("no-store")))
        // Every callback error path returns RFC 7807 problem+json with
        // a "detail" describing the failure shape (not the user's input).
        // Plain-text bodies make machine clients guess; ProblemDetail is
        // the consistent shape the rest of the auth-service uses.
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("tx:" + state)).isEmpty();
    assertThat(stateStore.keys()).noneMatch(key -> key.startsWith("sess:"));
  }

  @Test
  void callbackSetsXsrfCookieAsSignedToken() throws Exception {
    // The XSRF-TOKEN cookie must be shaped as <value>.<hmac> — both
    // base64url alphabet, separated by a literal dot. A naive
    // implementation that emits a single opaque value would fail this.
    String state = "state-xsrf-shape";
    storeTransaction(state, "/");

    MvcResult callback = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andReturn();

    String xsrfCookie = callback.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
        .filter(c -> c.startsWith("XSRF-TOKEN="))
        .findFirst()
        .orElseThrow();
    String tokenValue = xsrfCookie.substring(
        "XSRF-TOKEN=".length(),
        xsrfCookie.indexOf(';'));
    assertThat(tokenValue)
        .as("signed CSRF token: <value>.<hmac> in base64url alphabet")
        .matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");
  }

  @Test
  void callbackSetsHostSidCookieInProductionForwardedProto() throws Exception {
    // X-Forwarded-Proto: https → cookie name is __Host-sid AND Secure
    // attribute is set (required for the __Host- prefix to be honored
    // by browsers). With http, the cookie name is sid and no Secure
    // attribute.
    String state = "state-https";
    storeTransaction(state, "/");

    MvcResult httpsResult = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state))
            .header("Host", "app.example.com")
            .header("X-Forwarded-Proto", "https")
            .header("X-Forwarded-Host", "app.example.com"))
        .andExpect(status().isFound())
        .andReturn();
    String httpsSid = httpsResult.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
        .filter(c -> c.startsWith("__Host-sid="))
        .findFirst()
        .orElse(null);
    assertThat(httpsSid)
        .as("X-Forwarded-Proto=https must produce __Host-sid with Secure")
        .isNotNull()
        .contains("Secure");

    // Same flow over http → plain sid, no Secure attribute.
    String state2 = "state-http";
    storeTransaction(state2, "/");
    MvcResult httpResult = mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state2)
            .cookie(txCookie(state2))
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound())
        .andReturn();
    String httpSid = httpResult.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
        .filter(c -> c.startsWith("sid="))
        .findFirst()
        .orElse(null);
    assertThat(httpSid)
        .as("plain http must produce sid (no __Host- prefix) and no Secure")
        .isNotNull()
        .doesNotContain("Secure");
  }

  // -- callback: iss param mix-up defense (RFC 9700 §4.4, RFC 9207) --------

  @Test
  void callbackRejectsIssParamFromWrongIssuer(CapturedOutput output) throws Exception {
    // An attacker who controls a malicious IdP can complete a flow on that
    // IdP and trick the user into hitting our callback with the resulting
    // (code, state, iss). The iss value tells us which IdP minted them —
    // if it doesn't match our configured issuer, RFC 9700 §4.4 / RFC 9207
    // says reject. Without this check we'd attempt token exchange against
    // OUR token endpoint with a code that doesn't belong to us.
    String state = "state-iss-wrong";
    storeTransaction(state, "/api/user-data");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .param("iss", "http://attacker.example")
            .cookie(txCookie(state)))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(cookie().exists(OAuthTxBinding.cookieName(state)))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(state), 0));

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=iss_mismatch");
    // Transaction MUST be consumed so attacker cannot retry with the right iss.
    assertThat(stateStore.get("tx:" + state)).isEmpty();
  }

  @Test
  void callbackAcceptsMatchingIssParam() throws Exception {
    // Belt: if the IdP supports RFC 9207 (Keycloak does as of 26.x via
    // the authorization_response_iss_parameter_supported metadata flag),
    // every callback carries iss. The HAPPY path must remain green when
    // iss matches the configured issuer.
    String state = "state-iss-match";
    storeTransaction(state, "/api/user-data");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .param("iss", "http://idp.example")
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(cookie().exists("sid"));
  }

  @Test
  void callbackAcceptsMissingIssParam() throws Exception {
    // Suspenders: not every IdP emits the iss query parameter (RFC 9207 is
    // recent and adoption is gradual). When iss is absent we must NOT
    // reject — the rest of the validation (state, tx-cookie binding, PKCE,
    // ID-token issuer claim) is still load-bearing.
    String state = "state-iss-absent";
    storeTransaction(state, "/api/user-data");

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(cookie().exists("sid"));
  }

  @Test
  void callbackHandlesIdpErrorRedirectGracefully(CapturedOutput output) throws Exception {
    // User clicks "Deny" at the IdP (or the IdP rejects the request): it
    // redirects to /auth/callback/idp with ?error=access_denied&state=... and
    // NO code. The callback must consume the transaction (no lingering tx
    // until TTL), evict the oauth_tx cookie, and return the user to the app
    // home — not a raw framework 400 with the transaction left behind.
    String state = "state-idp-denied";
    storeTransaction(state, "/api/user-data");

    mockMvc.perform(get("/auth/callback/idp")
            .param("error", "access_denied")
            .param("state", state)
            .cookie(txCookie(state)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/"))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(state), 0));

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=idp_error");
    // Single-use: the transaction must be consumed on the error path too.
    assertThat(stateStore.get("tx:" + state)).isEmpty();
  }

  // -- callback: browser binding (oauth_tx) --------------------------------

  @Test
  void callbackSucceedsWhenOauthTxCookieMatchesTxHash() throws Exception {
    // The transaction was created with a tx_cookie_hash; the browser
    // presents the original cookie value at callback. HMAC(cookie) must
    // equal the stored hash → callback proceeds, sid + XSRF set.
    String state = "state-binding-ok";
    String cookieValue = OAuthTxBinding.issueCookieValue();
    String hash = OAuthTxBinding.hash(cookieValue, COOKIE_SIGNING_KEY);
    storeBoundTransaction(state, "/", hash);

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(new Cookie(OAuthTxBinding.cookieName(state), cookieValue)))
        .andExpect(status().isFound())
        .andExpect(cookie().exists("sid"))
        // Callback evicts the oauth_tx cookie even on success — the
        // transaction is single-use.
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(state), 0));
    assertThat(stateStore.get("tx:" + state)).isEmpty();
  }

  @Test
  void concurrentLoginCallbacksUseIndependentTransactionCookies() throws Exception {
    String stateA = "state-tab-a";
    String stateB = "state-tab-b";
    String cookieValueA = OAuthTxBinding.issueCookieValue();
    String cookieValueB = OAuthTxBinding.issueCookieValue();
    storeBoundTransaction(
        stateA, "/api/a", OAuthTxBinding.hash(cookieValueA, COOKIE_SIGNING_KEY));
    storeBoundTransaction(
        stateB, "/api/b", OAuthTxBinding.hash(cookieValueB, COOKIE_SIGNING_KEY));

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", stateA)
            .cookie(new Cookie(OAuthTxBinding.cookieName(stateA), cookieValueA))
            .cookie(new Cookie(OAuthTxBinding.cookieName(stateB), cookieValueB)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/api/a"))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(stateA), 0))
        .andExpect(cookie().doesNotExist(OAuthTxBinding.cookieName(stateB)));

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", stateB)
            .cookie(new Cookie(OAuthTxBinding.cookieName(stateB), cookieValueB)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/api/b"))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(stateB), 0));

    assertThat(stateStore.get("tx:" + stateA)).isEmpty();
    assertThat(stateStore.get("tx:" + stateB)).isEmpty();
  }

  @Test
  void callbackRejectsWhenOauthTxCookieIsMissing(CapturedOutput output) throws Exception {
    String state = "state-binding-missing";
    String cookieValue = OAuthTxBinding.issueCookieValue();
    String hash = OAuthTxBinding.hash(cookieValue, COOKIE_SIGNING_KEY);
    storeBoundTransaction(state, "/", hash);

    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(cookie().exists(OAuthTxBinding.cookieName(state)))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(state), 0));

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=missing_tx_cookie");
    // tx:{state} was getAndDelete'd, so the transaction is single-use
    // even on rejection — replays cannot retry with a different cookie.
    assertThat(stateStore.get("tx:" + state)).isEmpty();
  }

  @Test
  void callbackRejectsWhenOauthTxCookieDoesNotMatchStoredHash(CapturedOutput output)
      throws Exception {
    String state = "state-binding-mismatch";
    String realCookieValue = OAuthTxBinding.issueCookieValue();
    String hash = OAuthTxBinding.hash(realCookieValue, COOKIE_SIGNING_KEY);
    storeBoundTransaction(state, "/", hash);

    // Attacker presents (code, state) but in their own browser, so their
    // oauth_tx cookie value is different — the HMAC won't match the
    // stored hash and the callback refuses.
    String attackerCookieValue = OAuthTxBinding.issueCookieValue();
    mockMvc.perform(get("/auth/callback/idp")
            .param("code", "code-1")
            .param("state", state)
            .cookie(new Cookie(OAuthTxBinding.cookieName(state), attackerCookieValue)))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
        .andExpect(cookie().maxAge(OAuthTxBinding.cookieName(state), 0));

    assertThat(output.getOut())
        .contains("event=callback_failed")
        .contains("reason=tx_cookie_mismatch");
    assertThat(stateStore.get("tx:" + state)).isEmpty();
  }

  // -- session lifecycle ---------------------------------------------------

  @Test
  void meIncludesVaryCookieHeader() throws Exception {
    // Vary: Cookie is the contract that any cache between the SPA and
    // the Auth Service (a corporate forward proxy, a CDN that does pass-
    // through caching, a service worker) MUST key the cached response
    // on the request's Cookie header. Without it a shared cache could
    // serve user A's /auth/me response to user B with no per-user keying.
    // Cache-Control: no-store already guards us from compliant caches,
    // but Vary is the defense-in-depth that non-compliant ones honor.
    Cookie sid = createSessionCookie();

    mockMvc.perform(get("/auth/me").cookie(sid))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.VARY, "Cookie"));
  }

  @Test
  void expiredAbsoluteSessionIsRejectedAndDeleted() throws Exception {
    // Sliding TTL has a hard ceiling at absoluteExpiresAt. Even if the
    // record is still in the state store, an absolute-expired session
    // must be treated as missing and DEL'd lazily on read.
    Cookie sid = createExpiredAbsoluteSessionCookie();

    mockMvc.perform(get("/auth/me").cookie(sid))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
            org.hamcrest.Matchers.containsString("no-store")));

    assertThat(stateStore.get("sess:" + sid.getValue())).isEmpty();
  }

  @Test
  void authMeDoesNotSlideIdleTtl() throws Exception {
    Cookie sid = createSessionCookie();

    mockMvc.perform(get("/auth/me").cookie(sid))
        .andExpect(status().isOk());

    assertThat(stateStore.expireCalls())
        .as("/auth/me is a liveness/read probe and must not extend idle TTL")
        .isZero();
  }

  // -- logout (signed CSRF) ------------------------------------------------

  @Test
  void logoutDeletesSessionAndClearsCookie() throws Exception {
    Cookie sid = createSessionCookie();
    String csrf = signCsrfToken("logout-value", sid.getValue());

    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", csrf))
            .header("X-XSRF-TOKEN", csrf)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound())
        // The logout response carries only a same-origin, opaque continuation
        // handle — never the IdP URL and never the id_token. The server emits
        // the IdP end-session redirect itself at /auth/logout/continue, so the
        // id_token (PII) never reaches the browser as readable data.
        .andExpect(header().string(HttpHeaders.LOCATION, org.hamcrest.Matchers.allOf(
            org.hamcrest.Matchers.startsWith("/auth/logout/continue?lc="),
            org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("id_token_hint")),
            org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("idp.example")))))
        // sid + XSRF evicted. Per-transaction oauth_tx_<hash> cookies
        // are cleared by their matching callback and otherwise expire
        // naturally at TX_TTL.
        .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
            org.hamcrest.Matchers.hasItems(
                org.hamcrest.Matchers.containsString("sid=;"),
                org.hamcrest.Matchers.containsString("XSRF-TOKEN=;"))));

    assertThat(stateStore.get("sess:" + sid.getValue())).isEmpty();
  }

  @Test
  void logoutCanReturnJsonRedirectForSpaFetch() throws Exception {
    Cookie sid = createSessionCookie();
    String csrf = signCsrfToken("spa-logout-value", sid.getValue());

    MvcResult result = mockMvc.perform(post("/auth/logout")
            .accept(MediaType.APPLICATION_JSON)
            .cookie(sid, new Cookie("XSRF-TOKEN", csrf))
            .header("X-XSRF-TOKEN", csrf)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
            org.hamcrest.Matchers.containsString("no-store")))
        .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
            org.hamcrest.Matchers.hasItems(
                org.hamcrest.Matchers.containsString("sid=;"),
                org.hamcrest.Matchers.containsString("XSRF-TOKEN=;"))))
        .andReturn();

    // The SPA-readable body carries only a same-origin opaque handle — no
    // id_token, no IdP URL. This is the invariant: tokens never reach JS.
    String body = result.getResponse().getContentAsString();
    assertThat(body)
        .contains("\"logoutUrl\":\"/auth/logout/continue?lc=")
        .doesNotContain("id_token_hint")
        .doesNotContain("idp.example");
    assertThat(stateStore.get("sess:" + sid.getValue())).isEmpty();
  }

  @Test
  void logoutContinueRedirectsToIdpServerSide_andIsSingleUse() throws Exception {
    // The SPA navigates (top-level) to the opaque continuation handle returned
    // by POST /auth/logout. ONLY this server endpoint emits the IdP end-session
    // redirect, with id_token_hint + no-referrer, so the id_token never reaches
    // JS as readable data. The handle is single-use.
    Cookie sid = createSessionCookie();
    String csrf = signCsrfToken("continue-value", sid.getValue());

    MvcResult logout = mockMvc.perform(post("/auth/logout")
            .accept(MediaType.APPLICATION_JSON)
            .cookie(sid, new Cookie("XSRF-TOKEN", csrf))
            .header("X-XSRF-TOKEN", csrf)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isOk())
        .andReturn();

    java.util.regex.Matcher m = java.util.regex.Pattern
        .compile("/auth/logout/continue\\?lc=([^\"\\\\]+)")
        .matcher(logout.getResponse().getContentAsString());
    assertThat(m.find()).isTrue();
    String handle = m.group(1);

    // First navigation: server emits the IdP end-session 302 with id_token_hint.
    mockMvc.perform(get("/auth/logout/continue").param("lc", handle))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, org.hamcrest.Matchers.allOf(
            org.hamcrest.Matchers.startsWith("http://idp.example/logout?"),
            org.hamcrest.Matchers.containsString("id_token_hint=id-token-1"))))
        .andExpect(header().string("Referrer-Policy", "no-referrer"));

    // Single-use: replaying the handle no longer yields the IdP URL.
    mockMvc.perform(get("/auth/logout/continue").param("lc", handle))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/"));
  }

  @Test
  void logoutContinueWithUnknownHandleRedirectsHome() throws Exception {
    mockMvc.perform(get("/auth/logout/continue").param("lc", "does-not-exist"))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, "/"));
  }

  @Test
  void logoutRequiresSignedDoubleSubmitCsrf() throws Exception {
    // Four sub-cases of the signed-CSRF contract from §7.3:
    //   1. missing CSRF entirely → 403
    //   2. mismatched signature (forged HMAC) → 403  ← load-bearing case
    //   3. tampered value half → 403
    //   4. valid signed token → 200 (or 302 navigation)
    Cookie sid = createSessionCookie();

    // 1. missing CSRF entirely
    mockMvc.perform(post("/auth/logout").cookie(sid))
        .andExpect(status().isForbidden());
    assertThat(stateStore.get("sess:" + sid.getValue())).isPresent();

    // 2. mismatched signature — value valid base64url, HMAC computed under
    //    a foreign key. The constant-time equality check on cookie/header
    //    passes; the HMAC recompute under the real key disagrees. This is
    //    the cookie-injection attack signed double-submit defends against.
    String value = "tampered-value";
    String forgedHmac = hmacUnderForeignKey(value, sid.getValue());
    String forged = value + "." + forgedHmac;
    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", forged))
            .header("X-XSRF-TOKEN", forged))
        .andExpect(status().isForbidden());
    assertThat(stateStore.get("sess:" + sid.getValue()))
        .as("forged-HMAC logout must NOT terminate the session")
        .isPresent();

    // 3. tampered value half with original HMAC — same cookie==header, but
    //    HMAC recompute under the real key fails on the new value.
    String legitValue = "legit-value";
    String legitHmac = computeHmac(legitValue, sid.getValue());
    String tamperedToken = "TAMPERED-value" + "." + legitHmac;
    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", tamperedToken))
            .header("X-XSRF-TOKEN", tamperedToken))
        .andExpect(status().isForbidden());
    assertThat(stateStore.get("sess:" + sid.getValue())).isPresent();

    // 4. valid signed token
    String valid = legitValue + "." + legitHmac;
    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", valid))
            .header("X-XSRF-TOKEN", valid)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isFound());
    assertThat(stateStore.get("sess:" + sid.getValue())).isEmpty();
  }

  @Test
  void logoutRejectsCsrfTokenIssuedForDifferentSession() throws Exception {
    Cookie sid = createSessionCookie("sid-a", "access-token-1", Instant.now().plusSeconds(300));
    String csrfForOtherSession = signCsrfToken("cross-session-value", "sid-b");

    mockMvc.perform(post("/auth/logout")
            .cookie(sid, new Cookie("XSRF-TOKEN", csrfForOtherSession))
            .header("X-XSRF-TOKEN", csrfForOtherSession))
        .andExpect(status().isForbidden());

    assertThat(stateStore.get("sess:" + sid.getValue()))
        .as("CSRF token from another sid must not terminate this session")
        .isPresent();
  }

  @Test
  void logoutWithoutKnownSessionStillDrivesIdpLogout() throws Exception {
    Cookie sid = createSessionCookie("stale-sid", "access-token-1", Instant.now().plusSeconds(300));
    stateStore.delete("sess:" + sid.getValue());
    String csrf = signCsrfToken("any-value", sid.getValue());
    MvcResult logout = mockMvc.perform(post("/auth/logout")
            .accept(MediaType.APPLICATION_JSON)
            .cookie(sid, new Cookie("XSRF-TOKEN", csrf))
            .header("X-XSRF-TOKEN", csrf)
            .header("Host", "127.0.0.1:5173")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "127.0.0.1:5173"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
            org.hamcrest.Matchers.containsString("no-store")))
        .andReturn();

    String body = logout.getResponse().getContentAsString();
    assertThat(body)
        .contains("\"logoutUrl\":\"/auth/logout/continue?lc=")
        .doesNotContain("id_token_hint")
        .doesNotContain("id-token-1")
        .doesNotContain("idp.example");

    java.util.regex.Matcher m = java.util.regex.Pattern
        .compile("/auth/logout/continue\\?lc=([^\"\\\\]+)")
        .matcher(body);
    assertThat(m.find()).isTrue();

    mockMvc.perform(get("/auth/logout/continue").param("lc", m.group(1)))
        .andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, org.hamcrest.Matchers.allOf(
            org.hamcrest.Matchers.startsWith("http://idp.example/logout?"),
            org.hamcrest.Matchers.containsString("client_id=oidc-reference-auth"),
            org.hamcrest.Matchers.containsString("id_token_hint=id-token-1"))));

    assertThat(stateStore.get("logout_hint:" + sid.getValue()))
        .as("stale-session logout hint is single-use")
        .isEmpty();
  }

  @Test
  void unknownAuthPathIsDeniedByDefault() throws Exception {
    // The Order-1 chain (/internal/**) requires authentication. An
    // unauthenticated request to a non-existent /internal subpath must
    // produce 401 (filter rejects before handler resolution), proving
    // the security chain is wired at this path. (The B-frame note in
    // the task plan flagged this as 403, but the actual chain is
    // oauth2ResourceServer → 401; either is acceptable as long as the
    // call does NOT reach a permitAll handler.)
    mockMvc.perform(get("/internal/accidental"))
        .andExpect(result -> {
          int s = result.getResponse().getStatus();
          assertThat(s)
              .as("/internal/** must be denied without bearer")
              .isIn(401, 403);
        });
  }

  // -- helpers --------------------------------------------------------------

  // Fixed oauth_tx cookie/hash value used by the happy-path callback
  // tests so the controller's browser-binding check (mandatory since
  // commit f66... follow-up) actually runs end-to-end on every
  // positive callback test rather than being bypassed by a null hash.
  // Tests present txCookie(state) on the callback request; tests
  // exercising the binding-failure paths use storeBoundTransaction
  // with a hash whose cookie value they withhold, mismatch, or replace.
  private static final String TX_COOKIE_VALUE = "fixed-test-oauth-tx-value";

  private static Cookie txCookie(String state) {
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

  private static String queryParam(String url, String name) {
    URI uri = URI.create(url);
    return java.util.Arrays.stream(Optional.ofNullable(uri.getRawQuery()).orElse("").split("&"))
        .map(pair -> pair.split("=", 2))
        .filter(parts -> parts.length == 2 && parts[0].equals(name))
        .findFirst()
        .map(parts -> java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8))
        .orElseThrow();
  }

  // Persist a transaction with a tx_cookie_hash, so the callback's
  // browser-binding check is exercised. Callers pass the hash they've
  // already computed (via OAuthTxBinding.hash) — the test holds the
  // raw cookie value separately so it can present it on the callback.
  private void storeBoundTransaction(String state, String savedRequest, String txCookieHash) {
    OAuthTransaction transaction = new OAuthTransaction(
        "verifier",
        "nonce",
        savedRequest,
        Instant.now(),
        txCookieHash);
    stateStore.put("tx:" + state, TestBeans.JSON.encode(transaction), Duration.ofMinutes(5));
  }

  private Cookie createSessionCookie() {
    return createSessionCookie("sid-test", "access-token-1", Instant.now().plusSeconds(300));
  }

  private Cookie createSessionCookie(String sid, String accessToken, Instant expiresAt) {
    Instant createdAt = Instant.now();
    SessionRecord session = new SessionRecord(
        accessToken,
        "refresh-token-1",
        "id-token-1",
        expiresAt,
        Instant.now().plusSeconds(1800),
        createdAt,
        createdAt.plus(Duration.ofHours(12)),
        Map.of("sub", "alice"));
    stateStore.put("sess:" + sid, TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    new SessionIndexes(stateStore, TestBeans.JSON).index(sid, session);
    return new Cookie("sid", sid);
  }

  private Cookie createExpiredAbsoluteSessionCookie() {
    String sid = "sid-absolute-expired";
    SessionRecord session = new SessionRecord(
        "access-token-1",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(300),
        Instant.now().plusSeconds(1800),
        Instant.now().minus(Duration.ofHours(13)),
        Instant.now().minusSeconds(1),
        Map.of("sub", "alice"));
    stateStore.put("sess:" + sid, TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    return new Cookie("sid", sid);
  }

  /** Compute a valid signed CSRF token using the key wired in @SpringBootTest properties. */
  private static String signCsrfToken(String value, String sid) {
    return value + "." + computeHmac(value, sid);
  }

  private static String computeHmac(String value, String sid) {
    return hmac(value + ":" + sid, CSRF_KEY_BYTES);
  }

  private static String hmacUnderForeignKey(String value, String sid) {
    byte[] foreign = new byte[32];
    for (int i = 0; i < foreign.length; i++) {
      foreign[i] = (byte) (i + 7);  // deliberately not the wired key
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
      // AuthControllerTest never exercises refresh; provide an unreachable
      // stub so context refresh succeeds.
      return session -> {
        throw new UnsupportedOperationException("refresh path is not exercised in AuthControllerTest");
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

    // Production wires a NimbusJwtDecoder that hits JWKS at startup. The
    // /internal/** filter chain still requires a bean to be present even
    // though /auth/** flows never trigger it; stub it.
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
