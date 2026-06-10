package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Coverage for the POST {@code /internal/refresh} contract from SPEC-0001
 * §7.1. Uses {@code @SpringBootTest} so the full Resource-Server filter
 * chain (Order 1) is exercised end-to-end. The {@code jwt()} request
 * post-processor from {@code spring-security-test} installs a pre-built
 * {@code Jwt} principal — that bypasses the real {@link JwtDecoder} (which
 * would otherwise need a live JWKS endpoint) while still letting the
 * controller observe the audience and {@code azp} claims defensively.
 *
 * <p>The {@link JwtDecoder} bean is stubbed via {@code @Primary} so context
 * refresh does not call out to the (non-existent) Keycloak issuer at bean
 * construction.
 */
@SpringBootTest(properties = {
    "spring.main.allow-bean-definition-overriding=true",
    "app.oauth-registration-id=idp",
    "app.issuer-uri=http://idp.example",
    "app.client-id=oidc-reference-auth",
    "app.client-secret=test-secret",
    "app.scopes=openid,profile,email,roles,api.audience,api.read",
    // 60 s refresh window — short and explicit so the
    // "expiring vs fresh" tests have predictable fences.
    "app.session-refresh-window=60s",
    "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class InternalRefreshControllerTest {

  private static final String EXPECTED_AUDIENCE = "oidc-reference-auth-internal";
  private static final String EXPECTED_CLIENT_ID = "oidc-reference-api-gateway";

  @jakarta.annotation.Resource
  private MockMvc mockMvc;

  @jakarta.annotation.Resource
  private InMemoryStateStore stateStore;

  @jakarta.annotation.Resource
  private RecordingTokenRefreshClient tokenRefreshClient;

  @BeforeEach
  void resetState() {
    stateStore.clear();
    tokenRefreshClient.reset();
  }

  @Test
  void refreshFailsWithoutBearer() throws Exception {
    // The Order-1 chain has oauth2ResourceServer with anyRequest authenticated;
    // anonymous calls are rejected at the filter, never reaching the handler.
    mockMvc.perform(post("/internal/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void refreshFailsWithWrongAudience() throws Exception {
    // Bearer is structurally valid but aud=other-api; the controller's
    // defensive audience check rejects with 401 problem+json even if a
    // misconfigured filter chain let the call through.
    mockMvc.perform(post("/internal/refresh")
            .with(jwt().jwt(j -> j
                .audience(List.of("other-api"))
                .claim("azp", EXPECTED_CLIENT_ID)))
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void refreshFailsWithoutMatchingClientId() throws Exception {
    // azp = the Auth Service's own client_id, not the API Gateway's; the
    // controller must reject because a refresh request can only legitimately
    // come from the Gateway under its Client Credentials identity.
    mockMvc.perform(post("/internal/refresh")
            .with(jwt().jwt(j -> j
                .audience(List.of(EXPECTED_AUDIENCE))
                .claim("azp", "oidc-reference-auth")))
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void refreshReturns400WhenSidMissing(CapturedOutput output) throws Exception {
    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}"))
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("status=400")
        .contains("reason=missing_sid");
  }

  @Test
  void refreshReturns404WhenSessionMissing(CapturedOutput output) throws Exception {
    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-does-not-exist\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("status=404")
        .contains("reason=no_such_session");
  }

  @Test
  void refreshReturns200WithRotatedTokenWhenExpiring(CapturedOutput output) throws Exception {
    // Access token expires in 10 s — well inside the 60 s refresh window —
    // so the controller will call the refresh client and persist the
    // rotated tokens. Assert both the 200 contract fields and the
    // post-write state of sess:{sid}.
    String sid = "sid-expiring";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        // SPEC-0001 §7.1 pins the response body to snake_case: the API
        // Gateway consumes these field names verbatim, and the Lua reader
        // is case-sensitive. camelCase would be a silent contract break.
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"refreshed_at\"")))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"access_token_expires_at\"")))
        .andExpect(content().string(org.hamcrest.Matchers.not(
            org.hamcrest.Matchers.containsString("\"refreshedAt\""))))
        .andExpect(content().string(org.hamcrest.Matchers.not(
            org.hamcrest.Matchers.containsString("\"accessTokenExpiresAt\""))));

    assertThat(tokenRefreshClient.refreshCalls()).isEqualTo(1);
    SessionRecord rotated = decodeSession(sid);
    assertThat(rotated.accessToken()).isEqualTo("refreshed-token");
    assertThat(rotated.refreshToken()).isEqualTo("rotated-refresh-token");

    assertThat(output.getOut())
        .contains("event=refresh_succeeded")
        .contains("status=200")
        .contains("reason=ok");
  }

  @Test
  void refreshReturns200IdempotentWhenStillFresh(CapturedOutput output) throws Exception {
    // Access token has > 60 s remaining; controller must not call the
    // refresh client. Idempotent under contention per §7.1 step 5.
    String sid = "sid-still-fresh";
    SessionRecord fresh = new SessionRecord(
        "still-fresh-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(600),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, fresh);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk());

    verify(tokenRefreshClient.delegate(), never()).refresh(any());
    // Session value preserved exactly — no rewrite path runs.
    SessionRecord untouched = decodeSession(sid);
    assertThat(untouched.accessToken()).isEqualTo("still-fresh-access");
    assertThat(untouched.refreshToken()).isEqualTo("refresh-token-1");

    assertThat(output.getOut())
        .contains("event=refresh_not_needed")
        .contains("reason=outside_refresh_window");
  }

  @Test
  void refreshReturns409OnInvalidRefreshToken(CapturedOutput output) throws Exception {
    // Refresh-token reuse: Keycloak returns invalid_grant; the refresh
    // client surfaces that as InvalidRefreshTokenException. Per §7.1 the
    // controller must: emit the audit event, DEL sess:{sid}, return 409.
    String sid = "sid-reused";
    SessionRecord reused = new SessionRecord(
        "stale-access",
        "reused-refresh-token",  // sentinel — the recording client throws on this
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, reused);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("sess:" + sid)).isEmpty();
    // The WARN line correlates the event to a session WITHOUT
    // leaking the raw sid (session credential). It MUST emit sid_hash=
    // and MUST NOT emit the raw sid string anywhere.
    assertThat(output.getOut())
        .contains("sid_hash=")
        .doesNotContain("sid=" + sid)
        .doesNotContain("sid=" + sid + " ");
    // C13: invalid_grant has many routine, non-attack causes (expired or
    // revoked refresh token, SSO max lifespan) and cannot be attributed to
    // reuse at the RP. The 409 + session-invalidation outcome is correct; the
    // event MUST be labeled honestly, not asserted as proven reuse.
    assertThat(output.getOut())
        .contains("event=refresh_token_rejected")
        .doesNotContain("event=refresh_token_reuse")
        .doesNotContain("reuse detected");
  }

  @Test
  void refreshReturns404AndSkipsKeycloakWhenRefreshTokenExpired(CapturedOutput output)
      throws Exception {
    // C15: the session needs a refresh (access token inside the 60s window)
    // but its refresh token is already expired. Sending a provably-dead
    // refresh token to Keycloak would only earn invalid_grant and route a
    // predictable session end through the refresh-rejected/invalidation path.
    // The controller MUST short-circuit to a clean "session ended" 404 with no
    // upstream call and no rejection alarm.
    String sid = "sid-refresh-expired";
    SessionRecord expired = new SessionRecord(
        "stale-access",
        "would-succeed-if-called",        // NOT a throw sentinel — guard must skip it
        "id-token-1",
        Instant.now().plusSeconds(10),    // inside the refresh window
        Instant.now().minusSeconds(60),   // refresh token already expired
        Map.of("sub", "alice"));
    storeSession(sid, expired);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(tokenRefreshClient.refreshCalls())
        .as("must not call Keycloak with a provably-expired refresh token")
        .isZero();
    assertThat(stateStore.get("sess:" + sid))
        .as("expired-refresh session is dead — must be deleted")
        .isEmpty();
    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("reason=refresh_token_expired")
        .doesNotContain("refresh_token_reuse");
  }

  @Test
  void refreshReturns502OnKeycloakTransientFailure(CapturedOutput output) throws Exception {
    // Network blip / Keycloak 5xx: the refresh client throws a generic
    // RuntimeException. Per §7.1 the controller returns 502 and the
    // session MUST remain intact — refresh is unavailable, but the user's
    // session itself has not been compromised.
    String sid = "sid-transient";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "transient-fail-refresh",  // sentinel — the recording client throws RuntimeException
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isBadGateway())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("sess:" + sid))
        .as("session must NOT be invalidated on transient Keycloak failure")
        .isPresent();

    assertThat(output.getOut())
        .contains("event=refresh_failed")
        .contains("status=502")
        .contains("reason=authorization_server_unreachable");
  }

  @Test
  void refreshDeletesSessionWhenRefreshedRecordCrossesAbsoluteTtl(CapturedOutput output)
      throws Exception {
    // Race window: the pre-refresh absoluteExpired() check at line 95 happens
    // before tokenRefreshClient.refresh() — which is a NETWORK CALL that can
    // take hundreds of ms. A session that is barely valid at the start can
    // have crossed its absolute lifetime by the time the refreshed record
    // is built. refreshed.nextTtl() then returns Duration.ZERO and the
    // current code passes that to stateStore.put, whose semantics differ by
    // backend (Redis rejects EX 0; some Lettuce paths drop the TTL silently
    // turning the session into a permanent key). The controller MUST instead
    // delete the session and return 404 — matching the shape of the
    // pre-refresh check.
    String sid = "sid-crossed-absolute-during-refresh";
    SessionRecord nearlyExpired = new SessionRecord(
        "stale-access",
        "expired-after-refresh",                  // sentinel
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Instant.now().minusSeconds(60),
        Instant.now().plusSeconds(60),            // valid now, but refresh returns past
        Map.of("sub", "alice"));
    storeSession(sid, nearlyExpired);

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("sess:" + sid))
        .as("session crossed absolute TTL during upstream refresh — must be deleted")
        .isEmpty();
    assertThat(stateStore.putCallsWithZeroTtl())
        .as("must never call stateStore.put with Duration.ZERO")
        .isZero();
    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("reason=session_absolute_expired_post_refresh");
  }

  @Test
  void refreshDoesNotResurrectASessionDeletedDuringTheUpstreamCall(CapturedOutput output)
      throws Exception {
    // Resurrection race: the delete paths (POST /auth/logout, back-channel
    // logout) do NOT take the per-sid refresh lock, so a concurrent logout can
    // DEL sess:{sid} after this controller has read the session and entered the
    // IdP round-trip. The post-refresh write must be conditional — if the
    // session is gone, the refreshed tokens must be discarded, NOT used to
    // recreate a session the user just logged out of.
    String sid = "sid-deleted-during-refresh";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    // Simulate the concurrent logout landing mid-refresh: the recording client
    // deletes sess:{sid} from inside refresh(), i.e. during the upstream call.
    tokenRefreshClient.runDuringRefresh(() -> stateStore.delete("sess:" + sid));

    mockMvc.perform(post("/internal/refresh")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("sess:" + sid))
        .as("a session deleted by a concurrent logout must NOT be resurrected by the refresh write")
        .isEmpty();
    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("reason=session_deleted_during_refresh");
  }

  @Test
  void concurrentRefreshCallsForSameSidSerializeOnLock() throws Exception {
    // Two simultaneous refresh calls on the same sid — the per-session
    // lock plus the under-lock re-read of sess:{sid} mean exactly ONE
    // upstream refresh call should fire. The second caller acquires the
    // lock after the first has written the rotated tokens, sees expiry is
    // now > refresh window, and short-circuits to 200.
    String sid = "sid-concurrent";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    tokenRefreshClient.pauseNextRefresh();
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<Integer> first = executor.submit(() -> mockMvc.perform(post("/internal/refresh")
              .with(validApiGatewayBearer())
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"sid\":\"" + sid + "\"}"))
          .andReturn().getResponse().getStatus());
      assertThat(tokenRefreshClient.awaitRefreshStarted())
          .as("first request should reach the refresh client")
          .isTrue();
      Future<Integer> second = executor.submit(() -> mockMvc.perform(post("/internal/refresh")
              .with(validApiGatewayBearer())
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"sid\":\"" + sid + "\"}"))
          .andReturn().getResponse().getStatus());
      tokenRefreshClient.releaseRefresh();

      assertThat(first.get(5, TimeUnit.SECONDS)).isEqualTo(HttpStatus.OK.value());
      assertThat(second.get(5, TimeUnit.SECONDS)).isEqualTo(HttpStatus.OK.value());
    } finally {
      executor.shutdownNow();
    }

    assertThat(tokenRefreshClient.refreshCalls())
        .as("per-session lock + under-lock re-read should collapse two callers to one upstream refresh")
        .isEqualTo(1);
  }

  // -- helpers --------------------------------------------------------------

  private static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor
      validApiGatewayBearer() {
    return jwt().jwt(j -> j
        .audience(List.of(EXPECTED_AUDIENCE))
        .claim("azp", EXPECTED_CLIENT_ID));
  }

  private void storeSession(String sid, SessionRecord session) {
    stateStore.put("sess:" + sid, TestBeans.JSON.encode(session), Duration.ofMinutes(30));
  }

  private SessionRecord decodeSession(String sid) {
    return TestBeans.JSON.decode(
        stateStore.get("sess:" + sid).orElseThrow(),
        SessionRecord.class);
  }

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
    RecordingTokenRefreshClient tokenRefreshClient() {
      return new RecordingTokenRefreshClient();
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
    IdTokenValidator idTokenValidator() {
      return (idToken, accessToken, transaction) -> Map.of("sub", "alice");
    }

    @Bean
    @Primary
    IDTokenValidator nimbusIdTokenValidator() {
      return new IDTokenValidator(new Issuer("http://idp.example"), new ClientID("oidc-reference-auth"));
    }

    // The prod JwtDecoder bean would call JwtDecoders.fromIssuerLocation()
    // which hits http://idp.example over the network. Stub it: the
    // jwt() MockMvc post-processor bypasses the decoder anyway by setting
    // a pre-built JwtAuthenticationToken on the SecurityContext.
    @Bean
    @Primary
    JwtDecoder internalJwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException(
            "test stub — real decoding bypassed by jwt() post-processor");
      };
    }
  }

  /**
   * Recording refresh client that lets the test (a) count upstream calls
   * for the contention test, (b) pause/release in a latch dance to model
   * concurrent contention, and (c) trigger the two failure paths from
   * §7.1 (invalid_grant → InvalidRefreshTokenException, transient → other
   * RuntimeException) via sentinel refresh-token values.
   *
   * <p>The {@code delegate()} accessor returns a Mockito spy so tests can
   * use {@code verify(client, never()).refresh(any())} for the idempotent-
   * when-fresh path; the spy is wired to the same instance.
   */
  static class RecordingTokenRefreshClient implements TokenRefreshClient {
    private final AtomicInteger refreshCalls = new AtomicInteger();
    private final AtomicReference<CountDownLatch> refreshStarted = new AtomicReference<>();
    private final AtomicReference<CountDownLatch> releaseRefresh = new AtomicReference<>();
    private final AtomicReference<Runnable> duringRefresh = new AtomicReference<>();
    private final TokenRefreshClient spy = org.mockito.Mockito.spy(new InnerDelegate());

    @Override
    public SessionRecord refresh(SessionRecord session) {
      return spy.refresh(session);
    }

    TokenRefreshClient delegate() {
      return spy;
    }

    void pauseNextRefresh() {
      refreshStarted.set(new CountDownLatch(1));
      releaseRefresh.set(new CountDownLatch(1));
    }

    boolean awaitRefreshStarted() throws InterruptedException {
      CountDownLatch started = refreshStarted.get();
      return started != null && started.await(5, TimeUnit.SECONDS);
    }

    void releaseRefresh() {
      CountDownLatch release = releaseRefresh.get();
      if (release != null) {
        release.countDown();
      }
    }

    // Run an arbitrary action from INSIDE refresh() — i.e. while the upstream
    // IdP round-trip is notionally in flight — to model a concurrent mutation
    // (e.g. a logout DEL of sess:{sid}) that lands during the refresh.
    void runDuringRefresh(Runnable action) {
      duringRefresh.set(action);
    }

    int refreshCalls() {
      return refreshCalls.get();
    }

    void reset() {
      refreshCalls.set(0);
      refreshStarted.set(null);
      releaseRefresh.set(null);
      duringRefresh.set(null);
      org.mockito.Mockito.clearInvocations(spy);
    }

    private class InnerDelegate implements TokenRefreshClient {
      @Override
      public SessionRecord refresh(SessionRecord session) {
        refreshCalls.incrementAndGet();
        CountDownLatch started = refreshStarted.get();
        CountDownLatch release = releaseRefresh.get();
        if (started != null && release != null) {
          started.countDown();
          try {
            if (!release.await(5, TimeUnit.SECONDS)) {
              throw new IllegalStateException("timed out waiting to release refresh");
            }
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted waiting to release refresh", e);
          }
        }
        Runnable midRefresh = duringRefresh.get();
        if (midRefresh != null) {
          midRefresh.run();
        }
        if ("reused-refresh-token".equals(session.refreshToken())) {
          throw new InvalidRefreshTokenException("refresh token rejected by authorization server");
        }
        if ("transient-fail-refresh".equals(session.refreshToken())) {
          throw new IllegalStateException("Keycloak unreachable");
        }
        if ("expired-after-refresh".equals(session.refreshToken())) {
          // Simulates the race: refresh succeeded but the session's absolute
          // ceiling crossed during the network call. The refreshed record's
          // absoluteExpiresAt is now in the past, so refreshed.nextTtl()
          // returns Duration.ZERO.
          return new SessionRecord(
              "refreshed-token",
              "rotated-refresh-token",
              session.idToken(),
              Instant.now().plusSeconds(300),
              Instant.now().plusSeconds(1800),
              session.createdAt(),
              Instant.now().minusSeconds(1),
              session.claims());
        }
        return new SessionRecord(
            "refreshed-token",
            "rotated-refresh-token",
            session.idToken(),
            Instant.now().plusSeconds(300),
            Instant.now().plusSeconds(1800),
            session.createdAt(),
            session.absoluteExpiresAt(),
            session.claims());
      }
    }
  }

}
