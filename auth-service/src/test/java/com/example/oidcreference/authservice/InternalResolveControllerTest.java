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
 * Coverage for the POST {@code /internal/resolve} contract from SPEC-0001
 * §7.1 (the phantom-token session resolution endpoint). The gateway holds
 * only the opaque sid and introspects it here to obtain the access token it
 * injects upstream — resolve does lookup, an idle-TTL slide (this call
 * represents real {@code /api} activity), and a refresh when the access
 * token is near expiry, then returns the current valid token.
 *
 * <p>Uses {@code @SpringBootTest} so the full Resource-Server filter chain
 * (Order 1) is exercised end-to-end. The {@code jwt()} post-processor
 * installs a pre-built {@code Jwt} principal, bypassing the real
 * {@link JwtDecoder} while still letting the controller observe the
 * audience and {@code azp} claims defensively.
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
class InternalResolveControllerTest {

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
  void resolveFailsWithoutBearer() throws Exception {
    // The Order-1 chain has oauth2ResourceServer with anyRequest authenticated;
    // anonymous calls are rejected at the filter, never reaching the handler.
    mockMvc.perform(post("/internal/resolve")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void resolveFailsWithWrongAudience() throws Exception {
    mockMvc.perform(post("/internal/resolve")
            .with(jwt().jwt(j -> j
                .audience(List.of("other-api"))
                .claim("azp", EXPECTED_CLIENT_ID)))
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void resolveFailsWithoutMatchingClientId() throws Exception {
    // azp = the Auth Service's own client_id, not the API Gateway's; a resolve
    // request can only legitimately come from the Gateway's CC identity.
    mockMvc.perform(post("/internal/resolve")
            .with(jwt().jwt(j -> j
                .audience(List.of(EXPECTED_AUDIENCE))
                .claim("azp", "oidc-reference-auth")))
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"sid-anything\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void resolveReturns400WhenSidMissing(CapturedOutput output) throws Exception {
    mockMvc.perform(post("/internal/resolve")
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
  void resolveReturns404WhenSessionMissing(CapturedOutput output) throws Exception {
    mockMvc.perform(post("/internal/resolve")
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
  void resolveReturnsCurrentAccessTokenWhenFresh() throws Exception {
    // Access token has > 60 s remaining; resolve must NOT call the refresh
    // client, and it returns the CURRENT access token verbatim (snake_case
    // body, the headline change vs the old refresh endpoint which returned
    // only timestamps and made the gateway re-read the store).
    String sid = "sid-still-fresh";
    SessionRecord fresh = new SessionRecord(
        "still-fresh-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(600),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, fresh);

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        // SPEC-0001 §7.1: the gateway (Lua, case-sensitive) consumes
        // `access_token` verbatim; camelCase would be a silent contract break.
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"access_token\"")))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("still-fresh-access")))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"access_token_expires_at\"")))
        .andExpect(content().string(org.hamcrest.Matchers.not(
            org.hamcrest.Matchers.containsString("\"accessToken\""))));

    verify(tokenRefreshClient.delegate(), never()).refresh(any());
    SessionRecord untouched = decodeSession(sid);
    assertThat(untouched.accessToken()).isEqualTo("still-fresh-access");
    assertThat(untouched.refreshToken()).isEqualTo("refresh-token-1");
  }

  @Test
  void resolveSlidesIdleTtlAsApiActivity() throws Exception {
    // resolve represents a real /api call, so it slides the idle window (the
    // slide that used to live in the gateway's Lua EXPIRE). Seed a short TTL,
    // resolve, and assert the TTL grew toward the configured idle. (/auth/me
    // is a non-extending liveness probe and does NOT slide — proven by the
    // C9 conformance gate.)
    String sid = "sid-slide";
    SessionRecord fresh = new SessionRecord(
        "fresh-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(600),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    // Deliberately short initial TTL so a slide is observable.
    stateStore.put("sess:" + sid, TestBeans.JSON.encode(fresh), Duration.ofSeconds(5));

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk());

    assertThat(stateStore.expireCalls())
        .as("resolve must slide the idle TTL on a fresh session")
        .isGreaterThanOrEqualTo(1);
    assertThat(stateStore.ttl("sess:" + sid))
        .as("idle window slid well past the 5s seed toward the configured idle")
        .isGreaterThan(Duration.ofSeconds(60));
  }

  @Test
  void resolveRefreshesAndRotatesSidWhenExpiring(CapturedOutput output) throws Exception {
    // Access token expires in 10 s — inside the 60 s window — so resolve
    // refreshes AND rotates the sid (A6): sess:{old} is gone, the refreshed
    // session lives under the new sid the response hands back as rotated_sid.
    String sid = "sid-expiring";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    var result = mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("refreshed-token")))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"rotated_sid\"")))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"rotated_sid_max_age\"")))
        .andReturn();

    assertThat(tokenRefreshClient.refreshCalls()).isEqualTo(1);

    // A6: the old key is gone; the refreshed session lives under the rotated sid.
    @SuppressWarnings("unchecked")
    Map<String, Object> body =
        TestBeans.JSON.decode(result.getResponse().getContentAsString(), Map.class);
    String newSid = (String) body.get("rotated_sid");
    assertThat(newSid).isNotNull().isNotBlank().isNotEqualTo(sid);
    assertThat(stateStore.get("sess:" + sid)).as("old session key deleted on rotation").isEmpty();
    SessionRecord rotated = decodeSession(newSid);
    assertThat(rotated.accessToken()).isEqualTo("refreshed-token");
    assertThat(rotated.refreshToken()).isEqualTo("rotated-refresh-token");

    // The breadcrumb forwards an in-flight old-sid request to the new session.
    assertThat(stateStore.get("rotated:" + sid)).contains(newSid);

    assertThat(output.getOut())
        .contains("event=refresh_succeeded")
        .contains("status=200")
        .contains("reason=ok");
  }

  @Test
  void resolveFollowsRotationBreadcrumbForInFlightOldSid() throws Exception {
    // A6: after a rotation, a request still presenting the OLD sid (a concurrent
    // call that was already in flight) must NOT lose its session. The
    // rotated:{old} breadcrumb forwards it to the new session and returns
    // rotated_sid so the gateway switches the browser to the new cookie. No
    // second refresh — the new session is already fresh.
    String oldSid = "sid-old";
    String newSid = "sid-new";
    SessionRecord fresh = new SessionRecord(
        "fresh-access", "fresh-refresh", "id-token-1",
        Instant.now().plusSeconds(300), Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(newSid, fresh);
    stateStore.put("rotated:" + oldSid, newSid, Duration.ofSeconds(30));

    var result = mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + oldSid + "\"}"))
        .andExpect(status().isOk())
        .andExpect(content().string(org.hamcrest.Matchers.containsString("fresh-access")))
        .andReturn();

    assertThat(tokenRefreshClient.refreshCalls()).isEqualTo(0);
    @SuppressWarnings("unchecked")
    Map<String, Object> body =
        TestBeans.JSON.decode(result.getResponse().getContentAsString(), Map.class);
    assertThat(body.get("rotated_sid")).isEqualTo(newSid);
  }

  @Test
  void resolveReturns404WhenBreadcrumbPointsToAGoneSession(CapturedOutput output)
      throws Exception {
    // A6 breadcrumb branch (resolveViaBreadcrumb, raw.isEmpty): rotated:{old}
    // exists, but the forwarded sess:{new} is itself gone — a concurrent logout
    // deleted it, or its grace window outlived the session. The breadcrumb must
    // NOT manufacture a session; resolveViaBreadcrumb returns null and the
    // endpoint 404s, exactly as a genuinely missing session. No refresh, no slide.
    String oldSid = "sid-old-gone";
    String newSid = "sid-new-gone";
    stateStore.put("rotated:" + oldSid, newSid, Duration.ofSeconds(30));
    // sess:{newSid} intentionally NOT seeded.

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + oldSid + "\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(tokenRefreshClient.refreshCalls())
        .as("the breadcrumb path never refreshes").isZero();
    assertThat(stateStore.expireCalls())
        .as("a gone forwarded session must not be slid").isZero();
    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("status=404")
        .contains("reason=no_such_session");
  }

  @Test
  void resolveReturns404WhenBreadcrumbPointsToAnAbsoluteExpiredSession(CapturedOutput output)
      throws Exception {
    // A6 breadcrumb branch (resolveViaBreadcrumb, absoluteExpired): rotated:{old}
    // forwards to sess:{new}, but that session is already past its absolute
    // ceiling. The breadcrumb must not resurrect a session the absolute-TTL
    // ceiling has ended — return null -> 404, with NO idle slide and NO token,
    // even though the access token itself is still fresh.
    String oldSid = "sid-old-expired";
    String newSid = "sid-new-expired";
    SessionRecord pastCeiling = new SessionRecord(
        "fresh-access",
        "fresh-refresh",
        "id-token-1",
        Instant.now().plusSeconds(300),      // access token still fresh...
        Instant.now().plusSeconds(1800),
        Instant.now().minusSeconds(36000),   // createdAt long ago
        Instant.now().minusSeconds(60),      // ...but the absolute ceiling is past
        Instant.now().minusSeconds(36000),
        Map.of("sub", "alice"));
    storeSession(newSid, pastCeiling);
    stateStore.put("rotated:" + oldSid, newSid, Duration.ofSeconds(30));

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + oldSid + "\"}"))
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(tokenRefreshClient.refreshCalls()).isZero();
    assertThat(stateStore.expireCalls())
        .as("an absolute-expired forwarded session must not be slid (returns before the slide)")
        .isZero();
    assertThat(output.getOut())
        .contains("event=refresh_rejected")
        .contains("status=404")
        .contains("reason=no_such_session");
  }

  @Test
  void oldSidIsDeadOnceTheRotationGraceBreadcrumbExpires() throws Exception {
    // A6 / N4 security bound (C1): a once-observed (or stolen) OLD sid must stop
    // resolving once the rotation grace breadcrumb expires — it must NOT keep
    // forwarding to the live new session for the absolute lifetime. Rotate, prove
    // the old sid still resolves WHILE the breadcrumb lives (the in-flight grace),
    // then simulate ROTATION_GRACE elapsing (delete rotated:{old}) and assert the
    // old sid 404s while the new session is untouched. Without this, a breadcrumb
    // accidentally set to the absolute ceiling would silently re-open the exact
    // fixation hole A6 closed, and nothing else would catch it.
    String sid = "sid-grace";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    // First resolve refreshes + rotates; capture the new sid and the breadcrumb.
    var rotated = mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk())
        .andReturn();
    @SuppressWarnings("unchecked")
    Map<String, Object> body =
        TestBeans.JSON.decode(rotated.getResponse().getContentAsString(), Map.class);
    String newSid = (String) body.get("rotated_sid");
    assertThat(stateStore.get("rotated:" + sid))
        .as("breadcrumb present during the grace window").contains(newSid);
    // Pin the grace VALUE, not just its presence: the breadcrumb TTL must be the
    // short rotation grace (~10s / ROTATION_GRACE), NOT the idle (1800s) or
    // absolute (28800s) session TTL. Without this the test would still pass if
    // ROTATION_GRACE were widened to the absolute ceiling — the exact regression
    // it names — because the hand-deleted breadcrumb below masks the TTL.
    assertThat(stateStore.ttl("rotated:" + sid))
        .as("the old sid must die within the SHORT rotation grace, not live for hours")
        .isPositive()
        .isLessThanOrEqualTo(Duration.ofSeconds(10));

    // While the breadcrumb lives, an in-flight request on the old sid still resolves.
    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isOk());

    // Simulate ROTATION_GRACE elapsing: the breadcrumb TTL expires.
    stateStore.delete("rotated:" + sid);

    // Now the old sid is dead — no breadcrumb to forward, the old session is gone.
    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isNotFound());

    // The live new session is unaffected by the old sid dying.
    assertThat(stateStore.get("sess:" + newSid))
        .as("the rotated-to session stays alive").isPresent();
  }

  @Test
  void concurrentLogoutDuringRefreshIsNotResurrectedByRotation(CapturedOutput output)
      throws Exception {
    // Review FINDING 2: a back-channel logout that clears idp_sid mid-refresh must
    // WIN — the rotation must not rebuild the indexes and resurrect the revoked
    // session. The session has a real IdP sid claim, so the rekey CAS engages;
    // idp_sid:{X} is absent (simulating the logout already cleared it), so the
    // CAS fails -> the controller fails closed (409) and leaves no session behind.
    String sid = "sid-logout-race";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        jwtWithSid("kc-session-race"),
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);
    // Note: idp_sid:kc-session-race is intentionally NOT seeded -> CAS(expected=sid)
    // on an absent key returns false, exactly as if a concurrent logout deleted it.

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isConflict());

    assertThat(tokenRefreshClient.refreshCalls()).isEqualTo(1);
    // Neither the old session nor a resurrected new session survives, and the
    // breadcrumb was cleaned up.
    assertThat(stateStore.get("sess:" + sid)).as("old session moved then undone").isEmpty();
    assertThat(stateStore.get("rotated:" + sid)).as("breadcrumb cleaned up").isEmpty();
    assertThat(stateStore.keys().stream().anyMatch(k -> k.startsWith("sess:")))
        .as("no resurrected sess:* key").isFalse();
    assertThat(output.getOut()).contains("session_invalidated_during_refresh");
  }

  @Test
  void resolveReturns409OnInvalidRefreshToken(CapturedOutput output) throws Exception {
    String sid = "sid-reused";
    SessionRecord reused = new SessionRecord(
        "stale-access",
        "reused-refresh-token",  // sentinel — the recording client throws on this
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, reused);

    mockMvc.perform(post("/internal/resolve")
            .with(validApiGatewayBearer())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"sid\":\"" + sid + "\"}"))
        .andExpect(status().isConflict())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    assertThat(stateStore.get("sess:" + sid)).isEmpty();
    assertThat(output.getOut())
        .contains("sid_hash=")
        .doesNotContain("sid=" + sid)
        .doesNotContain("sid=" + sid + " ");
    // C13: invalid_grant cannot be attributed to reuse at the RP. The label
    // MUST stay honest, never asserted as proven reuse.
    assertThat(output.getOut())
        .contains("event=refresh_token_rejected")
        .doesNotContain("event=refresh_token_reuse")
        .doesNotContain("reuse detected");
  }

  @Test
  void resolveReturns404AndSkipsKeycloakWhenRefreshTokenExpired(CapturedOutput output)
      throws Exception {
    // C15: refresh is due (access token inside the window) but the refresh
    // token is already expired. Short-circuit to a clean "session ended" 404
    // with no upstream call and no rejection alarm.
    String sid = "sid-refresh-expired";
    SessionRecord expired = new SessionRecord(
        "stale-access",
        "would-succeed-if-called",        // NOT a throw sentinel — guard must skip it
        "id-token-1",
        Instant.now().plusSeconds(10),    // inside the refresh window
        Instant.now().minusSeconds(60),   // refresh token already expired
        Map.of("sub", "alice"));
    storeSession(sid, expired);

    mockMvc.perform(post("/internal/resolve")
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
  void resolveReturns502OnKeycloakTransientFailure(CapturedOutput output) throws Exception {
    String sid = "sid-transient";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "transient-fail-refresh",  // sentinel — the recording client throws RuntimeException
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    mockMvc.perform(post("/internal/resolve")
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
  void resolveDeletesSessionWhenRefreshedRecordCrossesAbsoluteTtl(CapturedOutput output)
      throws Exception {
    // Race: the absolute ceiling crosses during the upstream refresh network
    // call, so refreshed.nextTtl() is ZERO. The controller MUST delete and
    // 404, never write with Duration.ZERO.
    String sid = "sid-crossed-absolute-during-refresh";
    SessionRecord nearlyExpired = new SessionRecord(
        "stale-access",
        "expired-after-refresh",                  // sentinel
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Instant.now().minusSeconds(60),
        Instant.now().plusSeconds(60),            // valid now, but refresh returns past
        Instant.now().minusSeconds(60),
        Map.of("sub", "alice"));
    storeSession(sid, nearlyExpired);

    mockMvc.perform(post("/internal/resolve")
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
  void resolveDoesNotResurrectASessionDeletedDuringTheUpstreamCall(CapturedOutput output)
      throws Exception {
    // Resurrection race: a concurrent logout DELs sess:{sid} mid-refresh. The
    // post-refresh write must be conditional — discard the rotated tokens, do
    // not recreate a session the user just logged out of.
    String sid = "sid-deleted-during-refresh";
    SessionRecord expiring = new SessionRecord(
        "stale-access",
        "refresh-token-1",
        "id-token-1",
        Instant.now().plusSeconds(10),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));
    storeSession(sid, expiring);

    tokenRefreshClient.runDuringRefresh(() -> stateStore.delete("sess:" + sid));

    mockMvc.perform(post("/internal/resolve")
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
  void concurrentResolveCallsForSameSidSerializeOnLock() throws Exception {
    // Two simultaneous resolves on an expiring sid — the per-session lock plus
    // the under-lock re-read collapse them to exactly ONE upstream refresh.
    // The second caller acquires the lock after the first wrote the rotated
    // tokens, sees expiry now outside the window, and returns 200. This is the
    // single-instance serialization property the distributed-lock note guards.
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
      Future<Integer> first = executor.submit(() -> mockMvc.perform(post("/internal/resolve")
              .with(validApiGatewayBearer())
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"sid\":\"" + sid + "\"}"))
          .andReturn().getResponse().getStatus());
      assertThat(tokenRefreshClient.awaitRefreshStarted())
          .as("first request should reach the refresh client")
          .isTrue();
      Future<Integer> second = executor.submit(() -> mockMvc.perform(post("/internal/resolve")
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

  // A minimal parseable JWT carrying a `sid` claim, so SessionIndexes.idpSid()
  // extracts the IdP session id that the rotation rekey CAS keys on.
  private static String jwtWithSid(String idpSid) {
    var enc = java.util.Base64.getUrlEncoder().withoutPadding();
    var utf8 = java.nio.charset.StandardCharsets.UTF_8;
    String header = enc.encodeToString("{\"alg\":\"HS256\"}".getBytes(utf8));
    String payload = enc.encodeToString(("{\"sid\":\"" + idpSid + "\"}").getBytes(utf8));
    return header + "." + payload + ".sig";
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
   * Recording refresh client: counts upstream calls, supports a pause/release
   * latch dance for the contention test, runs a mid-refresh action to model a
   * concurrent logout, and triggers the §7.1 failure paths via sentinel
   * refresh-token values.
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
          return new SessionRecord(
              "refreshed-token",
              "rotated-refresh-token",
              session.idToken(),
              Instant.now().plusSeconds(300),
              Instant.now().plusSeconds(1800),
              session.createdAt(),
              Instant.now().minusSeconds(1),
              Instant.now(),
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
            Instant.now(),
            session.claims());
      }
    }
  }
}
