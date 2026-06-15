package com.example.oidcreference.authservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Phantom-token session resolution. The API Gateway holds only the opaque
 * sid; it introspects it here to obtain the access token it injects upstream.
 * This is the single place that reads the session store on the bearer-
 * injection path — the gateway has no Redis client and no knowledge of the
 * {@code sess:{sid}} schema (SPEC-0001 §7.1).
 *
 * <p>{@code resolve} represents a real {@code /api} request, so it slides the
 * idle window. The common case (token still fresh) is lock-free: read, slide,
 * return the current token. Only a near-expiry refresh takes the per-session
 * lock, exactly as the old {@code /internal/refresh} did.
 */
@RestController
@RequestMapping("/internal")
class InternalResolveController {
  private static final Logger log = LoggerFactory.getLogger(InternalResolveController.class);

  // Forward-pointer breadcrumb left when a refresh rotates the sid (A6): maps the
  // OLD sid -> the new sid for a short grace window, so a concurrent request that
  // was already in flight with the old cookie still resolves (to the new session)
  // instead of losing its session. Also bounds how long a stolen old sid remains
  // usable after a rotation — to this window, not the absolute ceiling.
  //
  // The only legitimate consumer is a request that RACED the rotation, so the
  // window need only cover the in-flight resolve budget (~5s read timeout), not
  // 30s (N4): kept at 10s to cut the post-rotation replay surface ~3x while
  // staying comfortably above the resolve round-trip. See SECURITY.md S-5.
  private static final String ROTATED_PREFIX = "rotated:";
  private static final Duration ROTATION_GRACE = Duration.ofSeconds(10);

  private final StateStore stateStore;
  private final JsonCodec json;
  private final TokenRefreshClient tokenRefreshClient;
  private final AuthProperties props;
  private final SessionIndexes sessionIndexes;
  // Serializes concurrent refreshes for one sid so they collapse to a single
  // upstream grant. A RefreshLock interface (default InProcessRefreshLock, a
  // per-JVM lock) rather than a hardcoded map, so the single-instance lock is a
  // swap — not a rewrite of this method — for a horizontally-scaled deployment.
  // The in-process limitation and the distributed swap are documented on
  // RefreshLock / InProcessRefreshLock.
  private final RefreshLock refreshLock;

  InternalResolveController(
      StateStore stateStore,
      JsonCodec json,
      TokenRefreshClient tokenRefreshClient,
      AuthProperties props,
      RefreshLock refreshLock,
      SessionIndexes sessionIndexes) {
    this.stateStore = stateStore;
    this.json = json;
    this.tokenRefreshClient = tokenRefreshClient;
    this.props = props;
    this.refreshLock = refreshLock;
    this.sessionIndexes = sessionIndexes;
  }

  @PostMapping(path = "/resolve", consumes = MediaType.APPLICATION_JSON_VALUE)
  ResponseEntity<?> resolve(
      @RequestBody ResolveRequest req,
      @AuthenticationPrincipal Jwt callerJwt,
      HttpServletRequest request) {
    if (callerJwt == null) {
      SecurityAudit.event(request, 401, "auth_denied", "missing_bearer");
      return problem(401, "missing bearer token");
    }
    if (!hasExpectedAudience(callerJwt, props.internalAudience())
        || !hasExpectedCaller(callerJwt, props.gatewayClientId())) {
      SecurityAudit.event(request, 401, "auth_denied", "bearer_audience_or_client_mismatch");
      return problem(401, "bearer token audience or client mismatch");
    }
    if (req == null || req.sid() == null || req.sid().isBlank()) {
      SecurityAudit.event(request, 400, "refresh_rejected", "missing_sid");
      return problem(400, "missing sid");
    }

    var sessKey = "sess:" + req.sid();
    Optional<String> raw = stateStore.get(sessKey);
    if (raw.isEmpty()) {
      // The sid may have rotated under a concurrent refresh — follow the
      // breadcrumb to the new session before giving up.
      var forwarded = resolveViaBreadcrumb(req.sid(), request);
      if (forwarded != null) {
        return forwarded;
      }
      SecurityAudit.event(request, 404, "refresh_rejected", "no_such_session");
      return problem(404, "no such session");
    }
    Optional<SessionRecord> decoded = decodeSessionOrDelete(req.sid(), raw.get());
    if (decoded.isEmpty()) {
      SecurityAudit.event(request, 404, "refresh_rejected", "corrupt_session");
      return problem(404, "session is unusable");
    }
    var session = decoded.get();

    // Absolute-TTL ceiling. nextTtl() returns Duration.ZERO once the ceiling is
    // past, which would make a write/slide evict the key. Refuse here instead,
    // with the same shape AuthController uses on /auth/me.
    if (session.absoluteExpired()) {
      SecurityAudit.event(
          request, 404, "refresh_rejected", "session_absolute_expired", subjectClaim(session));
      stateStore.delete(sessKey);
      return problem(404, "session past absolute TTL");
    }

    // Hot path: token still fresh. Lock-free — slide the idle window and return
    // the current access token. No per-request audit (this fires on every /api
    // call; a security-audit line per request would be pure noise).
    if (!session.requiresRefresh(props.sessionRefreshWindow())) {
      slideIdle(sessKey, session);
      return ok(session);
    }

    // Refresh due: serialize under the per-session lock so concurrent resolves
    // on one sid collapse to a single upstream refresh (the loser re-reads
    // sess:{sid} under the lock and finds the rotated token).
    //
    // refreshUnderLock maps its own outcomes (invalid_grant 409, upstream 502,
    // ...) and RETURNS them, so the only throwable out of withLock is a lock
    // INFRASTRUCTURE failure: the distributed lock failing to acquire within
    // max-wait, a store error, or an interrupt — which it throws to fail closed
    // rather than refresh unguarded (the in-process default never throws here).
    // Map it to a deliberate, audited, no-store transient 503 (not an unmapped
    // 500) so the gateway keeps the session cookie and retries.
    try {
      return refreshLock.withLock(req.sid(), () -> refreshUnderLock(req.sid(), sessKey, request));
    } catch (RefreshLockUnavailableException e) {
      log.warn("refresh lock unavailable; failing closed (transient) for sid_hash={}",
          SecurityAudit.hashSid(req.sid()));
      SecurityAudit.event(request, 503, "refresh_failed", "refresh_lock_unavailable");
      return transientProblem(503, "refresh temporarily unavailable, retry");
    }
  }

  // Runs while holding the per-session refresh lock. Re-reads sess:{sid} — a
  // concurrent caller may have refreshed it, or a logout deleted it, while we
  // waited for the lock — then performs the refresh-token grant and the
  // conditional write.
  private ResponseEntity<?> refreshUnderLock(
      String sid, String sessKey, HttpServletRequest request) {
    Optional<String> raw = stateStore.get(sessKey);
    if (raw.isEmpty()) {
      // A concurrent caller rotated this sid while we waited for the lock — the
      // old key is gone. Follow the breadcrumb to the rotated session.
      var forwarded = resolveViaBreadcrumb(sid, request);
      if (forwarded != null) {
        return forwarded;
      }
      SecurityAudit.event(request, 404, "refresh_rejected", "no_such_session");
      return problem(404, "no such session");
    }
    Optional<SessionRecord> decoded = decodeSessionOrDelete(sid, raw.get());
    if (decoded.isEmpty()) {
      SecurityAudit.event(request, 404, "refresh_rejected", "corrupt_session");
      return problem(404, "session is unusable");
    }
    var session = decoded.get();
    if (session.absoluteExpired()) {
      SecurityAudit.event(
          request, 404, "refresh_rejected", "session_absolute_expired", subjectClaim(session));
      stateStore.delete(sessKey);
      return problem(404, "session past absolute TTL");
    }

    // Another caller may have refreshed while we waited for the lock; the
    // token is now fresh. Slide and return it, no second upstream call. This
    // is what collapses concurrent resolves on one sid to a single refresh.
    if (!session.requiresRefresh(props.sessionRefreshWindow())) {
      slideIdle(sessKey, session);
      return ok(session);
    }

    // A refresh is due, but the refresh token is already past its own expiry —
    // either the IdP-supplied refresh_expires_in, or the optional
    // app.max-refresh-token-age ceiling (which bounds refresh-token age even
    // when the IdP omits refresh_expires_in). Sending it to Keycloak would only
    // earn invalid_grant — a predictable, routine session end. Short-circuit to
    // a clean "session ended" 404 with no upstream call and a non-alarming
    // audit reason.
    if (session.refreshTokenExpired(props.maxRefreshTokenAge())) {
      SecurityAudit.event(
          request, 404, "refresh_rejected", "refresh_token_expired", subjectClaim(session));
      stateStore.delete(sessKey);
      return problem(404, "session ended, re-login required");
    }

    SessionRecord refreshed;
    try {
      refreshed = tokenRefreshClient.refresh(session);
    } catch (InvalidRefreshTokenException e) {
      // Keycloak invalid_grant. RFC 6749 §5.2 collapses many causes (expired
      // or revoked refresh token, SSO max lifespan, AND genuine reuse) under
      // one code, distinguishable only in the free-text error_description we
      // do not parse. The fail-closed outcome (invalidate + 409) is correct;
      // the label stays honest. sid is a session credential — never log it
      // raw; hash it the same way SecurityAudit hashes sub for correlation.
      log.warn("refresh rejected by authorization server (invalid_grant); "
          + "session invalidated for sid_hash={}", SecurityAudit.hashSid(sid));
      SecurityAudit.event(
          request, 409, "refresh_token_rejected", "session_invalidated", subjectClaim(session));
      stateStore.delete(sessKey);
      return problem(409, "refresh token rejected, session invalidated");
    } catch (RuntimeException e) {
      SecurityAudit.event(
          request, 502, "refresh_failed", "authorization_server_unreachable",
          subjectClaim(session));
      return problem(502, "refresh failed at authorization server");
    }

    Duration nextTtl = refreshed.nextTtl(props.sessionIdleTtl());
    if (nextTtl.isZero() || nextTtl.isNegative()) {
      // Pre-refresh absoluteExpired() passed, but the upstream network call
      // took long enough to cross the absolute ceiling. Writing Duration.ZERO
      // has backend-defined semantics; fail closed instead.
      SecurityAudit.event(
          request, 404, "refresh_rejected", "session_absolute_expired_post_refresh",
          subjectClaim(refreshed));
      stateStore.delete(sessKey);
      return problem(404, "session past absolute TTL");
    }
    // Rotate the sid on refresh (A6): a once-observed sid must not stay valid
    // across token rotations. Mint sid', then ATOMICALLY move sess:{sid} ->
    // sess:{sid'} only if the old key still exists. A concurrent logout (which
    // does NOT take this lock) can DEL the session during the upstream
    // round-trip; rotateIfPresent's EXISTS-gate fails closed in that case rather
    // than resurrecting it — the same property the old SET XX gave.
    String newSid = CryptoSupport.randomUrlToken(32);
    // Move sess:{sid} -> sess:{sid'} AND write the rotated:{sid}->sid' breadcrumb
    // ATOMICALLY (N3). The breadcrumb lets a concurrent request still in flight
    // with the OLD sid forward to sid' for a short grace window instead of losing
    // its session; folding it into the move closes the revocation window where a
    // subject-wide logout could see sess:{sid'} without a breadcrumb to follow.
    // The EXISTS-gate still fails closed if a logout DEL'd sess:{sid} first.
    if (!stateStore.rotateIfPresent(
        sessKey, "sess:" + newSid, json.encode(refreshed), nextTtl,
        ROTATED_PREFIX + sid, newSid, ROTATION_GRACE)) {
      SecurityAudit.event(
          request, 404, "refresh_rejected", "session_deleted_during_refresh",
          subjectClaim(refreshed));
      return problem(404, "session ended, re-login required");
    }
    // Repoint the secondary indexes (idp_sid / sub_sessions / logout_hint) at sid'.
    // The idp_sid repoint is a CAS: if a concurrent back-channel logout cleared it
    // during the IdP round-trip, the session was revoked — undo the rotation
    // (delete the new session + breadcrumb) and fail closed, rather than let the
    // rebuilt indexes resurrect a logged-out session.
    if (!sessionIndexes.rotate(sid, newSid, refreshed)) {
      stateStore.delete("sess:" + newSid);
      stateStore.delete(ROTATED_PREFIX + sid);
      SecurityAudit.event(
          request, 409, "refresh_token_rejected", "session_invalidated_during_refresh",
          subjectClaim(refreshed));
      return problem(409, "session ended, re-login required");
    }
    SecurityAudit.event(request, 200, "refresh_succeeded", "ok", subjectClaim(refreshed));
    return okRotated(refreshed, newSid);
  }

  // Slide the idle window on the live key. This is the slide that used to be a
  // Lua EXPIRE in the gateway; it now lives with the sole store reader. EXPIRE
  // on a key a concurrent logout just removed is a harmless no-op.
  private void slideIdle(String sessKey, SessionRecord session) {
    Duration nextTtl = session.nextTtl(props.sessionIdleTtl());
    if (nextTtl.isZero() || nextTtl.isNegative()) {
      // absoluteExpired() was already checked above, so this is defensive.
      stateStore.delete(sessKey);
      return;
    }
    stateStore.expire(sessKey, nextTtl);
  }

  private ResponseEntity<ResolveResponse> ok(SessionRecord session) {
    // Explicit no-store: this body carries the live access token. The Order-1
    // /internal chain inherits Spring Security's default cache-control writer,
    // but stating it here keeps the no-store with the token-bearing response
    // itself (matching AuthController) — so it survives a chain reconfig or these
    // responses being served off this chain.
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .body(new ResolveResponse(session.accessToken(), session.expiresAt(), null, null, null));
  }

  // The sid rotated on this resolve: hand the new sid back, plus the cookie's
  // max-age (remaining absolute lifetime) AND a fresh signed CSRF token bound to
  // the new sid. The signed-CSRF HMAC covers value:sid, so a rotated sid with the
  // OLD csrf token would 403 every subsequent write — the gateway re-issues BOTH
  // the __Host-sid cookie and the XSRF-TOKEN cookie. Invisible to the SPA.
  private ResponseEntity<ResolveResponse> okRotated(SessionRecord session, String rotatedSid) {
    long maxAge = Math.max(0L,
        Duration.between(Instant.now(), session.absoluteExpiresAt()).getSeconds());
    String rotatedCsrf = SignedCsrfSupport.issueToken(props.cookieSigningKey(), rotatedSid);
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .body(new ResolveResponse(
            session.accessToken(), session.expiresAt(), rotatedSid, maxAge, rotatedCsrf));
  }

  // A concurrent request may have rotated this sid (sess:{sid} -> sess:{sid'})
  // while THIS request was in flight. The rotated:{sid} breadcrumb (short grace
  // TTL) forwards us to sid': resolve sess:{sid'}, slide it, and return its token
  // tagged with rotated_sid=sid' so the gateway switches the browser to the new
  // cookie. Returns null when there is no breadcrumb (genuinely no session) or
  // the forwarded session is itself gone/expired — the caller then 404s.
  private @Nullable ResponseEntity<?> resolveViaBreadcrumb(
      String oldSid, HttpServletRequest request) {
    Optional<String> newSid = stateStore.get(ROTATED_PREFIX + oldSid);
    if (newSid.isEmpty()) {
      return null;
    }
    String newKey = "sess:" + newSid.get();
    Optional<String> raw = stateStore.get(newKey);
    if (raw.isEmpty()) {
      return null;
    }
    Optional<SessionRecord> decoded = decodeSessionOrDelete(newSid.get(), raw.get());
    if (decoded.isEmpty()) {
      stateStore.delete(ROTATED_PREFIX + oldSid);
      SecurityAudit.event(request, 404, "refresh_rejected", "corrupt_session");
      return problem(404, "session is unusable");
    }
    var session = decoded.get();
    if (session.absoluteExpired()) {
      return null;
    }
    slideIdle(newKey, session);
    return okRotated(session, newSid.get());
  }

  private Optional<SessionRecord> decodeSessionOrDelete(String sid, String raw) {
    try {
      return Optional.of(json.decode(raw, SessionRecord.class));
    } catch (RuntimeException e) {
      // A truncated write, schema drift, or manual store corruption must not
      // turn the token-bearing resolve path into a 500. Treat the record as an
      // unusable credential, evict it (including logout hints / rotation
      // breadcrumbs), and let the gateway clear the browser session on 404.
      sessionIndexes.deleteLocalSession(sid);
      return Optional.empty();
    }
  }

  // Package-private + parameterized so the configurable identity is unit-tested
  // directly (InternalRefreshIdentityCheckTest) without a Spring context.
  static boolean hasExpectedAudience(Jwt jwt, String expectedAudience) {
    List<String> aud = jwt.getAudience();
    return aud != null && aud.contains(expectedAudience);
  }

  static boolean hasExpectedCaller(Jwt jwt, String expectedClientId) {
    boolean found = false;
    // Microsoft Entra ID v1 access tokens identify the calling application
    // with appid. Entra v2 and most OIDC providers use azp/client_id instead.
    // If a token contains multiple identity claims, every present value must
    // agree; a matching fallback must not mask a conflicting primary claim.
    for (String claimName : List.of("azp", "client_id", "appid")) {
      String value = jwt.getClaimAsString(claimName);
      if (value != null) {
        found = true;
        if (!expectedClientId.equals(value)) {
          return false;
        }
      }
    }
    return found;
  }

  private static ResponseEntity<ProblemDetail> problem(int status, String detail) {
    var pd = ProblemDetail.forStatus(status);
    pd.setTitle(titleFor(status));
    pd.setDetail(detail);
    pd.setType(URI.create("about:blank"));
    // Explicit no-store: these are token/session-adjacent error responses on the
    // resolve path. The Order-1 /internal chain inherits Spring Security's default
    // cache-control writer, but stating it here keeps the whole resolve contract
    // (success, transient, AND error) local to the endpoint and consistent.
    return ResponseEntity.status(status)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .header("Cache-Control", "no-store")
        .body(pd);
  }

  // Like problem(), but for a transient/retryable outcome (the refresh lock could
  // not be acquired): explicit Cache-Control: no-store — a token-adjacent error
  // response must never be cached — plus a short Retry-After to invite the
  // gateway's retry while it keeps the session cookie.
  private static ResponseEntity<ProblemDetail> transientProblem(int status, String detail) {
    var pd = ProblemDetail.forStatus(status);
    pd.setTitle(titleFor(status));
    pd.setDetail(detail);
    pd.setType(URI.create("about:blank"));
    return ResponseEntity.status(status)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .header("Cache-Control", "no-store")
        .header("Retry-After", "1")
        .body(pd);
  }

  private static String titleFor(int status) {
    return switch (status) {
      case 400 -> "Bad Request";
      case 401 -> "Unauthorized";
      case 404 -> "Not Found";
      case 409 -> "Conflict";
      case 502 -> "Bad Gateway";
      case 503 -> "Service Unavailable";
      default -> "Error";
    };
  }

  private static @Nullable String subjectClaim(@Nullable SessionRecord session) {
    if (session == null || session.claims() == null) {
      return null;
    }
    Object sub = session.claims().get("sub");
    return sub == null ? null : sub.toString();
  }

  record ResolveRequest(String sid) {}

  // Wire shape MUST be snake_case per SPEC-0001 §7.1 — the API Gateway (Lua,
  // case-sensitive) reads `access_token` verbatim and injects it as the
  // upstream bearer. Java fields stay camelCase; @JsonProperty pins the wire name.
  // rotated_sid / rotated_sid_max_age are present ONLY when this resolve rotated
  // the sid (A6): the gateway then re-issues the session cookie with the new sid.
  // NON_NULL keeps the common no-rotation response byte-identical.
  @com.fasterxml.jackson.annotation.JsonInclude(
      com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
  record ResolveResponse(
      @JsonProperty("access_token") String accessToken,
      @JsonProperty("access_token_expires_at") Instant accessTokenExpiresAt,
      @JsonProperty("rotated_sid") @Nullable String rotatedSid,
      @JsonProperty("rotated_sid_max_age") @Nullable Long rotatedSidMaxAge,
      @JsonProperty("rotated_csrf") @Nullable String rotatedCsrf) {}
}
