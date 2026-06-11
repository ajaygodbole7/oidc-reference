package com.example.oidcreference.authservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

  private final StateStore stateStore;
  private final JsonCodec json;
  private final TokenRefreshClient tokenRefreshClient;
  private final AuthProperties props;
  // SINGLE-INSTANCE LOCK. Serializes concurrent refreshes for one sid within
  // THIS JVM only — a per-process ReentrantLock map, not a distributed lock.
  // Correct for the single-instance reference. With two or more Auth Service
  // instances, two of them can refresh the same session concurrently: both
  // send the same refresh token to the IdP, and with this realm's rotation +
  // reuse detection the second is rejected as invalid_grant and the session is
  // invalidated — naive horizontal scaling logs active users out. The phantom-
  // token shape puts this endpoint on the hot path (every /api call), so
  // scaling the Auth Service is more likely; the distributed lock (SET NX PX
  // refresh_lock:{sid} + compare-and-delete release) becomes a more pressing
  // production requirement. See docs/operations/production-hardening.md and
  // docs/architecture/phantom-token-session-resolution.md. Deliberately
  // in-process here, not a bug.
  private final ConcurrentHashMap<String, LockRef> locksPerSid = new ConcurrentHashMap<>();

  InternalResolveController(
      StateStore stateStore,
      JsonCodec json,
      TokenRefreshClient tokenRefreshClient,
      AuthProperties props) {
    this.stateStore = stateStore;
    this.json = json;
    this.tokenRefreshClient = tokenRefreshClient;
    this.props = props;
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
      SecurityAudit.event(request, 404, "refresh_rejected", "no_such_session");
      return problem(404, "no such session");
    }
    var session = json.decode(raw.get(), SessionRecord.class);

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

    // Refresh due: serialize under the per-session lock.
    LockRef lockRef = acquireRefreshLock(req.sid());
    Lock lock = lockRef.lock();
    lock.lock();
    try {
      raw = stateStore.get(sessKey);
      if (raw.isEmpty()) {
        SecurityAudit.event(request, 404, "refresh_rejected", "no_such_session");
        return problem(404, "no such session");
      }
      session = json.decode(raw.get(), SessionRecord.class);
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

      // A refresh is due, but the refresh token is already past its own expiry.
      // Sending it to Keycloak would only earn invalid_grant — a predictable,
      // routine session end. Short-circuit to a clean "session ended" 404 with
      // no upstream call and a non-alarming audit reason.
      if (session.refreshTokenExpired()) {
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
            + "session invalidated for sid_hash={}", SecurityAudit.hashSid(req.sid()));
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
      // Conditional write: persist the rotated tokens only if sess:{sid} still
      // exists. A concurrent logout (which does NOT take this lock) can DEL the
      // session during the upstream round-trip; an unconditional SET would
      // resurrect it. SET ... XX makes the write a no-op and we fail closed.
      if (!stateStore.putIfPresent(sessKey, json.encode(refreshed), nextTtl)) {
        SecurityAudit.event(
            request, 404, "refresh_rejected", "session_deleted_during_refresh",
            subjectClaim(refreshed));
        return problem(404, "session ended, re-login required");
      }
      SecurityAudit.event(request, 200, "refresh_succeeded", "ok", subjectClaim(refreshed));
      return ok(refreshed);
    } finally {
      lock.unlock();
      releaseRefreshLock(req.sid(), lockRef);
    }
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
    return ResponseEntity.ok(new ResolveResponse(session.accessToken(), session.expiresAt()));
  }

  private LockRef acquireRefreshLock(String sid) {
    return locksPerSid.compute(sid, (ignored, existing) -> {
      if (existing == null) {
        return new LockRef();
      }
      existing.retain();
      return existing;
    });
  }

  private void releaseRefreshLock(String sid, LockRef lockRef) {
    locksPerSid.computeIfPresent(sid, (ignored, existing) -> {
      if (existing != lockRef) {
        return existing;
      }
      return existing.release() == 0 ? null : existing;
    });
  }

  // Package-private + parameterized so the configurable identity is unit-tested
  // directly (InternalRefreshIdentityCheckTest) without a Spring context.
  static boolean hasExpectedAudience(Jwt jwt, String expectedAudience) {
    List<String> aud = jwt.getAudience();
    return aud != null && aud.contains(expectedAudience);
  }

  static boolean hasExpectedCaller(Jwt jwt, String expectedClientId) {
    var azp = jwt.getClaimAsString("azp");
    if (expectedClientId.equals(azp)) {
      return true;
    }
    var clientId = jwt.getClaimAsString("client_id");
    return expectedClientId.equals(clientId);
  }

  private static ResponseEntity<ProblemDetail> problem(int status, String detail) {
    var pd = ProblemDetail.forStatus(status);
    pd.setTitle(titleFor(status));
    pd.setDetail(detail);
    pd.setType(URI.create("about:blank"));
    return ResponseEntity.status(status)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .body(pd);
  }

  private static String titleFor(int status) {
    return switch (status) {
      case 400 -> "Bad Request";
      case 401 -> "Unauthorized";
      case 404 -> "Not Found";
      case 409 -> "Conflict";
      case 502 -> "Bad Gateway";
      default -> "Error";
    };
  }

  private static String subjectClaim(SessionRecord session) {
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
  record ResolveResponse(
      @JsonProperty("access_token") String accessToken,
      @JsonProperty("access_token_expires_at") Instant accessTokenExpiresAt) {}

  private static final class LockRef {
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicInteger refs = new AtomicInteger(1);

    Lock lock() {
      return lock;
    }

    void retain() {
      refs.incrementAndGet();
    }

    int release() {
      return refs.decrementAndGet();
    }
  }
}
