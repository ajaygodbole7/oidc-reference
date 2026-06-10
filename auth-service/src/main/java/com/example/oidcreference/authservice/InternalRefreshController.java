package com.example.oidcreference.authservice;

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

@RestController
@RequestMapping("/internal")
class InternalRefreshController {
  private static final Logger log = LoggerFactory.getLogger(InternalRefreshController.class);

  private final StateStore stateStore;
  private final JsonCodec json;
  private final TokenRefreshClient tokenRefreshClient;
  private final AuthProperties props;
  private final ConcurrentHashMap<String, LockRef> locksPerSid = new ConcurrentHashMap<>();

  InternalRefreshController(
      StateStore stateStore,
      JsonCodec json,
      TokenRefreshClient tokenRefreshClient,
      AuthProperties props) {
    this.stateStore = stateStore;
    this.json = json;
    this.tokenRefreshClient = tokenRefreshClient;
    this.props = props;
  }

  @PostMapping(path = "/refresh", consumes = MediaType.APPLICATION_JSON_VALUE)
  ResponseEntity<?> refresh(
      @RequestBody RefreshRequest req,
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

    LockRef lockRef = acquireRefreshLock(req.sid());
    Lock lock = lockRef.lock();
    lock.lock();
    try {
      raw = stateStore.get(sessKey);
      if (raw.isEmpty()) {
        SecurityAudit.event(request, 404, "refresh_rejected", "no_such_session");
        return problem(404, "no such session");
      }
      var session = json.decode(raw.get(), SessionRecord.class);

      // Absolute-TTL ceiling. AuthController.session() refuses sessions
      // past their hard cap on /auth/me, but the gateway calling
      // /internal/refresh has no equivalent check — and the body of
      // this method ends with stateStore.put(sessKey, ..., refreshed.
      // nextTtl()). nextTtl returns Duration.ZERO once
      // absoluteExpiresAt is past, which makes the write evict the key
      // immediately. The caller would then succeed once and 404 on
      // every subsequent call, producing a re-login loop. Refuse here
      // instead, with the same shape AuthController uses for the
      // analogous condition on /auth/me.
      if (session.absoluteExpired()) {
        SecurityAudit.event(
            request, 404, "refresh_rejected", "session_absolute_expired",
            subjectClaim(session));
        stateStore.delete(sessKey);
        return problem(404, "session past absolute TTL");
      }

      var windowToExpiry = Duration.between(Instant.now(), session.expiresAt());
      if (windowToExpiry.compareTo(props.sessionRefreshWindow()) > 0) {
        SecurityAudit.event(
            request, 200, "refresh_not_needed", "outside_refresh_window",
            subjectClaim(session));
        return ResponseEntity.ok(new RefreshResponse(Instant.now(), session.expiresAt()));
      }

      // A refresh is due, but the refresh token is already past its own
      // expiry. Sending it to Keycloak would only earn invalid_grant —
      // a predictable, routine session end, not a rejection to route through
      // the invalidation/alarm path below. Short-circuit to a clean "session
      // ended" 404 with no upstream call. Distinct, non-alarming audit reason.
      if (session.refreshTokenExpired()) {
        SecurityAudit.event(
            request, 404, "refresh_rejected", "refresh_token_expired",
            subjectClaim(session));
        stateStore.delete(sessKey);
        return problem(404, "session ended, re-login required");
      }

      SessionRecord refreshed;
      try {
        refreshed = tokenRefreshClient.refresh(session);
      } catch (InvalidRefreshTokenException e) {
        // Keycloak returned invalid_grant on the refresh grant. RFC 6749 §5.2
        // collapses many causes under this one code — refresh token expired or
        // revoked, SSO session past its max lifespan, client/user disabled, AND
        // genuine refresh-token reuse — and Keycloak only distinguishes them in
        // the free-text error_description (which we deliberately do not parse).
        // So we CANNOT attribute this to reuse at the RP. The fail-closed
        // outcome (invalidate + 409) is correct; the label must stay honest, or
        // routine long-session expiries drown the genuine reuse signal in noise.
        // sid is a session credential — never log the raw value; hash it the
        // same way SecurityAudit hashes `sub` for correlation.
        log.warn("refresh rejected by authorization server (invalid_grant); "
            + "session invalidated for sid_hash={}", SecurityAudit.hashSid(req.sid()));
        SecurityAudit.event(
            request, 409, "refresh_token_rejected", "session_invalidated",
            subjectClaim(session));
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
        // The pre-refresh absoluteExpired() check at line 95 passed, but the
        // upstream refresh call (a network round-trip to Keycloak) took long
        // enough that the session crossed its absolute ceiling while we
        // waited. Writing with Duration.ZERO has backend-defined semantics:
        // Redis rejects EX 0 outright; some Lettuce code paths drop the TTL
        // silently turning the session into a permanent key. Fail closed,
        // matching the shape the pre-refresh check uses for the analogous
        // condition.
        SecurityAudit.event(
            request, 404, "refresh_rejected", "session_absolute_expired_post_refresh",
            subjectClaim(refreshed));
        stateStore.delete(sessKey);
        return problem(404, "session past absolute TTL");
      }
      // Conditional write: only persist the rotated tokens if sess:{sid} still
      // exists. A concurrent logout / back-channel logout can DEL the session
      // during the upstream refresh round-trip above — those delete paths do
      // NOT take this per-sid lock — and an unconditional SET would resurrect a
      // session the user just terminated. SET ... XX makes the write a no-op in
      // that race; we then fail closed (404) and discard the orphaned tokens
      // (the IdP session is being torn down by the logout anyway).
      if (!stateStore.putIfPresent(sessKey, json.encode(refreshed), nextTtl)) {
        SecurityAudit.event(
            request, 404, "refresh_rejected", "session_deleted_during_refresh",
            subjectClaim(refreshed));
        return problem(404, "session ended, re-login required");
      }
      SecurityAudit.event(
          request, 200, "refresh_succeeded", "ok", subjectClaim(refreshed));
      return ResponseEntity.ok(new RefreshResponse(Instant.now(), refreshed.expiresAt()));
    } finally {
      lock.unlock();
      releaseRefreshLock(req.sid(), lockRef);
    }
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

  record RefreshRequest(String sid) {}
  // Wire shape MUST be snake_case per SPEC-0001 §7.1 — the API Gateway
  // (Lua, case-sensitive) consumes these field names verbatim. Java fields
  // stay camelCase for readability; @JsonProperty pins the wire name.
  record RefreshResponse(
      @com.fasterxml.jackson.annotation.JsonProperty("refreshed_at") Instant refreshedAt,
      @com.fasterxml.jackson.annotation.JsonProperty("access_token_expires_at")
          Instant accessTokenExpiresAt) {}

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
