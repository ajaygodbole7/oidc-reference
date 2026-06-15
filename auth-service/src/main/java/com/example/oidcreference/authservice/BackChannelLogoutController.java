package com.example.oidcreference.authservice;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class BackChannelLogoutController {
  private static final Logger log = LoggerFactory.getLogger(BackChannelLogoutController.class);
  private static final Duration JTI_TTL = Duration.ofMinutes(5);

  private final BackChannelLogoutTokenValidator validator;
  private final SessionIndexes sessionIndexes;
  private final StateStore stateStore;

  BackChannelLogoutController(
      BackChannelLogoutTokenValidator validator,
      SessionIndexes sessionIndexes,
      StateStore stateStore) {
    this.validator = validator;
    this.sessionIndexes = sessionIndexes;
    this.stateStore = stateStore;
  }

  @PostMapping(
      path = "/backchannel-logout",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  ResponseEntity<Void> backChannelLogout(
      @RequestParam("logout_token") String logoutToken,
      HttpServletRequest request) {
    BackChannelLogoutTokenValidator.LogoutToken token;
    try {
      token = validator.validate(logoutToken);
      if (alreadyProcessed(token.jti())) {
        throw new BadCredentialsException("logout_token replay");
      }
    } catch (BadCredentialsException e) {
      log.warn("back-channel logout_token rejected: {}", e.getMessage());
      SecurityAudit.event(request, 400, "backchannel_logout_rejected", "invalid_logout_token");
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .cacheControl(CacheControl.noStore())
          .build();
    }

    int deleted = 0;
    if (token.sid() != null) {
      deleted += sessionIndexes.deleteByIdpSid(token.sid());
    } else if (token.sub() != null) {
      deleted += sessionIndexes.deleteBySubject(token.sub());
    }

    // Mark the jti processed ONLY after the revocation side effect succeeded. If a
    // deletion above throws it propagates as a 5xx and NO replay marker is left, so
    // the IdP's retry can still revoke the session — marking before deletion would
    // turn a failed delete into a permanent fail-open (retry rejected as replay,
    // session stays alive). Deletion is idempotent, so a concurrent retry that
    // races into the gap re-runs it harmlessly.
    markProcessed(token.jti());

    SecurityAudit.event(
        request,
        200,
        "backchannel_logout_succeeded",
        deleted > 0 ? "session_deleted" : "no_matching_session",
        token.sub());
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .build();
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  ResponseEntity<Void> missingLogoutToken(HttpServletRequest request) {
    SecurityAudit.event(request, 400, "backchannel_logout_rejected", "missing_logout_token");
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .cacheControl(CacheControl.noStore())
        .build();
  }

  // Replay = a logout_token whose jti we have ALREADY fully processed (deleted
  // its sessions). A read-only check, so a token whose prior deletion FAILED (no
  // marker written) is not treated as a replay and can be retried.
  private boolean alreadyProcessed(String jti) {
    return stateStore.get("logout_jti:" + jti).isPresent();
  }

  // Record the jti as processed (idempotent putIfAbsent). Called only after a
  // successful deletion. The TTL bounds how long replays are remembered.
  private void markProcessed(String jti) {
    stateStore.putIfAbsent("logout_jti:" + jti, "1", JTI_TTL);
  }
}
