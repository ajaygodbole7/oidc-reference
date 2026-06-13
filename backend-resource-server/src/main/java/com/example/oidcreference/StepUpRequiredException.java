package com.example.oidcreference;

import java.time.Duration;
import java.util.Set;

// Thrown when a sensitive endpoint is reached with a token whose authentication
// is insufficient for the action — either its last interactive authentication
// (auth_time) is older than the configured window (recency) or its assurance
// level (acr) is below what the resource requires (assurance), or either is
// absent. Mapped to an RFC 9470 "insufficient_user_authentication" challenge so
// the client knows to elevate via the BFF's /auth/step-up rather than perform a
// full re-login. The token is otherwise valid (authenticated, correctly scoped);
// only its authentication strength/recency is insufficient.
class StepUpRequiredException extends RuntimeException {
  private final transient Duration maxAge;
  private final transient Set<String> requiredAcr;

  StepUpRequiredException(Duration maxAge, Set<String> requiredAcr) {
    super("step-up authentication required");
    this.maxAge = maxAge;
    this.requiredAcr = Set.copyOf(requiredAcr);
  }

  Duration maxAge() {
    return maxAge;
  }

  // The acr values (LoA) the resource accepts, advertised back as RFC 9470
  // acr_values in the challenge. Empty when acr enforcement is disabled.
  Set<String> requiredAcr() {
    return requiredAcr;
  }
}
