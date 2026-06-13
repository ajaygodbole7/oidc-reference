package com.example.oidcreference;

import java.time.Duration;

// Thrown when a sensitive endpoint is reached with a token whose last
// interactive authentication (auth_time) is older than the configured step-up
// window — or absent. Mapped to an RFC 9470 "insufficient_user_authentication"
// challenge so the client knows to elevate via the BFF's /auth/step-up rather
// than perform a full re-login. The token is otherwise valid (authenticated,
// correctly scoped); only its authentication recency is insufficient.
class StepUpRequiredException extends RuntimeException {
  private final transient Duration maxAge;

  StepUpRequiredException(Duration maxAge) {
    super("step-up authentication required");
    this.maxAge = maxAge;
  }

  Duration maxAge() {
    return maxAge;
  }
}
