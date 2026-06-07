package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

// Proves /internal/refresh's caller-identity checks are config-driven: a
// non-default gateway client id / internal audience is honored, and the
// shipped defaults are NOT special-cased.
class InternalRefreshIdentityCheckTest {

  @Test
  void audienceCheckHonorsConfiguredValue() {
    Jwt jwt = jwt(j -> j.audience(List.of("custom-internal-aud")).claim("azp", "x"));

    assertThat(InternalRefreshController.hasExpectedAudience(jwt, "custom-internal-aud")).isTrue();
    assertThat(InternalRefreshController.hasExpectedAudience(jwt, "oidc-reference-auth-internal"))
        .isFalse();
  }

  @Test
  void callerCheckHonorsConfiguredAzp() {
    Jwt jwt = jwt(j -> j.claim("azp", "custom-gateway"));

    assertThat(InternalRefreshController.hasExpectedCaller(jwt, "custom-gateway")).isTrue();
    assertThat(InternalRefreshController.hasExpectedCaller(jwt, "oidc-reference-api-gateway"))
        .isFalse();
  }

  @Test
  void callerCheckAlsoMatchesClientIdClaim() {
    Jwt jwt = jwt(j -> j.claim("client_id", "custom-gateway"));

    assertThat(InternalRefreshController.hasExpectedCaller(jwt, "custom-gateway")).isTrue();
  }

  private static Jwt jwt(Consumer<Jwt.Builder> claims) {
    Jwt.Builder b = Jwt.withTokenValue("t")
        .header("alg", "RS256")
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300));
    claims.accept(b);
    return b.build();
  }
}
