package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

// Proves /internal/resolve's caller-identity checks are config-driven: a
// non-default gateway client id / internal audience is honored, and the
// shipped defaults are NOT special-cased.
class InternalResolveIdentityCheckTest {

  @Test
  void audienceCheckHonorsConfiguredValue() {
    Jwt jwt = jwt(j -> j.audience(List.of("custom-internal-aud")).claim("azp", "x"));

    assertThat(InternalResolveController.hasExpectedAudience(jwt, "custom-internal-aud")).isTrue();
    assertThat(InternalResolveController.hasExpectedAudience(jwt, "oidc-reference-auth-internal"))
        .isFalse();
  }

  @Test
  void callerCheckHonorsConfiguredAzp() {
    Jwt jwt = jwt(j -> j.claim("azp", "custom-gateway"));

    assertThat(InternalResolveController.hasExpectedCaller(jwt, "custom-gateway")).isTrue();
    assertThat(InternalResolveController.hasExpectedCaller(jwt, "oidc-reference-api-gateway"))
        .isFalse();
  }

  @Test
  void callerCheckAlsoMatchesClientIdClaim() {
    Jwt jwt = jwt(j -> j.claim("client_id", "custom-gateway"));

    assertThat(InternalResolveController.hasExpectedCaller(jwt, "custom-gateway")).isTrue();
  }

  @Test
  void callerCheckAlsoMatchesEntraAppIdClaim() {
    Jwt jwt = jwt(j -> j.claim("appid", "custom-gateway"));

    assertThat(InternalResolveController.hasExpectedCaller(jwt, "custom-gateway")).isTrue();
    assertThat(InternalResolveController.hasExpectedCaller(jwt, "other-gateway")).isFalse();
  }

  @Test
  void callerCheckRejectsConflictingClientIdentityClaims() {
    Jwt jwt = jwt(j -> j
        .claim("azp", "different-client")
        .claim("appid", "custom-gateway"));

    assertThat(InternalResolveController.hasExpectedCaller(jwt, "custom-gateway")).isFalse();
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
