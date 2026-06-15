package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

class JwtAuthenticationConverterTest {

  private final JwtAuthenticationConverter converter =
      new SecurityConfig().jwtAuthenticationConverter(List.of("realm_access", "roles"));

  @Test
  void mapsScopeClaimToScopeAuthorities() {
    Jwt jwt = jwtBuilder()
        .claim("scope", "openid profile api.read")
        .build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities)
        .contains("SCOPE_openid", "SCOPE_profile", "SCOPE_api.read");
  }

  @Test
  void mapsScpClaimToScopeAuthorities() {
    Jwt jwt = jwtBuilder()
        .claim("scp", List.of("openid", "profile", "api.read"))
        .build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities)
        .contains("SCOPE_openid", "SCOPE_profile", "SCOPE_api.read");
  }

  @Test
  void mapsSpaceDelimitedScpClaimToScopeAuthorities() {
    Jwt jwt = jwtBuilder()
        .claim("scp", "openid profile api.read")
        .build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities)
        .contains("SCOPE_openid", "SCOPE_profile", "SCOPE_api.read");
  }

  @Test
  void mapsRealmAccessRolesToRoleAuthorities() {
    Jwt jwt = jwtBuilder()
        .claim("realm_access", Map.of("roles", List.of("user", "admin")))
        .build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities).contains("ROLE_user", "ROLE_admin");
  }

  @Test
  void mergesScopesAndRoles() {
    Jwt jwt = jwtBuilder()
        .claim("scope", "api.read")
        .claim("realm_access", Map.of("roles", List.of("admin")))
        .build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities).contains("SCOPE_api.read", "ROLE_admin");
  }

  @Test
  void tolerantOfMissingRealmAccess() {
    Jwt jwt = jwtBuilder().claim("scope", "api.read").build();

    var authorities = converter.convert(jwt).getAuthorities().stream()
        .map(a -> a.getAuthority()).collect(Collectors.toSet());

    assertThat(authorities).contains("SCOPE_api.read");
    assertThat(authorities).noneMatch(a -> a.startsWith("ROLE_"));
  }

  private static Jwt.Builder jwtBuilder() {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300));
  }
}
