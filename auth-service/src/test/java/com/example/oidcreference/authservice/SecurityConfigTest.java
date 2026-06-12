package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Two behavioral concerns are exercised here:
 *
 * <ol>
 *   <li><strong>Fetch Metadata classification</strong> — the three small
 *       unit tests against {@link BrowserRequestClassifier} preserved from
 *       the BFF. They guard the navigation-vs-XHR decision the Auth Service
 *       relies on to issue 302 vs 401.
 *   <li><strong>Order-1 chain for {@code /internal/**}</strong> — per
 *       SPEC-0001 §7.1, an unauthenticated call returns 401, and a Bearer
 *       lacking the required authorization signal (the configured
 *       internal-refresh audience plus the gateway {@code azp}/{@code client_id})
 *       is rejected with 401 or 403. A misconfigured chain would let either
 *       case hit the handler.
 * </ol>
 *
 * <p>The security-chain tests are grouped into a {@code @Nested} class so
 * they share one {@code @SpringBootTest} context while the unit tests run
 * outside of it.
 */
class SecurityConfigTest {

  // -- BrowserRequestClassifier unit tests (preserved from BFF) ------------

  private final BrowserRequestClassifier classifier = new BrowserRequestClassifier();

  @Test
  void fetchMetadataIdentifiesDocumentNavigations() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Sec-Fetch-Mode", "navigate");
    request.addHeader("Sec-Fetch-Dest", "document");

    assertThat(classifier.isDocumentNavigation(request)).isTrue();
  }

  @Test
  void jsonFetchIsNotDocumentNavigation() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Accept", "application/json");

    assertThat(classifier.isDocumentNavigation(request)).isFalse();
  }

  @Test
  void fetchMetadataPresentPreventsAcceptFallback() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Sec-Fetch-Mode", "cors");
    request.addHeader("Sec-Fetch-Dest", "empty");
    request.addHeader("Accept", "text/html");

    assertThat(classifier.isDocumentNavigation(request)).isFalse();
  }

  @Test
  void internalJwtValidatorAcceptsKeycloakStringAudience() {
    Jwt jwt = internalJwt("http://idp.example", "oidc-reference-auth-internal");

    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "oidc-reference-auth-internal").validate(jwt).hasErrors())
        .isFalse();
  }

  @Test
  void internalJwtValidatorAcceptsArrayAudience() {
    Jwt jwt = internalJwt(
        "http://idp.example", List.of("other-audience", "oidc-reference-auth-internal"));

    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "oidc-reference-auth-internal").validate(jwt).hasErrors())
        .isFalse();
  }

  @Test
  void internalJwtValidatorRejectsWrongAudience() {
    Jwt jwt = internalJwt("http://idp.example", "oidc-reference-api");

    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "oidc-reference-auth-internal").validate(jwt).hasErrors())
        .isTrue();
  }

  @Test
  void internalJwtValidatorRejectsArrayWithoutExpectedAudience() {
    Jwt jwt = internalJwt("http://idp.example", List.of("oidc-reference-api", "other-api"));

    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "oidc-reference-auth-internal").validate(jwt).hasErrors())
        .isTrue();
  }

  @Test
  void internalJwtValidatorHonorsAConfiguredNonDefaultAudience() {
    // A non-default internal audience must validate, and the shipped default
    // must be rejected under that config — proving the value is config-driven,
    // not pinned to oidc-reference-auth-internal.
    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "custom-internal-aud")
            .validate(internalJwt("http://idp.example", "custom-internal-aud")).hasErrors())
        .isFalse();
    assertThat(SecurityConfig.internalJwtValidator("http://idp.example", "custom-internal-aud")
            .validate(internalJwt("http://idp.example", "oidc-reference-auth-internal")).hasErrors())
        .isTrue();
  }

  // -- /internal/** security-chain tests (new) ------------------------------

  /**
   * Spring Boot 4 supports {@code @SpringBootTest} on {@code @Nested}
   * classes; this lets the unit tests above stay collocated with the
   * chain tests below while only paying for context startup once.
   */
  @Nested
  @SpringBootTest(properties = {
      "spring.main.allow-bean-definition-overriding=true",
      "app.oauth-registration-id=idp",
      "app.issuer-uri=http://idp.example",
      "app.client-id=oidc-reference-auth",
      "app.client-secret=test-secret",
      "app.scopes=openid,profile,email,roles,api.audience,api.read",
      // 32 zero bytes Base64-encoded. The CSRF path isn't exercised here
      // but AuthProperties requires a non-blank value.
      "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  })
  @AutoConfigureMockMvc
  @Import(SecurityConfigTest.TestBeans.class)
  class InternalPathChainTests {

    @jakarta.annotation.Resource
    private MockMvc mockMvc;

    @Test
    void internalPathRequiresBearer() throws Exception {
      // No Authorization header → the Resource Server filter on the
      // /internal/** chain rejects with 401 before the handler runs.
      mockMvc.perform(post("/internal/resolve")
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"sid\":\"any\"}"))
          .andExpect(status().isUnauthorized());
    }

    @Test
    void internalPathRejectsBearerWithWrongCaller() throws Exception {
      // Per SPEC-0001 §7.1: a Bearer that is structurally valid (correct
      // internal-refresh audience) but is NOT the gateway — wrong azp/client_id
      // — must be rejected. SecurityConfig enforces audience binding at the
      // filter layer and InternalResolveController re-asserts audience+azp; a
      // Bearer with the wrong azp is rejected with 401 (controller re-assertion)
      // or 403 (filter chain). Both verdicts mean "rejected"; both are accepted
      // here so the test pins the behavior, not the exact enforcement path.
      mockMvc.perform(post("/internal/resolve")
              .with(jwt().jwt(j -> j
                  // wrong azp: bearer issued to the Auth Service itself,
                  // not the API Gateway
                  .claim("azp", "oidc-reference-auth")
                  .audience(List.of("oidc-reference-auth-internal"))))
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"sid\":\"any\"}"))
          .andExpect(result -> {
            int s = result.getResponse().getStatus();
            assertThat(s)
                .as("bearer with wrong caller (azp) must be rejected (401 or 403)")
                .isIn(401, 403);
          });
    }
  }

  // -- test config ---------------------------------------------------------

  @TestConfiguration
  static class TestBeans {
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
      return new IdTokenValidator() {
        @Override
        public Map<String, Object> validate(
            String idToken, String accessToken, OAuthTransaction transaction) {
          return Map.of("sub", "alice");
        }
      };
    }

    @Bean
    @Primary
    com.nimbusds.openid.connect.sdk.validators.IDTokenValidator nimbusIdTokenValidator() {
      // Auth Service auto-wires Nimbus's validator from JWKS; tests stub
      // with a no-op so context refresh does not perform JWKS discovery.
      return new IDTokenValidator(
          new Issuer("http://idp.example"), new ClientID("oidc-reference-auth"));
    }

    // Production wires a NimbusJwtDecoder via JwtDecoders.fromIssuerLocation()
    // which would hit http://idp.example at startup. Stub so context refresh
    // succeeds; the jwt() MockMvc post-processor bypasses the decoder anyway.
    @Bean
    @Primary
    JwtDecoder internalJwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException(
            "test stub — real decoding bypassed by jwt() post-processor");
      };
    }

    @Bean
    @Primary
    TokenExchangeClient tokenExchangeClient() {
      return (code, state, redirectUri, transaction) -> {
        throw new UnsupportedOperationException("not exercised in SecurityConfigTest");
      };
    }

    @Bean
    @Primary
    TokenRefreshClient tokenRefreshClient() {
      return session -> {
        throw new UnsupportedOperationException("not exercised in SecurityConfigTest");
      };
    }
  }

  private static Jwt internalJwt(String issuer, Object audience) {
    Instant now = Instant.now();
    return Jwt.withTokenValue("test-token")
        .header("alg", "RS256")
        .issuer(issuer)
        .subject("oidc-reference-api-gateway")
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .claim("aud", audience)
        .claim("azp", "oidc-reference-api-gateway")
        .build();
  }
}
