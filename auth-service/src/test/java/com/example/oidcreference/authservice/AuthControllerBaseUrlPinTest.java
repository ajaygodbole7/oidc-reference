package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * B1: when {@code app.base-url} is configured the Auth Service must IGNORE
 * X-Forwarded-Host / X-Forwarded-Proto / X-Forwarded-Port and build the
 * OAuth {@code redirect_uri} from the pinned value. A forged Host or XFH
 * header on the gateway must not be able to steer the IdP to a crafted
 * redirect_uri. Mirrors AuthControllerTest's header-resolution tests but
 * with the pin in place.
 */
@SpringBootTest(properties = {
    "spring.main.allow-bean-definition-overriding=true",
    "app.base-url=https://app.example.com",
    "app.oauth-registration-id=idp",
    "app.issuer-uri=http://idp.example",
    "app.client-id=oidc-reference-auth",
    "app.client-secret=test-secret",
    "app.scopes=openid,profile,email,roles,api.audience,api.read",
    "app.session-refresh-window=60s",
    "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
class AuthControllerBaseUrlPinTest {

  @jakarta.annotation.Resource
  private MockMvc mockMvc;

  @Test
  void redirectUriUsesConfiguredBaseUrl_ignoringForwardedHeaders() throws Exception {
    MvcResult result = mockMvc.perform(get("/auth/login")
            .param("return_to", "/")
            // Attempt to steer the redirect_uri via attacker-controlled XFH.
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Host", "attacker.example")
            .header("X-Forwarded-Port", "1337"))
        .andExpect(status().isFound())
        .andReturn();

    String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
    assertThat(location)
        .as("redirect_uri must come from app.base-url, not XFH headers")
        .contains("redirect_uri=https://app.example.com/auth/callback/idp")
        .doesNotContain("attacker.example")
        .doesNotContain("1337");
  }

  @Test
  void redirectUriUsesConfiguredBaseUrlEvenWithoutForwardedHeaders() throws Exception {
    MvcResult result = mockMvc.perform(get("/auth/login")
            .param("return_to", "/"))
        .andExpect(status().isFound())
        .andReturn();

    assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION))
        .contains("redirect_uri=https://app.example.com/auth/callback/idp");
  }

  @TestConfiguration
  static class TestBeans {
    @Bean
    @Primary
    StateStore stateStore() {
      return new InMemoryStateStore();
    }

    @Bean
    @Primary
    TokenExchangeClient tokenExchangeClient() {
      return (code, state, redirectUri, tx) -> {
        throw new UnsupportedOperationException("token exchange not exercised here");
      };
    }

    @Bean
    @Primary
    TokenRefreshClient tokenRefreshClient() {
      return session -> {
        throw new UnsupportedOperationException("refresh not exercised here");
      };
    }

    @Bean
    @Primary
    IdTokenValidator idTokenValidator() {
      return (idToken, accessToken, tx) -> Map.of("sub", "alice");
    }

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
    IDTokenValidator nimbusIdTokenValidator() {
      return new IDTokenValidator(new Issuer("http://idp.example"), new ClientID("oidc-reference-auth"));
    }

    @Bean
    @Primary
    JwtDecoder internalJwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("test stub");
      };
    }
  }

}
