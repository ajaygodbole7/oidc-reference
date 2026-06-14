package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
    "spring.main.allow-bean-definition-overriding=true",
    "app.oauth-registration-id=idp",
    "app.issuer-uri=http://idp.example",
    "app.client-id=oidc-reference-auth",
    "app.client-secret=test-secret",
    "app.scopes=openid,profile,email,roles,api.audience,api.read",
    "app.session-refresh-window=60s",
    "app.cookie-signing-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})
@AutoConfigureMockMvc
class BackChannelLogoutControllerTest {
  @jakarta.annotation.Resource
  private MockMvc mockMvc;

  @jakarta.annotation.Resource
  private InMemoryStateStore stateStore;

  @BeforeEach
  void clearState() {
    stateStore.clear();
  }

  @Test
  void validLogoutTokenByIdpSidDeletesLocalSession() throws Exception {
    SessionRecord session = session("alice", idTokenWithSid("idp-sid-1"));
    stateStore.put("sess:local-sid-1", TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    new SessionIndexes(stateStore, TestBeans.JSON)
        .index("local-sid-1", session);

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-sid"))
        .andExpect(status().isOk());

    assertThat(stateStore.get("sess:local-sid-1")).isEmpty();
    assertThat(stateStore.get("idp_sid:idp-sid-1")).isEmpty();
  }

  @Test
  void validLogoutTokenByIdpSidCanMatchSidFromAccessToken() throws Exception {
    Instant createdAt = Instant.now();
    SessionRecord session = new SessionRecord(
        idTokenWithSid("idp-sid-1"),
        "refresh-token",
        "id-token-without-sid",
        createdAt.plusSeconds(300),
        createdAt.plusSeconds(1800),
        createdAt,
        createdAt.plusSeconds(3600),
        createdAt,
        Map.of("sub", "alice"));
    stateStore.put("sess:local-sid-1", TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    new SessionIndexes(stateStore, TestBeans.JSON)
        .index("local-sid-1", session);

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-sid"))
        .andExpect(status().isOk());

    assertThat(stateStore.get("sess:local-sid-1")).isEmpty();
    assertThat(stateStore.get("idp_sid:idp-sid-1")).isEmpty();
  }

  @Test
  void validLogoutTokenBySubjectDeletesAllSubjectSessions() throws Exception {
    SessionRecord first = session("alice", "not-a-jwt");
    SessionRecord second = session("alice", "also-not-a-jwt");
    SessionIndexes indexes = new SessionIndexes(stateStore, TestBeans.JSON);
    stateStore.put("sess:local-sid-a", TestBeans.JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("local-sid-a", first);
    stateStore.put("sess:local-sid-b", TestBeans.JSON.encode(second), Duration.ofMinutes(30));
    indexes.index("local-sid-b", second);

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-sub"))
        .andExpect(status().isOk());

    assertThat(stateStore.get("sess:local-sid-a")).isEmpty();
    assertThat(stateStore.get("sess:local-sid-b")).isEmpty();
    assertThat(stateStore.members("sub_sessions:alice")).isEmpty();
  }

  @Test
  void logoutTokenWithSidAndSubjectDeletesOnlyMatchingIdpSession() throws Exception {
    SessionRecord first = session("alice", idTokenWithSid("idp-sid-1"));
    SessionRecord second = session("alice", idTokenWithSid("idp-sid-2"));
    SessionIndexes indexes = new SessionIndexes(stateStore, TestBeans.JSON);
    stateStore.put("sess:local-sid-1", TestBeans.JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("local-sid-1", first);
    stateStore.put("sess:local-sid-2", TestBeans.JSON.encode(second), Duration.ofMinutes(30));
    indexes.index("local-sid-2", second);

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-sid-and-sub"))
        .andExpect(status().isOk());

    assertThat(stateStore.get("sess:local-sid-1")).isEmpty();
    assertThat(stateStore.get("sess:local-sid-2")).isPresent();
    assertThat(stateStore.get("idp_sid:idp-sid-1")).isEmpty();
    assertThat(stateStore.members("idp_sid:idp-sid-2")).containsExactly("local-sid-2");
    assertThat(stateStore.members("sub_sessions:alice"))
        .containsExactly("local-sid-2");
  }

  @Test
  void invalidLogoutTokenReturns400AndLeavesSessionUntouched() throws Exception {
    SessionRecord session = session("alice", idTokenWithSid("idp-sid-1"));
    stateStore.put("sess:local-sid-1", TestBeans.JSON.encode(session), Duration.ofMinutes(30));
    new SessionIndexes(stateStore, TestBeans.JSON)
        .index("local-sid-1", session);

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=invalid"))
        .andExpect(status().isBadRequest());

    assertThat(stateStore.get("sess:local-sid-1")).isPresent();
    assertThat(stateStore.members("idp_sid:idp-sid-1")).containsExactly("local-sid-1");
  }

  @Test
  void replayedLogoutTokenReturns400() throws Exception {
    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-replay"))
        .andExpect(status().isOk());

    mockMvc.perform(post("/backchannel-logout")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("logout_token=valid-replay"))
        .andExpect(status().isBadRequest());
  }

  private static SessionRecord session(String sub, String idToken) {
    Instant createdAt = Instant.now();
    return new SessionRecord(
        "access-token",
        "refresh-token",
        idToken,
        createdAt.plusSeconds(300),
        createdAt.plusSeconds(1800),
        createdAt,
        createdAt.plusSeconds(3600),
        createdAt,
        Map.of("sub", sub));
  }

  private static String idTokenWithSid(String sid) {
    return new PlainJWT(new JWTClaimsSet.Builder().claim("sid", sid).build()).serialize();
  }

  @TestConfiguration
  static class TestBeans {
    static final JsonCodec JSON = new JsonCodec(tools.jackson.databind.json.JsonMapper.builder()
        .findAndAddModules()
        .build());

    @Bean
    @Primary
    InMemoryStateStore stateStore() {
      return new InMemoryStateStore();
    }

    @Bean
    @Primary
    BackChannelLogoutTokenValidator backChannelLogoutTokenValidator() {
      return new FakeBackChannelLogoutTokenValidator();
    }

    @Bean
    @Primary
    OidcProviderMetadata oidcProviderMetadata() {
      return oidcProviderMetadataForFake();
    }

    static OidcProviderMetadata oidcProviderMetadataForFake() {
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
      return new IDTokenValidator(
          new Issuer("http://idp.example"),
          new ClientID("oidc-reference-auth"));
    }

    @Bean
    @Primary
    IdTokenValidator idTokenValidator() {
      return (idToken, accessToken, transaction) -> Map.of("sub", "alice", "roles", List.of());
    }

    @Bean
    @Primary
    TokenExchangeClient tokenExchangeClient() {
      return (code, state, redirectUri, transaction) -> session("alice", "id-token");
    }

    @Bean
    @Primary
    TokenRefreshClient tokenRefreshClient() {
      return session -> session;
    }

    @Bean
    @Primary
    JwtDecoder internalJwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("not used by back-channel tests");
      };
    }
  }

  static final class FakeBackChannelLogoutTokenValidator extends BackChannelLogoutTokenValidator {
    FakeBackChannelLogoutTokenValidator() {
      super(TestBeans.oidcProviderMetadataForFake(), java.time.Clock.systemUTC(), null);
    }

    @Override
    LogoutToken validate(String serialized) {
      return switch (serialized) {
        case "valid-sid" -> new LogoutToken("alice", "idp-sid-1", "jti-sid");
        case "valid-sid-and-sub" -> new LogoutToken("alice", "idp-sid-1", "jti-sid-and-sub");
        case "valid-sub" -> new LogoutToken("alice", null, "jti-sub");
        case "valid-replay" -> new LogoutToken("alice", null, "jti-replay");
        default -> throw new BadCredentialsException("invalid");
      };
    }
  }
}
