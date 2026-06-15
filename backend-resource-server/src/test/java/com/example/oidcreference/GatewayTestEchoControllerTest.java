package com.example.oidcreference;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("gateway-test")
class GatewayTestEchoControllerTest {
  @MockitoBean
  private JwtDecoder jwtDecoder;

  @Autowired
  private MockMvc mockMvc;

  @Test
  void echoReflectsNonAuthorizationHeadersAndFingerprintsAuthorization() throws Exception {
    // An arbitrary probe header is reflected and lower-cased, while the bearer
    // is represented only by a deterministic fingerprint and count. This keeps
    // the exact-injection proof without making a token-reflection endpoint.
    String authorization = "Bearer upstream-token";
    Instant now = Instant.now();
    Jwt decoded = Jwt.withTokenValue("upstream-token")
        .header("alg", "RS256")
        .subject("gateway-test")
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .build();
    given(jwtDecoder.decode("upstream-token")).willReturn(decoded);

    mockMvc.perform(get("/api/_test/echo?alpha=1&encoded=ab")
            .header(HttpHeaders.AUTHORIZATION, authorization)
            .header("Cookie", "__Host-sid=test")
            .header("Connection", "keep-alive")
            .header("X-Should-Strip", "remove-me")
            .header("X-Echo-Probe", "probe-value"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.queryString").value("alpha=1&encoded=ab"))
        .andExpect(jsonPath("$.headers.cookie").value("__Host-sid=test"))
        .andExpect(jsonPath("$.headers.connection").value("keep-alive"))
        .andExpect(jsonPath("$.headers.x-should-strip").value("remove-me"))
        .andExpect(jsonPath("$.headers.x-echo-probe").value("probe-value"))
        .andExpect(jsonPath("$.headers.authorization").doesNotExist())
        .andExpect(jsonPath("$.authorization.present").value(true))
        .andExpect(jsonPath("$.authorization.scheme").value("Bearer"))
        .andExpect(jsonPath("$.authorization.value_count").value(1))
        .andExpect(jsonPath("$.authorization.sha256")
            .value(GatewayTestEchoController.sha256(authorization)));
  }
}
