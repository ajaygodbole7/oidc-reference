package com.example.oidcreference;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
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
  void echoReflectsEveryRequestHeaderLowerCased() throws Exception {
    // The controller reflects ALL inbound headers (not a fixed allowlist) so the
    // live gateway suite can assert the exact injected Authorization and that no
    // credential leaked into any header. Lock that capability here: an arbitrary
    // probe header is reflected, keys are lower-cased, and the query string and
    // harness headers round-trip.
    mockMvc.perform(get("/api/_test/echo?alpha=1&encoded=ab")
            .header("Cookie", "__Host-sid=test")
            .header("Connection", "keep-alive")
            .header("X-Should-Strip", "remove-me")
            .header("X-Echo-Probe", "probe-value")
            .with(jwt()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.queryString").value("alpha=1&encoded=ab"))
        .andExpect(jsonPath("$.headers.cookie").value("__Host-sid=test"))
        .andExpect(jsonPath("$.headers.connection").value("keep-alive"))
        .andExpect(jsonPath("$.headers.x-should-strip").value("remove-me"))
        .andExpect(jsonPath("$.headers.x-echo-probe").value("probe-value"));
  }
}
