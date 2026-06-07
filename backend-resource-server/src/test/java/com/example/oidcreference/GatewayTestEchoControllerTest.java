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
  void echoEndpointReflectsOnlyGatewayHarnessFields() throws Exception {
    mockMvc.perform(get("/api/_test/echo?alpha=1&encoded=ab")
            .header("Cookie", "__Host-sid=test")
            .header("Connection", "keep-alive")
            .header("X-Should-Strip", "remove-me")
            .with(jwt()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.queryString").value("alpha=1&encoded=ab"))
        .andExpect(jsonPath("$.headers.cookie").value("__Host-sid=test"))
        .andExpect(jsonPath("$.headers.connection").value("keep-alive"))
        .andExpect(jsonPath("$.headers.x-should-strip").value("remove-me"))
        .andExpect(jsonPath("$.headers.authorization").doesNotExist());
  }
}
