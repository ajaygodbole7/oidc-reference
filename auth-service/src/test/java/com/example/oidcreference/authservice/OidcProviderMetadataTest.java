package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class OidcProviderMetadataTest {

  @Test
  void requireMatchingIssuerReturnsWhenDocumentIssuerEqualsConfigured() {
    String issuer = "https://idp.example/realms/app";

    assertThat(OidcProviderMetadata.requireMatchingIssuer(issuer, issuer))
        .isEqualTo(issuer);
  }

  @Test
  void discoveryFailsFastAgainstAHungIssuer() throws Exception {
    // Discovery runs at startup; with Nimbus's default infinite timeouts a
    // stalled issuer hangs boot indefinitely instead of failing fast. The
    // hung socket completes the TCP handshake but never responds.
    try (java.net.ServerSocket hung = new java.net.ServerSocket(0, 1)) {
      var props = new AuthProperties(
          "idp",
          "",
          java.time.Duration.ofSeconds(60),
          java.time.Duration.ofSeconds(1800),
          java.time.Duration.ofSeconds(28800),
          null,
          java.net.URI.create("http://127.0.0.1:" + hung.getLocalPort()),
          null,
          null,
          null,
          null,
          "oidc-reference-auth",
          "test-secret",
          java.util.Set.of("openid"),
          java.util.List.of("realm_access", "roles"),
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          true,
          "oidc-reference-api-gateway",
          "oidc-reference-auth-internal",
        java.time.Duration.ofSeconds(3),
        java.time.Duration.ofSeconds(5));

      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
          java.time.Duration.ofSeconds(10),
          () -> assertThatThrownBy(() -> OidcProviderMetadata.discover(props))
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("OIDC discovery failed"));
    }
  }

  @Test
  void requireMatchingIssuerFailsClosedOnIssuerDrift() {
    // OIDC Discovery / RFC 8414 §3.3: the issuer in the discovery document MUST
    // equal the issuer used to fetch it. A drifted issuer means the document
    // came from (or was redirected to) a different authority — fail closed.
    assertThatThrownBy(() -> OidcProviderMetadata.requireMatchingIssuer(
            "https://attacker.example/realms/app",
            "https://idp.example/realms/app"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("issuer mismatch");
  }
}
