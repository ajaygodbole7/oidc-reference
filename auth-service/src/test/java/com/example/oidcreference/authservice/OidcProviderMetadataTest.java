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
