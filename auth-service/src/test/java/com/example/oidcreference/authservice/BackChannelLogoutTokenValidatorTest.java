package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

class BackChannelLogoutTokenValidatorTest {
  private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");
  private RSAKey signingKey;
  private BackChannelLogoutTokenValidator sut;

  @BeforeEach
  void setUp() throws Exception {
    signingKey = new RSAKeyGenerator(2048)
        .keyID("logout-kid")
        .algorithm(JWSAlgorithm.RS256)
        .generate();
    sut = new BackChannelLogoutTokenValidator(
        metadata(),
        Clock.fixed(NOW, ZoneOffset.UTC),
        processorFor(signingKey.toPublicJWK()));
  }

  @Test
  void validLogoutTokenReturnsSubjectAndSid() throws Exception {
    var token = sut.validate(sign(claims().build()));

    assertThat(token.sub()).isEqualTo("alice");
    assertThat(token.sid()).isEqualTo("idp-sid-1");
    assertThat(token.jti()).isEqualTo("jti-1");
  }

  @Test
  void wrongIssuerIsRejected() throws Exception {
    String token = sign(claims().issuer("http://attacker.example").build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void wrongAudienceIsRejected() throws Exception {
    String token = sign(claims().audience(List.of("other-client")).build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void staleIatIsRejected() throws Exception {
    String token = sign(claims()
        .issueTime(Date.from(NOW.minusSeconds(301)))
        .build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void missingEventsIsRejected() throws Exception {
    String token = sign(claims().claim("events", null).build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void nonceBearingLogoutTokenIsRejected() throws Exception {
    String token = sign(claims().claim("nonce", "login-nonce").build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void tokenWithoutSubAndSidIsRejected() throws Exception {
    String token = sign(new JWTClaimsSet.Builder()
        .issuer("http://idp.example")
        .audience("oidc-reference-auth")
        .issueTime(Date.from(NOW))
        .jwtID("jti-1")
        .claim("events", Map.of(BackChannelLogoutTokenValidator.LOGOUT_EVENT, Map.of()))
        .build());

    assertThatThrownBy(() -> sut.validate(token))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void algConfusionHs256IsRejected() throws Exception {
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("logout-kid").build(),
        claims().build());
    jwt.sign(new MACSigner(new byte[32]));

    assertThatThrownBy(() -> sut.validate(jwt.serialize()))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void unknownSigningKeyIsRejected() throws Exception {
    RSAKey foreign = new RSAKeyGenerator(2048)
        .keyID("logout-kid")
        .algorithm(JWSAlgorithm.RS256)
        .generate();
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("logout-kid").build(),
        claims().build());
    jwt.sign(new RSASSASigner(foreign));

    assertThatThrownBy(() -> sut.validate(jwt.serialize()))
        .isInstanceOf(BadCredentialsException.class);
  }

  private JWTClaimsSet.Builder claims() {
    return new JWTClaimsSet.Builder()
        .issuer("http://idp.example")
        .audience("oidc-reference-auth")
        .subject("alice")
        .claim("sid", "idp-sid-1")
        .issueTime(Date.from(NOW))
        .jwtID("jti-1")
        .claim("events", Map.of(BackChannelLogoutTokenValidator.LOGOUT_EVENT, Map.of()));
  }

  private String sign(JWTClaimsSet claims) throws Exception {
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("logout-kid").build(),
        claims);
    jwt.sign(new RSASSASigner(signingKey));
    return jwt.serialize();
  }

  private static DefaultJWTProcessor<SecurityContext> processorFor(RSAKey publicKey) {
    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
        JWSAlgorithm.RS256,
        new ImmutableJWKSet<>(new JWKSet(publicKey))));
    return processor;
  }

  private static OidcProviderMetadata metadata() {
    return new OidcProviderMetadata(
        "oidc-reference-auth",
        "secret",
        URI.create("http://idp.example/authorize"),
        URI.create("http://idp.example/token"),
        URI.create("http://idp.example/jwks"),
        URI.create("http://idp.example/logout"),
        "http://idp.example",
        Set.of("openid"));
  }
}
