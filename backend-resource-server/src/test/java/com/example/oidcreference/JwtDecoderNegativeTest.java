package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Negative-path tests for the Resource Server's {@code JwtDecoder}.
 *
 * <p>{@link ApiSecurityTest} {@code @MockitoBean}s the decoder away so it can
 * focus on URL-level authorization. That leaves every JWS-level guarantee
 * (RS256-only, issuer, audience, exp, nbf, kid resolution) untested. This
 * suite closes that gap by building a real {@link NimbusJwtDecoder} against
 * an in-memory {@link JWKSet} and applying the exact validator chain
 * production uses via {@link SecurityConfig#jwtValidator(String, String)}.
 *
 * <p>One decoder is shared across all tests so adding a new validator in
 * {@code SecurityConfig.jwtValidator(...)} is picked up here automatically.
 */
class JwtDecoderNegativeTest {

  private static final String ISSUER = "http://test/realm";
  private static final String AUDIENCE = "oidc-reference-api";
  private static final String LEGIT_KID = "kid-1";
  private static final String UNKNOWN_KID = "unknown-kid";

  private static RSAKey signingKey;
  private static RSAKey rogueKey;
  private static NimbusJwtDecoder decoder;

  @BeforeAll
  static void buildDecoder() throws Exception {
    signingKey = new RSAKeyGenerator(2048)
        .keyID(LEGIT_KID)
        .algorithm(JWSAlgorithm.RS256)
        .generate();
    // Second RSA key NOT published in the JWKSet. Used by
    // signatureFromUnknownKeyIsRejected to mint a token whose header
    // advertises the legit kid but whose signature was produced by this key.
    rogueKey = new RSAKeyGenerator(2048)
        .keyID(LEGIT_KID)
        .algorithm(JWSAlgorithm.RS256)
        .generate();

    JWKSource<SecurityContext> jwkSource =
        new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));

    decoder = NimbusJwtDecoder.withJwkSource(jwkSource)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .jwtProcessorCustomizer(SecurityConfig::customizeJwtProcessor)
        .build();
    decoder.setJwtValidator(SecurityConfig.jwtValidator(ISSUER, AUDIENCE));
  }

  @Test
  void validTokenDecodes() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID, baseClaims().build());

    var jwt = decoder.decode(token);

    assertThat(jwt.getSubject()).isEqualTo("alice");
    assertThat(jwt.getIssuer().toString()).isEqualTo(ISSUER);
    assertThat(jwt.getAudience()).contains(AUDIENCE);
  }

  @Test
  void validTokenWithStringAudienceDecodes() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID,
        baseClaimsWithoutAudience().claim("aud", AUDIENCE).build());

    var jwt = decoder.decode(token);

    assertThat(jwt.getAudience()).contains(AUDIENCE);
  }

  @Test
  void rfc9068AccessTokenTypeDecodes() throws Exception {
    String token = signRS256(
        signingKey, LEGIT_KID, new JOSEObjectType("at+JWT"), baseClaims().build());

    assertThat(decoder.decode(token).getSubject()).isEqualTo("alice");
  }

  @Test
  void missingJoseTypeIsRejected() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID, null, baseClaims().build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void unrelatedJoseTypeIsRejected() throws Exception {
    String token = signRS256(
        signingKey, LEGIT_KID, new JOSEObjectType("logout+jwt"), baseClaims().build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void algNoneIsRejected() throws Exception {
    // Unsigned ("alg":"none") token. The Nimbus JWS processor refuses to
    // treat a PlainJWT as a signed JWT, so decoding throws JwtException.
    PlainJWT plain = new PlainJWT(baseClaims().build());

    assertThatThrownBy(() -> decoder.decode(plain.serialize()))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void algConfusionHs256IsRejected() throws Exception {
    // Classic alg-confusion attempt: pretend the RSA public key (as bytes)
    // is an HMAC secret, sign HS256, and present it. The decoder's RS256
    // allowlist must reject this before any signature check happens.
    byte[] hmacSecret = new byte[64];
    java.util.Arrays.fill(hmacSecret, (byte) 0x42);
    SignedJWT hs = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.HS256)
            .type(JOSEObjectType.JWT)
            .keyID(LEGIT_KID)
            .build(),
        baseClaims().build());
    hs.sign(new MACSigner(new SecretKeySpec(hmacSecret, "HmacSHA256")));

    assertThatThrownBy(() -> decoder.decode(hs.serialize()))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void wrongIssuerIsRejected() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID,
        baseClaims().issuer("http://attacker").build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void wrongAudienceIsRejected() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID,
        baseClaims().audience(List.of("other-api")).build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void wrongStringAudienceIsRejected() throws Exception {
    String token = signRS256(signingKey, LEGIT_KID,
        baseClaimsWithoutAudience().claim("aud", "other-api").build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void missingAudienceIsRejected() throws Exception {
    // baseClaims() includes aud; rebuild without it to assert the audience
    // validator rejects a structurally valid token that simply omits aud.
    JWTClaimsSet noAud = new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject("alice")
        .issueTime(Date.from(Instant.now()))
        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
        .build();
    String token = signRS256(signingKey, LEGIT_KID, noAud);

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void expiredIsRejected() throws Exception {
    JWTClaimsSet expired = new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject("alice")
        .audience(List.of(AUDIENCE))
        .issueTime(Date.from(Instant.now().minusSeconds(3600)))
        .expirationTime(Date.from(Instant.now().minusSeconds(60)))
        .build();
    String token = signRS256(signingKey, LEGIT_KID, expired);

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void nbfInFutureIsRejected() throws Exception {
    // Spring's JwtTimestampValidator has a default 60-second clock-skew
    // tolerance for nbf; push the nbf well past that so this test exercises
    // the not-before check rather than the tolerance window.
    JWTClaimsSet notYet = new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject("alice")
        .audience(List.of(AUDIENCE))
        .issueTime(Date.from(Instant.now()))
        .notBeforeTime(Date.from(Instant.now().plusSeconds(600)))
        .expirationTime(Date.from(Instant.now().plusSeconds(1200)))
        .build();
    String token = signRS256(signingKey, LEGIT_KID, notYet);

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void kidNotInJwkSetIsRejected() throws Exception {
    // Sign with the real private key but advertise an unknown kid in the
    // header. The JWKSource cannot resolve a verification key.
    String token = signRS256(signingKey, UNKNOWN_KID, baseClaims().build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  @Test
  void signatureFromUnknownKeyIsRejected() throws Exception {
    // Header advertises the legit kid; signature was produced by a key not
    // in the JWKSet. The decoder resolves the legit public key by kid and
    // signature verification must fail.
    String token = signRS256(rogueKey, LEGIT_KID, baseClaims().build());

    assertThatThrownBy(() -> decoder.decode(token))
        .isInstanceOf(JwtException.class);
  }

  // ---- helpers ----------------------------------------------------------

  private static JWTClaimsSet.Builder baseClaims() {
    return baseClaimsWithoutAudience().audience(List.of(AUDIENCE));
  }

  private static JWTClaimsSet.Builder baseClaimsWithoutAudience() {
    Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .subject("alice")
        .issueTime(Date.from(now))
        .notBeforeTime(Date.from(now.minusSeconds(5)))
        .expirationTime(Date.from(now.plusSeconds(300)))
        .claim("scope", "openid api.read");
  }

  private static String signRS256(RSAKey key, String kid, JWTClaimsSet claims) throws Exception {
    return signRS256(key, kid, JOSEObjectType.JWT, claims);
  }

  private static String signRS256(
      RSAKey key,
      String kid,
      @Nullable JOSEObjectType type,
      JWTClaimsSet claims) throws Exception {
    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256)
        .keyID(kid);
    if (type != null) {
      header.type(type);
    }
    SignedJWT signed = new SignedJWT(
        header.build(),
        claims);
    signed.sign(new RSASSASigner(key));
    return signed.serialize();
  }
}
