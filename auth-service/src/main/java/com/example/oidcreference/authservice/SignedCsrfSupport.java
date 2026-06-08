package com.example.oidcreference.authservice;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
class SignedCsrfSupport {
  private static final String CSRF_COOKIE = "XSRF-TOKEN";
  private static final String CSRF_HEADER = "X-XSRF-TOKEN";
  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder BASE64_STD = Base64.getDecoder();

  static String issueToken(String signingKey, String sid) {
    String value = CryptoSupport.randomUrlToken(16);
    String hmac = hmacSha256(message(value, sid), signingKey);
    return value + "." + hmac;
  }

  static boolean validate(
      String tokenFromCookie,
      String tokenFromHeader,
      String signingKey,
      String sid) {
    if (signingKey == null || signingKey.isBlank()) {
      return false;
    }
    if (sid == null || sid.isBlank()) {
      return false;
    }
    if (tokenFromCookie == null || tokenFromHeader == null) {
      return false;
    }
    if (!constantTimeEquals(tokenFromCookie, tokenFromHeader)) {
      return false;
    }
    int dot = tokenFromCookie.lastIndexOf('.');
    if (dot < 1 || dot == tokenFromCookie.length() - 1) {
      return false;
    }
    String value = tokenFromCookie.substring(0, dot);
    String suppliedHmac = tokenFromCookie.substring(dot + 1);
    String expectedHmac;
    try {
      expectedHmac = hmacSha256(message(value, sid), signingKey);
    } catch (RuntimeException e) {
      return false;
    }
    return constantTimeEquals(suppliedHmac, expectedHmac);
  }

  boolean hasValidCsrf(HttpServletRequest request, String signingKey, String sid) {
    String cookie = cookieValue(request, CSRF_COOKIE).orElse(null);
    String header = request.getHeader(CSRF_HEADER);
    return validate(cookie, header, signingKey, sid);
  }

  static Optional<String> cookieValue(HttpServletRequest request, String name) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    return Arrays.stream(cookies)
        .filter(c -> name.equals(c.getName()))
        .map(Cookie::getValue)
        .findFirst();
  }

  // Package-private so OAuthTxBinding (and any future
  // signed-cookie helper) can reuse the same HMAC implementation
  // rather than copy-pasting the key-decode + Mac dance.
  static String hmacSha256(String value, String signingKey) {
    try {
      byte[] keyBytes = BASE64_STD.decode(signingKey);
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
      byte[] sig = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
      return BASE64_URL.encodeToString(sig);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("CSRF signing key is not valid Base64", e);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 unavailable in this JDK", e);
    }
  }

  private static String message(String value, String sid) {
    return value + ":" + sid;
  }

  private static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8),
        b.getBytes(StandardCharsets.UTF_8));
  }
}
