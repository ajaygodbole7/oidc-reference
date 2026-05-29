package com.example.oidcreference.authservice;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

final class CryptoSupport {
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

  private CryptoSupport() {
  }

  static String randomUrlToken(int bytes) {
    byte[] value = new byte[bytes];
    RANDOM.nextBytes(value);
    return BASE64_URL.encodeToString(value);
  }

  static String sha256Base64Url(String value) {
    return BASE64_URL.encodeToString(sha256(value.getBytes(StandardCharsets.US_ASCII)));
  }

  static String hashForStorage(String value) {
    return sha256Base64Url(value);
  }

  private static byte[] sha256(byte[] value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the JDK", e);
    }
  }
}
