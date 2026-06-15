package com.example.oidcreference;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only upstream behind the gateway. Reflects the request the Resource
 * Server actually received so the live gateway suite can assert what the
 * bff-session plugin forwarded: a fingerprint of the injected
 * {@code Authorization: Bearer} value, and that no session cookie / CSRF value
 * survived into any header.
 *
 * <p>Echoes every non-Authorization inbound header (lower-cased), not a fixed
 * allowlist, so a credential leaking into an unexpected header is still
 * observable. Authorization is summarized by count, scheme, and SHA-256
 * fingerprint; the live access token is never reflected into a response.
 * Present only under the {@code gateway-test} profile — never in a real
 * deployment.
 */
@Profile("gateway-test")
@RestController
@RequestMapping("/api/_test")
class GatewayTestEchoController {

  @GetMapping("/echo")
  Map<String, Object> echo(HttpServletRequest request) {
    Map<String, String> headers = new LinkedHashMap<>();
    Enumeration<String> names = request.getHeaderNames();
    while (names.hasMoreElements()) {
      String name = names.nextElement();
      if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
        continue;
      }
      // Join multiple values with ", " so a duplicated header (e.g. two
      // values from an append-instead-of-overwrite bug) remains visible.
      headers.put(
          name.toLowerCase(Locale.ROOT),
          String.join(", ", Collections.list(request.getHeaders(name))));
    }
    List<String> authorizationValues =
        Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
    String authorization = String.join(", ", authorizationValues);
    return Map.of(
        "method", request.getMethod(),
        "queryString", request.getQueryString() == null ? "" : request.getQueryString(),
        "headers", headers,
        "authorization", Map.of(
            "present", !authorizationValues.isEmpty(),
            "scheme", authorizationValues.size() == 1
                && authorization.startsWith("Bearer ") ? "Bearer" : "",
            "value_count", authorizationValues.size(),
            "sha256", sha256(authorization)));
  }

  static String sha256(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the Java runtime", e);
    }
  }
}
