package com.example.oidcreference;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only upstream behind the gateway. Reflects the request the Resource
 * Server actually received so the live gateway suite can assert what the
 * bff-session plugin forwarded: the exact injected {@code Authorization: Bearer}
 * value, and that no session cookie / CSRF value survived into any header.
 *
 * <p>Echoes <b>every</b> inbound header (lower-cased), not a fixed allowlist, so
 * a credential leaking into an unexpected header is still observable. Present
 * only under the {@code gateway-test} profile — never in a real deployment.
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
      // Join multiple values with ", " so a duplicated header (e.g. two
      // Authorization values from an append-instead-of-overwrite bug) is
      // visible to the gateway-injection assertion, not silently collapsed.
      headers.put(
          name.toLowerCase(Locale.ROOT),
          String.join(", ", Collections.list(request.getHeaders(name))));
    }
    return Map.of(
        "method", request.getMethod(),
        "queryString", request.getQueryString() == null ? "" : request.getQueryString(),
        "headers", headers);
  }
}
