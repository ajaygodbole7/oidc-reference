package com.example.oidcreference;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Profile("gateway-test")
@RestController
@RequestMapping("/api/_test")
class GatewayTestEchoController {
  private static final List<String> ECHO_HEADERS = List.of(
      "cookie",
      "connection",
      "keep-alive",
      "proxy-authorization",
      "te",
      "trailer",
      "transfer-encoding",
      "upgrade",
      "x-should-strip");

  @GetMapping("/echo")
  Map<String, Object> echo(HttpServletRequest request) {
    Map<String, String> headers = new LinkedHashMap<>();
    for (String header : ECHO_HEADERS) {
      String value = request.getHeader(header);
      headers.put(header, value == null ? "" : value);
    }
    return Map.of(
        "method", request.getMethod(),
        "queryString", request.getQueryString() == null ? "" : request.getQueryString(),
        "headers", headers);
  }
}
