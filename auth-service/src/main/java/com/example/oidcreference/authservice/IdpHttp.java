package com.example.oidcreference.authservice;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import java.time.Duration;

/**
 * Transport bounds for every outbound HTTP call to the IdP made through the
 * Nimbus SDK (token exchange, token refresh, discovery). Nimbus
 * {@link HTTPRequest} defaults both timeouts to 0 — infinite, per
 * {@code HttpURLConnection} semantics — so a hung IdP would otherwise pin a
 * servlet thread forever; on the refresh path that thread also holds the
 * per-sid refresh lock, turning one stalled Keycloak into auth-service
 * thread-pool exhaustion. (The JWKS fetches are not routed through here:
 * Nimbus's {@code JWKSourceBuilder} retriever ships its own finite
 * defaults.) The values are configuration knobs (see
 * {@link AuthProperties#idpConnectTimeout()} / {@link AuthProperties#idpReadTimeout()}),
 * not constants.
 */
final class IdpHttp {
  private IdpHttp() {
  }

  static HTTPRequest withTimeouts(HTTPRequest request, Duration connect, Duration read) {
    request.setConnectTimeout((int) connect.toMillis());
    request.setReadTimeout((int) read.toMillis());
    return request;
  }
}
