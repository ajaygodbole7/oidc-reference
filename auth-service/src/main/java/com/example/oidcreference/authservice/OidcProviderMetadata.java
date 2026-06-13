package com.example.oidcreference.authservice;

import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.net.URI;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Snapshot of the OpenID Provider configuration loaded once at startup.
 *
 * <p>Replaces Spring's {@code ClientRegistration} for our purposes: the Auth
 * Service needs the endpoint URIs (authorize, token, jwks, end-session), the
 * issuer identifier, and the bound client credentials. We fetch the discovery
 * document via Nimbus's {@link OIDCProviderConfigurationRequest} so we don't
 * depend on Spring Security's OAuth2 client to do it.
 *
 * <p>The {@code scopes} field is the Auth Service's configured list —
 * discovery advertises what the OP <em>supports</em>, not what this RP
 * <em>requests</em>; those are separate choices.
 */
public record OidcProviderMetadata(
    String clientId,
    String clientSecret,
    URI authorizationEndpoint,
    URI tokenEndpoint,
    URI jwksUri,
    @Nullable URI endSessionEndpoint,
    String issuer,
    Set<String> scopes) {

  // Override toString so clientSecret never lands in heap dumps,
  // exception messages, or accidental log lines. Record accessors are
  // still public — callers that want the secret must ask by name.
  @Override
  public String toString() {
    return "OidcProviderMetadata[clientId=" + clientId
        + ", clientSecret=<redacted>"
        + ", authorizationEndpoint=" + authorizationEndpoint
        + ", tokenEndpoint=" + tokenEndpoint
        + ", jwksUri=" + jwksUri
        + ", endSessionEndpoint=" + endSessionEndpoint
        + ", issuer=" + issuer
        + ", scopes=" + scopes + ']';
  }

  static OidcProviderMetadata discover(AuthProperties props) {
    if (props.authorizationUri() != null && props.tokenUri() != null && props.jwksUri() != null) {
      return new OidcProviderMetadata(
          props.clientId(),
          props.clientSecret(),
          props.authorizationUri(),
          props.tokenUri(),
          props.jwksUri(),
          props.endSessionUri(),
          props.issuerUri().toString(),
          props.scopes());
    }
    try {
      var req = new OIDCProviderConfigurationRequest(new Issuer(props.issuerUri().toString()));
      var m = OIDCProviderMetadata.parse(
          IdpHttp.withTimeouts(
              req.toHTTPRequest(),
              props.idpConnectTimeout(), props.idpReadTimeout()).send().getBodyAsJSONObject());
      return new OidcProviderMetadata(
          props.clientId(),
          props.clientSecret(),
          m.getAuthorizationEndpointURI(),
          m.getTokenEndpointURI(),
          m.getJWKSetURI(),
          m.getEndSessionEndpointURI(),
          requireMatchingIssuer(m.getIssuer().getValue(), props.issuerUri().toString()),
          props.scopes());
    } catch (Exception e) {
      throw new IllegalStateException("OIDC discovery failed at " + props.issuerUri(), e);
    }
  }

  // OIDC Discovery / RFC 8414 §3.3: the `issuer` in the discovery document MUST
  // be identical to the issuer used to fetch it. A mismatch means the document
  // was served by — or redirected to — a different authority, which is an
  // issuer mix-up vector. Fail closed at startup rather than trust a drifted
  // issuer for the rest of the process lifetime. Exact string equality is what
  // the spec requires (no normalization).
  static String requireMatchingIssuer(String discovered, String configured) {
    if (!configured.equals(discovered)) {
      throw new IllegalStateException(
          "OIDC discovery issuer mismatch: document advertised '" + discovered
          + "' but configured issuer is '" + configured + "'");
    }
    return discovered;
  }
}
