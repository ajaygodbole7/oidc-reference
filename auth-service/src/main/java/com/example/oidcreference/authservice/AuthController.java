package com.example.oidcreference.authservice;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Browser-facing OIDC endpoints under {@code /auth} (login, callback, me,
 * logout, logout/continue).
 *
 * <p>Design decision (O5/A5): this controller is deliberately kept cohesive
 * rather than split per-endpoint. All of its handlers share one tightly-coupled
 * core — the {@code oauth_tx} browser-binding cookie, the {@code sess:{sid}}
 * lifecycle, and the strict token-isolation invariant (no access/refresh/id
 * token ever reaches the browser). Splitting along HTTP routes would scatter
 * that shared state and its invariants across files and invite a future change
 * to satisfy one route while breaking the isolation contract on another. The
 * cohesion is the safer default here; revisit only if the shared core is
 * genuinely factored out.
 */
@RestController
@RequestMapping("/auth")
class AuthController {
  private static final Duration TX_TTL = Duration.ofMinutes(5);
  // Short-lived, single-use handle that lets /auth/logout/continue emit the IdP
  // end-session redirect server-side, so the id_token never reaches the browser.
  private static final Duration LOGOUT_TTL = Duration.ofMinutes(2);
  private static final String SECURE_SID_NAME = "__Host-sid";
  private static final String LOCAL_SID_NAME = "sid";
  private static final String XSRF_COOKIE_NAME = "XSRF-TOKEN";
  private static final int RETURN_TO_MAX_DECODED_LENGTH = 2048;
  private static final String RETURN_TO_INVALID_DETAIL =
      "return_to is required and must be a same-origin relative path";
  // RFC 3986 scheme regex: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) followed by ":".
  // Catches http:, https:, javascript:, data:, etc. — any absolute URL form.
  private static final Pattern ABSOLUTE_URL_SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.\\-]*:");

  private final StateStore stateStore;
  private final JsonCodec json;
  private final OidcProviderMetadata md;
  private final TokenExchangeClient tokenExchangeClient;
  private final AuthProperties props;
  private final SignedCsrfSupport csrf;
  private final SessionIndexes sessionIndexes;

  AuthController(
      StateStore stateStore,
      JsonCodec json,
      OidcProviderMetadata md,
      TokenExchangeClient tokenExchangeClient,
      AuthProperties props,
      SignedCsrfSupport csrf,
      SessionIndexes sessionIndexes) {
    this.stateStore = stateStore;
    this.json = json;
    this.md = md;
    this.tokenExchangeClient = tokenExchangeClient;
    this.props = props;
    this.csrf = csrf;
    this.sessionIndexes = sessionIndexes;
  }

  @GetMapping("/login")
  ResponseEntity<?> login(
      @RequestParam(name = "return_to", required = false) @Nullable String returnTo,
      HttpServletRequest request) {
    if (!isValidReturnTo(returnTo)) {
      SecurityAudit.event(request, 400, "login_rejected", "invalid_return_to");
      return badReturnTo();
    }
    return beginLogin(request, returnTo, false);
  }

  // Step-up authentication. Reached when a sensitive resource rejects a session
  // whose last interactive authentication is too old (the Resource Server's
  // auth_time freshness gate). Reuses the same same-origin return_to contract as
  // /auth/login, but adds `prompt=login` so the IdP forces a fresh credential
  // entry regardless of an existing SSO session; the callback then enforces that
  // the returned auth_time post-dates this request. We use prompt=login (OIDC
  // Core §3.1.2.1) rather than max_age=0 because Keycloak — like several IdPs —
  // treats max_age=0 as "unset" and silently reuses the SSO session; prompt=login
  // is the portable, reliable "re-authenticate now" lever.
  @GetMapping("/step-up")
  ResponseEntity<?> stepUp(
      @RequestParam(name = "return_to", required = false) @Nullable String returnTo,
      HttpServletRequest request) {
    if (!isValidReturnTo(returnTo)) {
      SecurityAudit.event(request, 400, "step_up_rejected", "invalid_return_to");
      return badReturnTo();
    }
    return beginLogin(request, returnTo, true);
  }

  ResponseEntity<Void> beginLogin(HttpServletRequest request, String savedRequest) {
    return beginLogin(request, savedRequest, false);
  }

  ResponseEntity<Void> beginLogin(
      HttpServletRequest request, String savedRequest, boolean stepUp) {
    var state = CryptoSupport.randomUrlToken(32);
    var codeVerifier = new CodeVerifier();
    var codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
    var nonce = CryptoSupport.randomUrlToken(32);

    // Browser-binding token. PKCE, state, and nonce don't bind the
    // callback to the originating browser; an attacker who exfiltrates
    // (code, state) could otherwise complete the callback in their own
    // user-agent. The hash goes in tx:{state}; the raw value rides as
    // an HttpOnly cookie scoped to /auth/callback/idp so the IdP's
    // 302-back is the only request that ever carries it.
    var txCookieValue = OAuthTxBinding.issueCookieValue();
    var txCookieHash = OAuthTxBinding.hash(txCookieValue, props.cookieSigningKey());

    var transaction = new OAuthTransaction(
        codeVerifier.getValue(),
        nonce,
        normalizeSavedRequest(savedRequest),
        Instant.now(),
        txCookieHash,
        stepUp);
    stateStore.put("tx:" + state, json.encode(transaction), TX_TTL);

    var authorizationBuilder = UriComponentsBuilder
        .fromUri(md.authorizationEndpoint())
        .queryParam("response_type", "code")
        .queryParam("client_id", md.clientId())
        .queryParam("scope", String.join(" ", md.scopes()))
        .queryParam("redirect_uri", redirectUri(request))
        .queryParam("state", state)
        .queryParam("nonce", nonce)
        .queryParam("code_challenge", codeChallenge.getValue())
        .queryParam("code_challenge_method", "S256");
    if (stepUp) {
      // OIDC Core §3.1.2.1 prompt=login: the IdP MUST re-authenticate the user,
      // refreshing auth_time, regardless of an existing SSO session. Portable
      // across IdPs (Keycloak treats max_age=0 as unset and would reuse the SSO
      // session); the callback verifies the returned auth_time post-dates this.
      authorizationBuilder.queryParam("prompt", "login");
      // RFC 9470 assurance axis: ask the IdP for a minimum acr (LoA). The
      // returned acr is enforced by the Resource Server on sensitive routes.
      // Optional and config-driven (app.step-up-acr-values) — omitted when unset.
      if (props.stepUpAcrValues() != null && !props.stepUpAcrValues().isBlank()) {
        authorizationBuilder.queryParam("acr_values", props.stepUpAcrValues());
      }
    }
    var authorizationUri = authorizationBuilder.encode().toUriString();

    boolean secure = isSecureRequest(request);
    var txCookieName = OAuthTxBinding.cookieName(state);
    var txCookie = oauthTxCookie(txCookieName, txCookieValue, TX_TTL, secure);

    SecurityAudit.event(
        request, 302, stepUp ? "step_up_started" : "login_started", "ok");
    return ResponseEntity.status(HttpStatus.FOUND)
        .header(HttpHeaders.LOCATION, authorizationUri)
        .header(HttpHeaders.SET_COOKIE, txCookie.toString())
        .build();
  }

  @GetMapping("/callback/idp")
  ResponseEntity<?> callback(
      @RequestParam(required = false) @Nullable String code,
      @RequestParam(name = "error", required = false) @Nullable String error,
      @RequestParam String state,
      @RequestParam(name = "iss", required = false) @Nullable String iss,
    HttpServletRequest request) {
    boolean secure = isSecureRequest(request);
    var clearTxCookie = clearOauthTxCookie(state, secure);

    // OAuth error redirect: the IdP returns ?error=...&state=... (e.g. the
    // user clicked "Deny") and omits `code`. Consume the transaction so it
    // does not linger until its TTL, evict the browser-binding cookie, and
    // return the user to the app home rather than a raw framework 400.
    //
    // Deliberate tradeoff (applies here AND to the code path below): the tx is
    // consumed on EVERY callback outcome, including rejection — it is single-use,
    // and an iss-mismatch / mix-up probe burns it so it cannot be retried (see
    // the iss check below: "rejected with the tx already consumed"). The cost is
    // a narrow denial-of-login: a party who knows the 256-bit `state` can fire a
    // forged error- or code-callback to consume a victim's in-flight tx, so the
    // victim's genuine callback then fails invalid_state. We accept it: `state`
    // is a server-generated secret not normally exposed, the window is the tx TTL
    // (minutes), and the alternative — defer the consume until after the oauth_tx
    // browser-binding verifies — would forfeit the single-use / mix-up burn that
    // matters more. Browser binding still gates everything that touches a SESSION
    // or token (below); only the pending-tx cleanup is state-only.
    if ((error != null && !error.isBlank()) || code == null) {
      stateStore.getAndDelete("tx:" + state);
      String reason = (error != null && !error.isBlank()) ? "idp_error" : "missing_code";
      SecurityAudit.event(request, 302, "callback_failed", reason);
      return ResponseEntity.status(HttpStatus.FOUND)
          .cacheControl(CacheControl.noStore())
          .header(HttpHeaders.LOCATION, "/")
          .header(HttpHeaders.SET_COOKIE, clearTxCookie.toString())
          .build();
    }

    var txKey = "tx:" + state;
    Optional<String> encoded = stateStore.getAndDelete(txKey);
    if (encoded.isEmpty()) {
      SecurityAudit.event(request, 400, "callback_failed", "invalid_state");
      return callbackError(HttpStatus.BAD_REQUEST, "invalid oauth transaction", clearTxCookie);
    }
    var transaction = json.decode(encoded.get(), OAuthTransaction.class);

    // RFC 9700 §4.4 / RFC 9207 — authorization server mix-up defense. A
    // malicious IdP can convince the user to complete a flow on its
    // endpoint and then redirect to our callback with (code, state, iss).
    // If we don't check iss against our configured issuer, we will
    // forward those credentials to OUR token endpoint, which either
    // (a) errors out and leaks state, or (b) succeeds if the attacker
    // managed to also get its IdP federated. Absent iss is accepted —
    // not every IdP emits it yet — but a PRESENT iss that disagrees
    // with our issuer is rejected with the tx already consumed.
    if (iss != null && !iss.isBlank() && !iss.equals(md.issuer())) {
      SecurityAudit.event(request, 400, "callback_failed", "iss_mismatch");
      return callbackError(
          HttpStatus.BAD_REQUEST, "iss parameter does not match issuer", clearTxCookie);
    }

    // Browser-binding check. The transaction was created in some
    // browser at /auth/login; only that browser holds the oauth_tx
    // cookie value whose HMAC we stored. Mismatch means this callback
    // is being attempted in a different user-agent (or the cookie was
    // dropped — same outcome, refuse). A null stored hash means the
    // transaction was created before browser binding existed, OR a
    // stale Redis entry was forged: either way, fail closed and emit
    // the binding-skipped audit event so the operator sees the
    // signal. Silently skipping (the previous behavior) would have
    // turned every old / forged tx into a free bypass.
    if (transaction.txCookieHash() == null) {
      SecurityAudit.event(request, 400, "callback_failed", "missing_tx_binding");
      return callbackError(
          HttpStatus.BAD_REQUEST,
          "oauth transaction has no browser binding",
          clearTxCookie);
    }
    var suppliedCookie = SignedCsrfSupport
        .cookieValue(request, OAuthTxBinding.cookieName(state))
        .orElse(null);
    if (!OAuthTxBinding.verify(
        suppliedCookie, transaction.txCookieHash(), props.cookieSigningKey())) {
      SecurityAudit.event(
          request, 400, "callback_failed",
          suppliedCookie == null ? "missing_tx_cookie" : "tx_cookie_mismatch");
      return callbackError(
          HttpStatus.BAD_REQUEST,
          "oauth transaction not bound to this browser",
          clearTxCookie);
    }

    SessionRecord session;
    try {
      session = tokenExchangeClient.exchange(code, state, redirectUri(request), transaction);
    } catch (RuntimeException e) {
      SecurityAudit.event(request, 401, "callback_failed", "token_exchange_failed");
      return callbackError(HttpStatus.UNAUTHORIZED, "oauth callback rejected", clearTxCookie);
    }
    // Step-up gate: if this transaction asked for a fresh authentication, the
    // returned id_token's auth_time must post-date the request. An IdP that
    // ignored max_age (returning a stale SSO auth_time) fails closed here, so a
    // step-up can never "succeed" without a genuine re-auth — which would
    // otherwise loop the SPA against the Resource Server's freshness gate.
    if (!stepUpAuthFresh(transaction, session.claims())) {
      SecurityAudit.event(
          request, 401, "callback_failed", "step_up_not_fresh", subjectClaim(session));
      return callbackError(
          HttpStatus.UNAUTHORIZED, "step-up authentication was not fresh", clearTxCookie);
    }
    var sid = CryptoSupport.randomUrlToken(32);
    // Issue a signed, session-bound CSRF token. The signed shape `<value>.<hmac>` is what every
    // subsequent state-changing request (logout, gateway-routed POSTs)
    // will validate against, with the HMAC computed over `value + ":" + sid`.
    var signedCsrf = SignedCsrfSupport.issueToken(props.cookieSigningKey(), sid);
    Instant createdAt = Instant.now();
    session = new SessionRecord(
        session.accessToken(),
        session.refreshToken(),
        session.idToken(),
        session.expiresAt(),
        session.refreshExpiresAt(),
        createdAt,
        createdAt.plus(props.sessionAbsoluteTtl()),
        // The refresh token was just minted by the code exchange; stamp its
        // age baseline so app.max-refresh-token-age (if set) measures from here.
        createdAt,
        session.claims());

    Duration sessionTtl = session.nextTtl(props.sessionIdleTtl());
    stateStore.put("sess:" + sid, json.encode(session), sessionTtl);
    sessionIndexes.index(sid, session);
    var savedRequest = normalizeSavedRequest(transaction.savedRequest());

    // Cookie Max-Age is the ABSOLUTE ceiling, not the idle TTL. The cookies
    // are issued exactly once — the Auth Service slides only the Valkey sess:
    // key (in /internal/resolve) and never re-issues Set-Cookie — so an idle-TTL Max-Age would
    // hard-stop every browser session 30 minutes after login and the
    // sliding-idle design could never take effect. Lifetime enforcement is
    // server-side (sliding sess: TTL + absolute ceiling); a cookie that
    // outlives its dead session just earns a 302 back to /auth/login.
    var sidCookie = sidCookie(sid, props.sessionAbsoluteTtl(), secure);
    var xsrfCookie = xsrfCookie(signedCsrf, props.sessionAbsoluteTtl(), secure);

    SecurityAudit.event(request, 302, "callback_succeeded", "ok", subjectClaim(session));
    return ResponseEntity.status(HttpStatus.FOUND)
        .cacheControl(CacheControl.noStore())
        .header(HttpHeaders.LOCATION, savedRequest)
        .header("Referrer-Policy", "no-referrer")
        .header(HttpHeaders.SET_COOKIE, sidCookie.toString())
        .header(HttpHeaders.SET_COOKIE, xsrfCookie.toString())
        // Single-use: even on success, evict the oauth_tx cookie so a
        // replayed (code, state) cannot match a stale browser binding.
        .header(HttpHeaders.SET_COOKIE, clearTxCookie.toString())
        .build();
  }

  @GetMapping("/me")
  ResponseEntity<MeResponse> me(HttpServletRequest request) {
    Optional<SessionRecord> session = session(request);
    if (session.isEmpty()) {
      SecurityAudit.event(request, 401, "auth_denied", "no_session");
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .cacheControl(CacheControl.noStore())
          .header(HttpHeaders.VARY, "Cookie")
          .build();
    }
    // Cache-Control: no-store should be enough on its own, but any
    // non-RFC-compliant intermediate cache (forward proxy, CDN
    // pass-through, service worker) needs Vary: Cookie to refuse to
    // serve one user's /auth/me response to another with a different
    // session cookie. Defense in depth, costs one header.
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .header(HttpHeaders.VARY, "Cookie")
        .body(projectMe(session.get().claims()));
  }

  // /auth/me is the server-owned public identity contract. Project the stored
  // claim map to a typed, allow-listed record so a future IdP claim, a nested
  // provider object, or token-shaped material in the session can never reach the
  // browser regardless of what the validator wrote — the server enforces the
  // contract, not the SPA's sanitizer. snake_case wire names match what the SPA
  // reads; NON_NULL omits absent optional fields (the prior putIfPresent shape).
  @JsonInclude(JsonInclude.Include.NON_NULL)
  record MeResponse(
      @Nullable String sub,
      @JsonProperty("preferred_username") @Nullable String preferredUsername,
      @Nullable String name,
      @Nullable String email,
      List<String> roles,
      @JsonProperty("auth_time") @Nullable Long authTime,
      @Nullable String acr) {}

  // Logout hands the SPA a SAME-ORIGIN continuation URL to navigate to; the IdP
  // end-session redirect (carrying id_token_hint) is emitted server-side at
  // /auth/logout/continue, so no id_token reaches the browser. Typed so the wire
  // contract is explicit rather than an ad-hoc map.
  record LogoutResponse(String logoutUrl) {}

  private static MeResponse projectMe(Map<String, Object> claims) {
    return new MeResponse(
        claimString(claims, "sub"),
        claimString(claims, "preferred_username"),
        claimString(claims, "name"),
        claimString(claims, "email"),
        claimStringList(claims, "roles"),
        claimEpochSeconds(claims, "auth_time"),
        claimString(claims, "acr"));
  }

  private static @Nullable String claimString(Map<String, Object> claims, String key) {
    return claims.get(key) instanceof String s ? s : null;
  }

  // auth_time is stored as epoch seconds; a JSON round-trip through the state
  // store may bring it back as Integer or Long, so read any Number.
  private static @Nullable Long claimEpochSeconds(Map<String, Object> claims, String key) {
    return claims.get(key) instanceof Number n ? n.longValue() : null;
  }

  private static List<String> claimStringList(Map<String, Object> claims, String key) {
    if (!(claims.get(key) instanceof Collection<?> values)) {
      return List.of();
    }
    List<String> result = new ArrayList<>();
    for (Object value : values) {
      if (value instanceof String s) {
        result.add(s);
      }
    }
    return List.copyOf(result);
  }

  @PostMapping("/logout")
  ResponseEntity<?> logout(HttpServletRequest request) {
    Optional<String> sid = sessionId(request);
    Optional<SessionRecord> session = sid.flatMap(this::session);
    if (session.isEmpty()) {
      String continuation = logoutContinuation(
          request,
          sid.flatMap(sessionIndexes::consumeLogoutHint));
      boolean secure = isSecureRequest(request);
      var clearSid = clearCookie(sessionCookieName(request), "/", secure);
      var clearXsrf = clearCookie(XSRF_COOKIE_NAME, "/", secure);
      SecurityAudit.event(request, acceptsJson(request) ? 200 : 302,
          "logout_succeeded", "no_local_session");
      if (acceptsJson(request)) {
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .header(HttpHeaders.SET_COOKIE, clearSid.toString())
            .header(HttpHeaders.SET_COOKIE, clearXsrf.toString())
            .body(new LogoutResponse(continuation));
      }
      return ResponseEntity.status(HttpStatus.FOUND)
          .cacheControl(CacheControl.noStore())
          .header(HttpHeaders.LOCATION, continuation)
          .header(HttpHeaders.SET_COOKIE, clearSid.toString())
          .header(HttpHeaders.SET_COOKIE, clearXsrf.toString())
          .build();
    }
    if (!csrf.hasValidCsrf(request, props.cookieSigningKey(), sid.get())) {
      SecurityAudit.event(request, 403, "auth_denied", "csrf_invalid");
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .cacheControl(CacheControl.noStore())
          .build();
    }
    // The IdP end-session URL carries id_token_hint=<full id_token> (PII).
    // Never hand it to the browser: stash it server-side under a single-use
    // opaque handle and return a SAME-ORIGIN continuation URL. The actual IdP
    // redirect is emitted by GET /auth/logout/continue, so the id_token never
    // reaches browser JS or the SPA-readable body — the headline invariant.
    String continuation = logoutContinuation(request, Optional.ofNullable(session.get().idToken()));
    sid.ifPresent(this::deleteSession);
    boolean secure = isSecureRequest(request);
    var clearSid = clearCookie(sessionCookieName(request), "/", secure);
    var clearXsrf = clearCookie(XSRF_COOKIE_NAME, "/", secure);
    SecurityAudit.event(request, acceptsJson(request) ? 200 : 302,
        "logout_succeeded", "ok", subjectClaim(session.get()));
    if (acceptsJson(request)) {
      return ResponseEntity.ok()
          .cacheControl(CacheControl.noStore())
          .header(HttpHeaders.SET_COOKIE, clearSid.toString())
          .header(HttpHeaders.SET_COOKIE, clearXsrf.toString())
          .body(new LogoutResponse(continuation));
    }
    return ResponseEntity.status(HttpStatus.FOUND)
        .cacheControl(CacheControl.noStore())
        .header(HttpHeaders.LOCATION, continuation)
        .header(HttpHeaders.SET_COOKIE, clearSid.toString())
        .header(HttpHeaders.SET_COOKIE, clearXsrf.toString())
        .build();
  }

  // Server-side logout continuation. The SPA performs a top-level navigation to
  // the opaque handle returned by POST /auth/logout; this endpoint resolves it
  // and 302s to the IdP end-session URL (id_token_hint). The id_token therefore
  // only ever appears in a server-emitted redirect — never in a body or URL the
  // SPA's JavaScript reads. No session is required (it is already deleted); the
  // single-use handle is the capability. Referrer-Policy: no-referrer keeps the
  // id_token in the redirect URL out of the Referer of IdP-loaded resources.
  @GetMapping("/logout/continue")
  ResponseEntity<Void> logoutContinue(
      @RequestParam(name = "lc", required = false) @Nullable String lc) {
    String target = "/";
    if (lc != null && !lc.isBlank()) {
      target = stateStore.getAndDelete("logout:" + lc).orElse("/");
    }
    return ResponseEntity.status(HttpStatus.FOUND)
        .cacheControl(CacheControl.noStore())
        .header(HttpHeaders.LOCATION, target)
        .header("Referrer-Policy", "no-referrer")
        .build();
  }

  private String logoutContinuation(HttpServletRequest request, Optional<String> idTokenHint) {
    String idpLogout = logoutRedirect(request, idTokenHint);
    if ("/".equals(idpLogout)) {
      return "/";
    }
    String handle = CryptoSupport.randomUrlToken(32);
    stateStore.put("logout:" + handle, idpLogout, LOGOUT_TTL);
    return "/auth/logout/continue?lc=" + handle;
  }

  // Step-up freshness gate. A step-up flow must return an id_token whose
  // auth_time is at or after the moment the transaction was initiated — proof
  // the IdP honored max_age and genuinely re-authenticated the user instead of
  // silently reusing an older SSO session. Ordinary (non-step-up) logins carry
  // no freshness requirement. A step-up that returns no auth_time, or an
  // auth_time predating the request, fails closed. Package-private + static so
  // it is unit-tested directly without a Spring context.
  static boolean stepUpAuthFresh(OAuthTransaction transaction, Map<String, Object> claims) {
    if (!transaction.isStepUp()) {
      return true;
    }
    Object authTime = claims == null ? null : claims.get("auth_time");
    if (!(authTime instanceof Number n)) {
      return false;
    }
    return n.longValue() >= transaction.createdAt().getEpochSecond();
  }

  private static @Nullable String subjectClaim(@Nullable SessionRecord session) {
    if (session == null || session.claims() == null) {
      return null;
    }
    Object sub = session.claims().get("sub");
    return sub == null ? null : sub.toString();
  }

  Optional<SessionRecord> session(HttpServletRequest request) {
    return sessionId(request).flatMap(this::session);
  }

  Optional<String> sessionId(HttpServletRequest request) {
    var fromHost = SignedCsrfSupport.cookieValue(request, SECURE_SID_NAME);
    if (fromHost.isPresent()) {
      return fromHost;
    }
    // Cookie-tossing / forced-login defense: on a secure (HTTPS) request accept
    // ONLY __Host-sid. The bare `sid` name is minted only over local plaintext
    // HTTP (sidCookie); honoring it on HTTPS would re-open the sibling-subdomain
    // cookie injection the __Host- prefix exists to block at set time. Fail closed.
    if (isSecureRequest(request)) {
      return Optional.empty();
    }
    return SignedCsrfSupport.cookieValue(request, LOCAL_SID_NAME);
  }

  Optional<SessionRecord> session(String sid) {
    Optional<String> raw = stateStore.get("sess:" + sid);
    if (raw.isEmpty()) {
      return Optional.empty();
    }
    SessionRecord session;
    try {
      session = json.decode(raw.get(), SessionRecord.class);
    } catch (RuntimeException e) {
      deleteSession(sid);
      return Optional.empty();
    }
    if (session.absoluteExpired()) {
      deleteSession(sid);
      return Optional.empty();
    }
    return Optional.of(session);
  }

  void deleteSession(String sid) {
    sessionIndexes.deleteLocalSession(sid);
  }

  /**
   * Validate a browser-supplied {@code return_to} per the return-to-login
   * contract. The value must be a same-origin relative path beginning with
   * exactly one {@code "/"}. Rejects:
   *
   * <ul>
   *   <li>{@code null} or empty/blank values</li>
   *   <li>Any absolute URL form per RFC 3986 (matches {@code scheme:}) —
   *       e.g. {@code http://}, {@code https://}, {@code javascript:},
   *       {@code data:}</li>
   *   <li>Protocol-relative URLs beginning with {@code //}</li>
   *   <li>Values not beginning with {@code /}</li>
   *   <li>Values whose URL-decoded form exceeds 2048 chars</li>
   *   <li>Values containing an encoded backslash ({@code %5C}) used to
   *       defeat same-origin parsers</li>
   * </ul>
   */
  private static boolean isValidReturnTo(String returnTo) {
    if (returnTo == null || returnTo.isEmpty()) {
      return false;
    }
    // Backslash check: Spring's @RequestParam URL-decodes %5C → '\'
    // before binding, so we MUST check the decoded form (literal '\')
    // not just the raw '%5C' substring. Browsers normalise consecutive
    // backslashes to forward-slashes in Location headers; '/\\evil' can
    // become '//evil' and cross the origin.
    if (returnTo.indexOf('\\') >= 0) {
      return false;
    }
    // Belt-and-suspenders: also reject any literal %5C in the raw value
    // for callers that double-encode or bypass Spring's decoder.
    if (containsEncodedBackslash(returnTo)) {
      return false;
    }
    // Reject control characters (CR/LF/NUL/tab/etc.) — they enable
    // HTTP-response-splitting via the Location header on the callback.
    for (int i = 0; i < returnTo.length(); i++) {
      char c = returnTo.charAt(i);
      if (c < 0x20 || c == 0x7F) {
        return false;
      }
    }
    // Absolute URL with scheme (http:, https:, javascript:, data:, ...).
    if (ABSOLUTE_URL_SCHEME.matcher(returnTo).find()) {
      return false;
    }
    // Protocol-relative form //host/path.
    if (returnTo.startsWith("//")) {
      return false;
    }
    // Must be a path beginning with exactly one "/".
    if (!returnTo.startsWith("/")) {
      return false;
    }
    // Length check on the DECODED value so percent-encoded payloads
    // cannot smuggle oversized strings past a raw-length check.
    String decoded;
    try {
      decoded = URLDecoder.decode(returnTo, StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return false;
    }
    if (decoded.length() > RETURN_TO_MAX_DECODED_LENGTH) {
      return false;
    }
    return true;
  }

  private static boolean containsEncodedBackslash(String value) {
    // Case-insensitive: %5C, %5c.
    int len = value.length();
    for (int i = 0; i <= len - 3; i++) {
      if (value.charAt(i) == '%'
          && value.charAt(i + 1) == '5'
          && (value.charAt(i + 2) == 'C' || value.charAt(i + 2) == 'c')) {
        return true;
      }
    }
    return false;
  }

  private static ResponseEntity<ProblemDetail> badReturnTo() {
    ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
    problem.setType(URI.create("about:blank"));
    problem.setTitle("Bad Request");
    problem.setDetail(RETURN_TO_INVALID_DETAIL);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .cacheControl(CacheControl.noStore())
        .body(problem);
  }

  private String redirectUri(HttpServletRequest request) {
    return baseUrl(request) + "/auth/callback/idp";
  }

  private String logoutRedirect(HttpServletRequest request, Optional<String> idTokenHint) {
    if (md.endSessionEndpoint() == null) {
      return "/";
    }
    // No `state` on the end-session redirect. OIDC RP-Initiated Logout 1.0
    // allows a `state` round-trip, but only if it is validated on return.
    // post_logout_redirect_uri lands at the public "/" with no callback to
    // check it, so emitting `state` here would be emit-and-ignore — a hollow
    // gesture toward the spec, not the control it implies. We omit it rather
    // than ship an unvalidated token.
    UriComponentsBuilder builder = UriComponentsBuilder
        .fromUri(md.endSessionEndpoint())
        .queryParam("post_logout_redirect_uri", baseUrl(request) + "/")
        .queryParam("client_id", md.clientId());
    idTokenHint
        .filter(idToken -> !idToken.isBlank())
        .ifPresent(idToken -> builder.queryParam("id_token_hint", idToken));
    return builder.encode().toUriString();
  }

  // Every callback error path returns RFC 7807 problem+json, no-store,
  // no-referrer, and evicts the oauth_tx cookie. Centralising the
  // header set means a future header addition (Strict-Transport-
  // Security, Vary, etc.) lands in one place rather than four.
  // ProblemDetail keeps machine clients consistent with the other
  // error shapes in the auth-service (badReturnTo and the /internal
  // controller all use it); plain-text bodies were the previous
  // inconsistency.
  private static ResponseEntity<ProblemDetail> callbackError(
      HttpStatus status, String detail, ResponseCookie clearTxCookie) {
    ProblemDetail problem = ProblemDetail.forStatus(status);
    problem.setDetail(detail);
    return ResponseEntity.status(status)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .cacheControl(CacheControl.noStore())
        .header("Referrer-Policy", "no-referrer")
        .header(HttpHeaders.SET_COOKIE, clearTxCookie.toString())
        .body(problem);
  }

  private String baseUrl(HttpServletRequest request) {
    // Trust anchor. If app.base-url is configured, use it verbatim — the
    // operator has named the public-facing origin, and X-Forwarded-* must
    // not override it. This defeats Host-header / XFH injection where a
    // sibling app on the same gateway (or a misbehaving CDN) could steer
    // the IdP to a crafted redirect_uri whose authority is attacker-
    // controlled. Empty means "fall back to header-derived resolution",
    // which is the inner-loop dev convenience.
    String configured = props.baseUrl();
    if (configured != null && !configured.isBlank()) {
      return configured.endsWith("/")
          ? configured.substring(0, configured.length() - 1)
          : configured;
    }
    var scheme = Optional.ofNullable(request.getHeader("X-Forwarded-Proto")).orElse(request.getScheme());
    var host = Optional.ofNullable(request.getHeader("X-Forwarded-Host")).orElse(request.getServerName());
    var forwardedPort = request.getHeader("X-Forwarded-Port");
    // Resolution order for the authority:
    //   1. If X-Forwarded-Host already carries a port, that wins — the
    //      proxy is being explicit about the public-facing address.
    //   2. Otherwise prefer X-Forwarded-Port (the proxy's explicit
    //      public port).
    //   3. Otherwise fall back to the servlet's local port (auth-service
    //      running on 8081 in inner-loop dev).
    // The previous version silently dropped X-Forwarded-Port whenever
    // host carried a colon, which is correct, but also fell back to
    // request.getServerPort() (the BACKEND port, e.g. 8081) whenever
    // X-Forwarded-Port was missing — producing redirect_uri values
    // pointing at the internal port. The split here keeps the first
    // case explicit and uses the servlet port only as a true fallback.
    String authority;
    if (host.contains(":")) {
      authority = host;
    } else if (forwardedPort != null && !forwardedPort.isBlank()) {
      // A non-numeric X-Forwarded-Port is rejected upstream with a 400 by
      // Spring's ForwardedHeaderFilter (server.forward-headers-strategy:
      // framework), so this parse only ever sees a validated numeric value.
      authority = host + ":" + Integer.parseInt(forwardedPort);
    } else {
      authority = host + ":" + request.getServerPort();
    }
    return scheme + "://" + authority;
  }

  private static String sessionCookieName(HttpServletRequest request) {
    return isSecureRequest(request) ? SECURE_SID_NAME : LOCAL_SID_NAME;
  }

  private static boolean isSecureRequest(HttpServletRequest request) {
    var forwardedProto = request.getHeader("X-Forwarded-Proto");
    if (forwardedProto != null && !forwardedProto.isBlank()) {
      return "https".equalsIgnoreCase(forwardedProto);
    }
    return request.isSecure();
  }

  private static ResponseCookie sidCookie(String value, Duration maxAge, boolean secure) {
    // SameSite=Lax (not Strict) is required for the OAuth callback flow.
    // The browser-perceived navigation chain is:
    //   user → Keycloak (cross-site top-level nav)
    //   Keycloak → /auth/callback (cross-site redirect; sid is SET here)
    //   /auth/callback → /api/<saved_request> (same-site redirect)
    // Per the SameSite spec, the "site for cookies" of the continuation
    // request is determined by the navigation's CROSS-SITE INITIATOR
    // (Keycloak), so a Strict sid will NOT be sent on the final hop —
    // producing a redirect loop (the gateway sees no session, 302s back
    // to /auth/login, the user already has a Keycloak session, etc.).
    // Lax sends on top-level GETs including this redirect target, which
    // is exactly what BFF + OAuth needs. State-changing protection comes
    // from the signed double-submit CSRF (XSRF-TOKEN), not from sid's
    // SameSite. See https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
    // §5.4.7 for the cross-site-initiator rule.
    var builder = ResponseCookie.from(secure ? SECURE_SID_NAME : LOCAL_SID_NAME, value)
        .httpOnly(true)
        .sameSite("Lax")
        .path("/")
        .maxAge(maxAge);
    if (secure) {
      builder.secure(true);
    }
    return builder.build();
  }

  private static ResponseCookie oauthTxCookie(
      String name, String value, Duration maxAge, boolean secure) {
    // Path=/auth/callback/idp scopes the cookie tightly: the browser
    // only sends it on the callback hop, never on /api/** or /auth/me.
    // SameSite=Lax is required so the cross-site IdP redirect carries
    // it back. HttpOnly + Secure (when behind HTTPS) keeps JS out and
    // forces a TLS channel for production.
    var builder = ResponseCookie.from(name, value)
        .httpOnly(true)
        .sameSite("Lax")
        .path(OAuthTxBinding.COOKIE_PATH)
        .maxAge(maxAge);
    if (secure) {
      builder.secure(true);
    }
    return builder.build();
  }

  private static ResponseCookie clearOauthTxCookie(String state, boolean secure) {
    // Path and SameSite MUST match the issued cookie or some browsers
    // refuse the deletion. Max-Age=0 is the eviction signal.
    var builder = ResponseCookie.from(OAuthTxBinding.cookieName(state), "")
        .httpOnly(true)
        .sameSite("Lax")
        .path(OAuthTxBinding.COOKIE_PATH)
        .maxAge(Duration.ZERO);
    if (secure) {
      builder.secure(true);
    }
    return builder.build();
  }

  private static ResponseCookie xsrfCookie(String value, Duration maxAge, boolean secure) {
    // SameSite=Strict (not Lax). The XSRF cookie is JS-readable so the
    // SPA can echo it in X-XSRF-TOKEN on same-origin XHR; it never
    // needs to ride a cross-site top-level navigation. SameSite governs
    // SEND, not SET, so the cross-site Keycloak → callback redirect
    // that issues this cookie is unaffected. The signed-HMAC value
    // already defeats sibling-subdomain cookie injection; Strict
    // tightens the surface by preventing the cookie from being
    // attached to any cross-site request at all. The clear-cookie
    // helper below mirrors these attributes so Firefox accepts the
    // deletion.
    var builder = ResponseCookie.from(XSRF_COOKIE_NAME, value)
        .httpOnly(false)
        .sameSite("Strict")
        .path("/")
        .maxAge(maxAge);
    if (secure) {
      builder.secure(true);
    }
    return builder.build();
  }

  private static ResponseCookie clearCookie(String name, String path, boolean secure) {
    // Deletion cookies MUST mirror the attributes the cookie was set
    // with (Path, SameSite, HttpOnly, Secure); some browsers — Firefox
    // most strictly — refuse to evict a cookie when the attributes
    // differ, leaving the client with an orphaned credential.
    //
    // Per-name mirroring:
    //   sid / __Host-sid : HttpOnly + SameSite=Lax (sidCookie)
    //   XSRF-TOKEN       : !HttpOnly + SameSite=Strict (xsrfCookie)
    //
    // If a new cookie name is added that this helper has to clear, add
    // it here — the per-name attribute map is the contract.
    boolean isXsrf = XSRF_COOKIE_NAME.equals(name);
    var builder = ResponseCookie.from(name, "")
        .httpOnly(!isXsrf)
        .sameSite(isXsrf ? "Strict" : "Lax")
        .path(path)
        .maxAge(Duration.ZERO);
    if (secure) {
      builder.secure(true);
    }
    return builder.build();
  }

  private static String normalizeSavedRequest(String savedRequest) {
    if (savedRequest == null || savedRequest.isBlank()) {
      return "/";
    }
    URI uri;
    try {
      uri = URI.create(savedRequest);
    } catch (IllegalArgumentException e) {
      return "/";
    }
    if (uri.isAbsolute() || !savedRequest.startsWith("/")) {
      return "/";
    }
    if (savedRequest.startsWith("//")) {
      return "/";
    }
    return savedRequest;
  }

  private static boolean acceptsJson(HttpServletRequest request) {
    var accept = request.getHeader(HttpHeaders.ACCEPT);
    return accept != null && accept.contains(MediaType.APPLICATION_JSON_VALUE);
  }
}
