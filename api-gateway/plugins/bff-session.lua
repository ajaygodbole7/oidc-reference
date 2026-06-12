--
-- bff-session — APISIX Lua plugin
--
-- Source of truth:
--   docs/specs/SPEC-0001-core-oidc-flows.md
--     §"API Gateway Architecture (APISIX)"
--     §7.1 /internal/resolve contract
--     §7.3 signed CSRF contract
--
-- Phantom-token shape: the gateway holds ONLY the opaque session id. It has
-- no Valkey client and no knowledge of the session schema; it introspects the
-- sid via the Auth Service to obtain the access token it injects upstream.
--
-- Pipeline executed in the APISIX `access` phase on every matched
-- /api/** request:
--   1. Read session cookie (__Host-sid in HTTPS, sid in HTTP).
--   2. No cookie -> Fetch-Metadata classifier (navigation -> 302
--      /auth/login?return_to=..., else -> 401 problem+json).
--   3. Signed CSRF validation on POST/PUT/DELETE/PATCH (sid from the cookie;
--      no store read).
--   4. POST /internal/resolve {sid} on the Auth Service (Client-Credentials
--      bearer, cached per worker). It looks up the session, slides the idle
--      window, refreshes the access token if near expiry, and returns the
--      current token. 404/409 -> session gone; 502/transport -> 503.
--   5. Strip Cookie + hop-by-hop headers; inject Authorization: Bearer.
--   6. Header_filter phase adds Cache-Control: no-store on the response.
--
-- The plugin's gateway-client identity and the CSRF signing key are supplied
-- via plugin conf in apisix.yaml. No secrets are hard-coded in this module.
--

local core        = require("apisix.core")
local cjson       = require("cjson.safe")
local http        = require("resty.http")
local hmac        = require("resty.hmac")
local ngx         = ngx
local ngx_time    = ngx.time
local ngx_var     = ngx.var
local str_byte    = string.byte
local str_len     = string.len
local str_sub     = string.sub
local str_find    = string.find

local plugin_name = "bff-session"

-- Priority: must run before the upstream call (proxy phase). APISIX
-- built-in proxy-rewrite is 1008; ssl is 9000. We need to be high
-- enough to run before request body forwarding but not so high that we
-- race authn primitives. 2500 sits comfortably above proxy-rewrite and
-- below APISIX auth plugins, matching the brief.
local priority    = 2500

local schema = {
  type = "object",
  required = {
    "auth_service_base", "idp_token_url", "gateway_client_id",
    "gateway_client_secret", "cookie_signing_key",
  },
  properties = {
    -- The gateway holds NO session store handle. It resolves the sid into an
    -- access token by calling auth_service_base/internal/resolve (phantom
    -- token); session lookup, the idle-TTL slide, and refresh all live in the
    -- Auth Service, the sole reader/writer of sess:{sid}.
    auth_service_base       = { type = "string" },                   -- e.g. http://auth-service:8081
    idp_token_url           = { type = "string" },                   -- IdP /token endpoint for the Client-Credentials bearer
    gateway_client_id       = { type = "string" },
    gateway_client_secret   = { type = "string" },
    cookie_signing_key      = { type = "string" },                   -- std-base64-encoded 256-bit key
    -- Accept the bare `sid` cookie (no __Host- prefix). ONLY for local HTTP,
    -- where __Host- cookies (Secure-required) can't be set. Default false:
    -- production honors __Host-sid only and never a spoofable bare sid. (B3)
    allow_insecure_sid      = { type = "boolean", default = false },
  },
}

local _M = {
  version  = 0.1,
  priority = priority,
  name     = plugin_name,
  schema   = schema,
}

-- ---------------------------------------------------------------------
-- Header / cookie helpers
-- ---------------------------------------------------------------------

-- Hop-by-hop headers per RFC 7230 §6.1 plus Cookie / Host / Content-
-- Length / Authorization. Stripped from the upstream request so the
-- Resource Server sees only the gateway-injected Authorization header
-- and the path/body.
--
-- "authorization" is in this set defensively: the upstream injection at
-- the end of access() uses core.request.set_header which currently
-- overwrites the existing value, so an inbound Bearer from the browser
-- never reaches the RS today. But that safety relies on the set_header
-- semantics of APISIX's API rather than an explicit eviction here. If
-- the API ever changes to append, an attacker-supplied Authorization
-- would survive and the RS would see two Bearer headers (or worse, the
-- attacker's bearer would win). Explicit strip + explicit set is the
-- defense-in-depth shape; the cost is one set lookup per request.
local HOP_BY_HOP = {
  ["cookie"]              = true,
  ["connection"]          = true,
  ["keep-alive"]          = true,
  ["proxy-authenticate"]  = true,
  ["proxy-authorization"] = true,
  ["te"]                  = true,
  ["trailer"]             = true,
  ["transfer-encoding"]   = true,
  ["upgrade"]             = true,
  ["host"]                = true,     -- nginx sets Host based on upstream
  ["content-length"]      = true,     -- let nginx recompute
  ["authorization"]       = true,     -- gateway-injected; never trust inbound
}

-- Inbound identity headers a client must never be able to assert. The Resource
-- Server today ignores all client-supplied identity headers — it authorizes
-- ONLY on the gateway-injected bearer — so this strips nothing load-bearing
-- right now. It is defense-in-depth for the gateway-as-security-boundary
-- invariant: a future RS change that starts trusting `X-User` (or similar) must
-- not be reachable by a header an external client sent. Contract: the RS MUST
-- ignore all client-supplied identity headers; the gateway enforces it here too.
local IDENTITY_HEADERS = {
  ["x-user"]                          = true,
  ["x-forwarded-user"]                = true,
  ["x-forwarded-email"]               = true,
  ["x-forwarded-groups"]              = true,
  ["x-forwarded-preferred-username"]  = true,
  ["x-auth-request-user"]             = true,
  ["x-auth-request-email"]            = true,
  ["x-auth-request-groups"]           = true,
  ["x-auth-request-preferred-username"] = true,
  ["x-email"]                         = true,
  ["x-groups"]                        = true,
  ["x-roles"]                         = true,
  ["x-remote-user"]                   = true,
  ["remote-user"]                     = true,
  ["x-authenticated-user"]            = true,
  ["x-forwarded-access-token"]        = true,
  ["x-id-token"]                      = true,
}

-- Parse a Cookie header value into { name = value, ... }. We do this
-- ourselves rather than using ngx.var.cookie_* because the latter
-- depends on nginx's $cookie_NAME variable, which downcases the name
-- and silently fails on the __Host- prefix in some configs.
local function parse_cookies(cookie_header)
  local out = {}
  if not cookie_header or cookie_header == "" then
    return out
  end
  -- Split on "; " — allow optional surrounding whitespace per RFC 6265.
  for pair in cookie_header:gmatch("[^;]+") do
    local eq = pair:find("=", 1, true)
    if eq then
      local k = pair:sub(1, eq - 1):gsub("^%s+", ""):gsub("%s+$", "")
      local v = pair:sub(eq + 1)
      if k ~= "" then
        out[k] = v
      end
    end
  end
  return out
end

local function get_session_cookie(cookies, allow_insecure_sid)
  -- __Host-sid (Secure-bound) is honored unconditionally. The bare `sid`
  -- fallback exists only for local HTTP, where __Host- cookies (which require
  -- Secure) can't be set. It is accepted ONLY when the route explicitly opts in
  -- via allow_insecure_sid — NOT inferred from a client-supplied
  -- X-Forwarded-Proto, which a caller could spoof to coax the gateway into
  -- honoring a bare sid where only a bare sid is present (e.g. a TLS-terminating
  -- LB forwarding plaintext). Production leaves the flag off: __Host-sid only. (B3)
  if cookies["__Host-sid"] then
    return cookies["__Host-sid"]
  end
  if cookies["sid"] and allow_insecure_sid then
    return cookies["sid"]
  end
  return nil
end

local function effective_scheme(ctx)
  local forwarded = core.request.header(ctx, "X-Forwarded-Proto")
  if forwarded then
    forwarded = forwarded:lower()
    if forwarded == "https" or forwarded == "http" then
      return forwarded
    end
  end
  return ngx_var.scheme or "http"
end

-- ---------------------------------------------------------------------
-- Constant-time byte comparison
-- ---------------------------------------------------------------------

-- Compare two strings in constant time relative to their length. Both
-- inputs must be strings; nil is treated as a non-match. We deliberately
-- avoid `a == b` anywhere on token material — see SPEC §7.3.
local function constant_time_equals(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then
    return false
  end
  if str_len(a) ~= str_len(b) then
    return false
  end
  local diff = 0
  for i = 1, str_len(a) do
    -- XOR the bytes; OR the differences into `diff`. `diff` stays 0
    -- iff every byte matched. No early exit.
    diff = bit.bor(diff, bit.bxor(str_byte(a, i), str_byte(b, i)))
  end
  return diff == 0
end

-- ---------------------------------------------------------------------
-- Response helpers
-- ---------------------------------------------------------------------

local function problem_json(status, title, detail)
  -- RFC 7807 problem+json. Cache-Control: no-store is set by the
  -- header_filter phase, but we set it here too for paths that exit
  -- before reaching that phase (defense in depth).
  core.response.set_header("Content-Type", "application/problem+json")
  core.response.set_header("Cache-Control", "no-store")
  return core.response.exit(status, {
    type   = "about:blank",
    title  = title,
    status = status,
    detail = detail,
  })
end

local function expire_session_cookie(scheme)
  -- Clear whichever cookie name we accept on this scheme. Setting
  -- Max-Age=0 + the original attributes is the correct way to evict;
  -- omitting Secure on local HTTP keeps the browser from rejecting it.
  local name = (scheme == "https") and "__Host-sid" or "sid"
  local attrs = "; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
  if scheme == "https" then
    attrs = attrs .. "; Secure"
  end
  core.response.set_header("Set-Cookie", name .. "=" .. attrs)
end

-- Build the Set-Cookie strings re-issued on a sid rotation (A6). Pure (string
-- building) so it is unit-tested directly. Mirrors the Auth Service login
-- cookies EXACTLY so a later logout's clearCookie evicts them:
--   sid        : HttpOnly, SameSite=Lax       (AuthController.sidCookie)
--   XSRF-TOKEN : NOT HttpOnly (SPA reads it), SameSite=Strict (AuthController.xsrfCookie)
-- __Host-sid + Secure unless allow_insecure_sid (local HTTP) -> bare sid, no
-- Secure. The name/Secure decision keys on the route flag, NOT the spoofable
-- forwarded scheme. Max-Age = the session's remaining absolute lifetime.
local function build_rotation_cookies(rotated_sid, csrf, max_age, allow_insecure_sid)
  local secure = not allow_insecure_sid
  local sid_name = secure and "__Host-sid" or "sid"
  local max_age_attr = ""
  if type(max_age) == "number" and max_age > 0 then
    max_age_attr = "; Max-Age=" .. math.floor(max_age)
  end
  local secure_attr = secure and "; Secure" or ""
  local cookies = {
    sid_name .. "=" .. rotated_sid
      .. "; Path=/; HttpOnly; SameSite=Lax" .. max_age_attr .. secure_attr,
  }
  if csrf and csrf ~= "" then
    cookies[#cookies + 1] = "XSRF-TOKEN=" .. csrf
      .. "; Path=/; SameSite=Strict" .. max_age_attr .. secure_attr
  end
  return cookies
end

-- Build a same-origin redirect URL for the no-session navigation case.
-- We URL-encode the original path+query so saved_request survives the
-- round-trip through the AS unchanged.
local function build_login_redirect(scheme, host, uri)
  local return_to_val = uri or "/"
  -- ngx.escape_uri is path-safe and is what nginx uses internally.
  return "/auth/login?return_to=" .. ngx.escape_uri(return_to_val)
end

local function redirect_to_login(scheme, host, uri)
  core.response.set_header("Location", build_login_redirect(scheme, host, uri))
  core.response.set_header("Cache-Control", "no-store")
  return core.response.exit(302)
end

-- Decide between 302 (top-level navigation) and 401 (XHR/fetch) when
-- the request has no usable session. Per SPEC §"Login Entry Conditions":
-- Sec-Fetch-Mode: navigate + Sec-Fetch-Dest: document => navigation.
-- We treat the explicit Fetch-Metadata signals as authoritative;
-- Accept: text/html is a fallback for clients that strip Sec-Fetch-*.
local function no_session_response(ctx, conf, scheme, host, uri)
  local mode = core.request.header(ctx, "Sec-Fetch-Mode")
  local dest = core.request.header(ctx, "Sec-Fetch-Dest")
  local accept = core.request.header(ctx, "Accept")
  local is_navigation =
    (mode == "navigate" and dest == "document")
    or (mode == nil and dest == nil and accept and str_find(accept, "text/html", 1, true) ~= nil)

  if is_navigation then
    return redirect_to_login(scheme, host, uri)
  end
  -- XHR / fetch — 401 with no Location. The SPA must observe the 401
  -- and decide to perform a top-level navigation itself; this prevents
  -- the AS login HTML from being served into an XHR response.
  return problem_json(401, "Unauthorized", "no session")
end

-- ---------------------------------------------------------------------
-- Session resolution (phantom token)
-- ---------------------------------------------------------------------

-- The gateway holds NO session store handle. Session lookup, the idle-TTL
-- slide, and refresh all live behind the Auth Service's POST /internal/resolve,
-- called from resolve_session() below. There is no Redis/Valkey client here and
-- no knowledge of the sess:{sid} schema — only the Auth Service touches the
-- store.

-- ---------------------------------------------------------------------
-- Signed CSRF validation (mirrors auth-service SignedCsrfSupport)
-- ---------------------------------------------------------------------

-- Base64 (std) decoder for the signing key. lua-resty-string ships
-- only base64 helpers via ngx.encode_base64 / ngx.decode_base64; both
-- handle standard base64. (URL-safe base64 must be normalized first.)
local function decode_signing_key(b64_std)
  local key = ngx.decode_base64(b64_std)
  if not key or key == "" then
    return nil, "cookie_signing_key is not valid base64"
  end
  return key
end

-- Compute HMAC-SHA256(key, message) and return the base64url-encoded
-- digest WITHOUT padding — matching auth-service's
-- Base64.getUrlEncoder().withoutPadding() output exactly.
local function hmac_b64url(key, message)
  local h = hmac:new(key, hmac.ALGOS.SHA256)
  if not h then return nil, "hmac:new failed" end
  local ok = h:update(message)
  if not ok then return nil, "hmac:update failed" end
  local digest = h:final()
  if not digest then return nil, "hmac:final failed" end
  -- ngx.encode_base64(s, no_padding) => string. b64_urlsafe is
  -- post-translated below.
  local b64 = ngx.encode_base64(digest, true)  -- true: no padding
  -- Translate std-base64 to URL-safe.
  b64 = b64:gsub("+", "-"):gsub("/", "_")
  return b64
end

-- Returns true if the request passes CSRF validation. Methods that are
-- not state-changing skip validation entirely. On failure, the caller
-- issues 403 problem+json and stops.
--
-- Validation steps mirror auth-service.SignedCsrfSupport.validate:
--   1. Cookie and header both present.
--   2. Constant-time equal (cheap, breaks early-but-constant pattern).
--   3. Split on the LAST dot — value contains no dot but defense in
--      depth uses lastIndexOf to match the Java code.
--   4. Recompute HMAC, constant-time compare.
local function csrf_ok(ctx, conf, method, cookies, sid)
  if method ~= "POST" and method ~= "PUT"
     and method ~= "DELETE" and method ~= "PATCH" then
    return true
  end
  if not sid or sid == "" then
    return false, "csrf_missing_sid"
  end
  local cookie_token = cookies["XSRF-TOKEN"]
  local header_token = core.request.header(ctx, "X-XSRF-TOKEN")
  if not cookie_token or not header_token then
    return false, "csrf_missing"
  end
  if not constant_time_equals(cookie_token, header_token) then
    return false, "csrf_cookie_header_mismatch"
  end
  local dot = nil
  -- lastIndexOf('.')
  for i = str_len(cookie_token), 2, -1 do
    if str_byte(cookie_token, i) == 46 then  -- '.'
      dot = i
      break
    end
  end
  if not dot or dot == str_len(cookie_token) then
    return false, "csrf_malformed"
  end
  local value         = str_sub(cookie_token, 1, dot - 1)
  local supplied_hmac = str_sub(cookie_token, dot + 1)

  local key, key_err = decode_signing_key(conf.cookie_signing_key)
  if not key then
    -- Misconfigured key is a server error; do not leak details.
    core.log.error("bff-session: ", key_err)
    return false, "csrf_misconfigured"
  end
  local expected_hmac, hmac_err = hmac_b64url(key, value .. ":" .. sid)
  if not expected_hmac then
    core.log.error("bff-session: hmac compute failed: ", hmac_err)
    return false, "csrf_hmac_failed"
  end
  if not constant_time_equals(supplied_hmac, expected_hmac) then
    return false, "csrf_bad_signature"
  end
  return true
end

-- ---------------------------------------------------------------------
-- Client-Credentials token cache (worker-local)
-- ---------------------------------------------------------------------

-- Cache shape stored in ngx.shared.cc_token_cache under the key derived
-- from the gateway_client_id (so multiple gateway identities, if ever
-- configured, do not collide):
--   value: JSON { "token": "<jwt>", "expires_at": <epoch_seconds> }
--
-- Concurrency: ngx.shared.DICT add/set are atomic; we also take a
-- worker-local lock from cc_token_lock to serialize the actual IdP
-- round-trip so concurrent callers do not stampede.
local function cc_cache_key(conf)
  return "cc:" .. conf.gateway_client_id
end

local function cc_get_cached(conf)
  local dict = ngx.shared.cc_token_cache
  if not dict then return nil end
  local raw = dict:get(cc_cache_key(conf))
  if not raw then return nil end
  local entry = cjson.decode(raw)
  if not entry or type(entry.token) ~= "string"
     or type(entry.expires_at) ~= "number" then
    return nil
  end
  -- Treat tokens with <60s remaining as already expired so a refresh
  -- happens proactively (matches SPEC §"Client Credentials token cache").
  if entry.expires_at - ngx_time() < 60 then
    return nil
  end
  return entry.token
end

local function cc_set_cached(conf, token, expires_in)
  local dict = ngx.shared.cc_token_cache
  if not dict then return end
  local entry = cjson.encode({
    token      = token,
    expires_at = ngx_time() + expires_in,
  })
  -- TTL on the shared dict slot is expires_in - 60 so a stale entry
  -- cannot linger past usefulness even if our refresh check misses.
  local ttl = math.max(1, expires_in - 60)
  local ok, err = dict:set(cc_cache_key(conf), entry, ttl)
  if not ok then
    core.log.error("bff-session: cc cache set failed: ", err)
  end
end

local function cc_invalidate(conf)
  local dict = ngx.shared.cc_token_cache
  if dict then
    dict:delete(cc_cache_key(conf))
  end
end

local resty_lock = require "resty.lock"

local function fetch_cc_token(conf)
  -- Blocking lock around the IdP token round-trip (lua-resty-lock backed
  -- by ngx.shared.cc_token_lock). The previous implementation used
  -- shared_dict:add(), which is atomic but non-blocking — the loser of the
  -- race fell through and ALSO called the IdP, so a concurrent burst right
  -- after cache expiry stampeded N requests at the AS for N parallel API
  -- calls (worst case). resty_lock:lock() blocks the loser until the
  -- winner has set the cache; the loser then re-reads cache and returns
  -- the now-populated token. Exptime > timeout so the lock survives the
  -- 2s HTTP timeout but cannot wedge a stuck worker forever.
  local lock, lock_err = resty_lock:new("cc_token_lock", {
    exptime = 5,
    timeout = 5,
  })
  if not lock then
    return nil, "cc_lock_new_failed: " .. tostring(lock_err)
  end
  local lock_key = "lock:" .. conf.gateway_client_id
  local elapsed, err = lock:lock(lock_key)
  if not elapsed then
    return nil, "cc_lock_acquire_failed: " .. tostring(err)
  end

  -- Re-check cache under the lock — the winner may have already populated.
  local cached = cc_get_cached(conf)
  if cached then
    lock:unlock()
    return cached
  end

  local httpc = http.new()
  httpc:set_timeout(2000)  -- 2s total per leg; CC endpoint is local.

  local body =
    "grant_type=client_credentials"
    .. "&client_id="     .. ngx.escape_uri(conf.gateway_client_id)
    .. "&client_secret=" .. ngx.escape_uri(conf.gateway_client_secret)

  local res, http_err = httpc:request_uri(conf.idp_token_url, {
    method  = "POST",
    body    = body,
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Accept"]       = "application/json",
    },
  })

  if not res then
    lock:unlock()
    return nil, "idp_unreachable: " .. tostring(http_err)
  end
  if res.status ~= 200 then
    lock:unlock()
    -- Do not log the response body — IdP error payloads are not secret per
    -- se but may include the client id in surprising ways.
    return nil, "idp_status:" .. tostring(res.status)
  end

  local parsed = cjson.decode(res.body or "")
  if not parsed or type(parsed.access_token) ~= "string"
     or type(parsed.expires_in) ~= "number" then
    lock:unlock()
    return nil, "idp_bad_body"
  end

  cc_set_cached(conf, parsed.access_token, parsed.expires_in)
  lock:unlock()
  return parsed.access_token
end

local function get_cc_token(conf, force_refresh)
  if not force_refresh then
    local cached = cc_get_cached(conf)
    if cached then return cached end
  else
    cc_invalidate(conf)
  end
  return fetch_cc_token(conf)
end

-- ---------------------------------------------------------------------
-- /internal/resolve delegation (phantom token)
-- ---------------------------------------------------------------------

-- Returns: status_code, body_string, error_string
-- status_code is the upstream /internal/resolve HTTP status (200, 401,
-- 404, 409, 502, or 0 for transport failure). body_string carries the
-- access_token on 200; nil otherwise.
local function call_internal_resolve(conf, sid, cc_token)
  local url = conf.auth_service_base .. "/internal/resolve"
  local httpc = http.new()
  -- Connect 1s + read 5s: resolve may include a Keycloak refresh round-trip.
  httpc:set_timeouts(1000, 5000, 5000)

  local res, err = httpc:request_uri(url, {
    method  = "POST",
    body    = cjson.encode({ sid = sid }),
    headers = {
      ["Authorization"] = "Bearer " .. cc_token,
      ["Content-Type"]  = "application/json",
      ["Accept"]        = "application/json",
    },
  })
  if not res then
    return 0, nil, tostring(err)
  end
  return res.status, res.body, nil
end

-- Extract access_token (+ optional sid rotation) from a /internal/resolve 200
-- body. Returns: token, rotation. token is nil if missing/malformed. rotation is
-- { sid = <new_sid>, max_age = <seconds> } when the Auth Service rotated the sid
-- on this resolve (A6), so the gateway re-issues the session cookie; else nil.
local function resolve_token_from_body(body)
  if type(body) ~= "string" or body == "" then return nil end
  local parsed = cjson.decode(body)
  if type(parsed) ~= "table" or type(parsed.access_token) ~= "string"
     or parsed.access_token == "" then
    return nil
  end
  local rotation
  if type(parsed.rotated_sid) == "string" and parsed.rotated_sid ~= "" then
    rotation = {
      sid = parsed.rotated_sid,
      max_age = tonumber(parsed.rotated_sid_max_age),
      -- Fresh signed-CSRF token bound to the rotated sid. The CSRF HMAC covers
      -- value:sid, so the old token would 403 every write after rotation — we
      -- re-issue the XSRF-TOKEN cookie alongside the sid cookie.
      csrf = (type(parsed.rotated_csrf) == "string" and parsed.rotated_csrf ~= "")
        and parsed.rotated_csrf or nil,
    }
  end
  return parsed.access_token, rotation
end

-- Resolve the sid into the current access token via /internal/resolve, per the
-- §7.1 Gateway-side response table. Returns: access_token, action_string.
--   "ok"        -> inject access_token and proceed
--   "401_clear" -> session gone (404 / 409): clear cookie + no-session response
--   "503"       -> 503 with Retry-After: 1 (502 / transport; do NOT clear cookie)
--   "502"       -> 502 to browser (CC-token retry exhausted, or a malformed 200)
--
-- `deps` (optional) injects the two I/O helpers so the failure-branch decision
-- table is unit-tested deterministically (api-gateway/tests/test-resolve-flow.lua)
-- — forcing a mid-flight 404/409/401/transport failure is not orchestratable
-- against the live stack. Production passes deps=nil and uses the real
-- get_cc_token / call_internal_resolve.
local function resolve_session(conf, sid, deps)
  local get_cc = (deps and deps.get_cc_token) or get_cc_token
  local call_resolve = (deps and deps.call_internal_resolve) or call_internal_resolve

  local cc_token, cc_err = get_cc(conf, false)
  if not cc_token then
    core.log.error("bff-session: cc token fetch failed: ", cc_err)
    return nil, "502"
  end

  local status, body = call_resolve(conf, sid, cc_token)
  if status == 200 then
    local token, rotation = resolve_token_from_body(body)
    if not token then
      core.log.error("bff-session: /internal/resolve 200 with no access_token")
      return nil, "502"
    end
    return token, "ok", rotation
  end
  if status == 404 or status == 409 then
    -- Session was logged out, or refresh was rejected by the IdP
    -- (invalid_grant) and the Auth Service already deleted sess:{sid}. The
    -- cookie is useless; the browser sees a no-session response.
    return nil, "401_clear"
  end
  if status == 401 then
    -- Our own CC token failed at the Auth Service. Invalidate cache, fetch a
    -- fresh one, retry exactly ONCE per §7.1 handling table.
    core.log.warn("bff-session: auth-service 401 on /internal/resolve; retrying with fresh CC token")
    local new_token, new_err = get_cc(conf, true)
    if not new_token then
      core.log.error("bff-session: cc token re-fetch failed: ", new_err)
      return nil, "502"
    end
    local retry_status, retry_body = call_resolve(conf, sid, new_token)
    if retry_status == 200 then
      local token, rotation = resolve_token_from_body(retry_body)
      if token then return token, "ok", rotation end
      return nil, "502"
    end
    if retry_status == 404 or retry_status == 409 then return nil, "401_clear" end
    -- Second 401 (or any other terminal failure) -> 502 + audit log.
    core.log.error("bff-session: resolve failed after CC retry; status=", tostring(retry_status))
    return nil, "502"
  end
  -- 502 or transport failure -> 503 to browser; the session may still be valid.
  if status == 502 or status == 0 then
    return nil, "503"
  end
  -- Unknown status — treat as server fault but do not clear cookie.
  core.log.error("bff-session: unexpected /internal/resolve status: ", tostring(status))
  return nil, "503"
end

-- Test hook: the resolve failure-branch decision table (404/409 eviction, 401
-- CC-token retry, transport→503) cannot be exercised against the live stack
-- because the failures are not deterministically orchestratable.
-- test-resolve-flow.lua drives this with stubbed I/O deps. Not part of the
-- APISIX plugin contract.
_M._resolve_session = resolve_session

-- Test hook: constant-time byte comparison — the primitive under signed-CSRF and
-- HMAC validation. Pure (string + bit ops, no ngx/resty), so test-pure-fns.lua
-- exercises its correctness directly in bare LuaJIT. Not part of the contract.
_M._constant_time_equals = constant_time_equals

-- Test hook: session-cookie selection. Pure (table lookups), so test-pure-fns.lua
-- exercises the __Host-sid-vs-bare-sid + allow_insecure_sid gate directly. Not
-- part of the APISIX plugin contract.
_M._get_session_cookie = get_session_cookie

-- Test hook: the sid-rotation Set-Cookie builder (A6). Pure string building, so
-- test-pure-fns.lua exercises the prod __Host-sid/Secure branch that the live
-- HTTP e2e never reaches, and the SameSite parity with the login cookies.
_M._build_rotation_cookies = build_rotation_cookies

-- ---------------------------------------------------------------------
-- Plugin lifecycle
-- ---------------------------------------------------------------------

-- Boot-time guard. The Auth Service ships dev-only sentinels that mirror
-- what this plugin receives (see SecretSentinelValidator on the Java side
-- for the matching half). If either survives into a non-dev env, we want
-- the operator to see it loud at plugin-load time. We only WARN rather
-- than fail-load because this is a local-only reference; a fail-fast in
-- check_schema would block every route the plugin is attached to, breaking
-- the documented zero-config local dev. The Java side handles fail-fast
-- on `prod` / `production` Spring profiles.
local CHANGE_BEFORE_DEPLOY_MARKER = "CHANGE_BEFORE_DEPLOY"
local DEV_COOKIE_SIGNING_KEY      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

local function warn_on_dev_sentinels(conf)
  if type(conf.gateway_client_secret) == "string"
     and conf.gateway_client_secret:find(CHANGE_BEFORE_DEPLOY_MARKER, 1, true) then
    core.log.warn(
      "bff-session: gateway_client_secret carries the local-dev sentinel ",
      "(", CHANGE_BEFORE_DEPLOY_MARKER, ") — replace before any non-local deploy")
  end
  if conf.cookie_signing_key == DEV_COOKIE_SIGNING_KEY then
    core.log.warn(
      "bff-session: cookie_signing_key is the known local-dev sentinel ",
      "(32 zero-bytes base64) — replace before any non-local deploy")
  end
end

function _M.check_schema(conf)
  local ok, err = core.schema.check(schema, conf)
  if not ok then
    return ok, err
  end
  warn_on_dev_sentinels(conf)
  return true
end

function _M.access(conf, ctx)
  local method = core.request.get_method() or "GET"
  local scheme = effective_scheme(ctx)
  local host   = ngx_var.host or ""
  local uri    = ngx_var.request_uri or "/"   -- full path + query

  local cookie_header = core.request.header(ctx, "Cookie")
  local cookies       = parse_cookies(cookie_header)

  -- Step 1 + 2: session cookie present?
  local sid = get_session_cookie(cookies, conf.allow_insecure_sid)
  if not sid or sid == "" then
    return no_session_response(ctx, conf, scheme, host, uri)
  end

  -- Step 3: signed CSRF on state-changing methods. Done BEFORE resolve so we
  -- don't burn a resolve RPC (and its possible refresh) on a forged request.
  -- CSRF uses the sid from the cookie; no store read.
  local csrf_pass, csrf_reason = csrf_ok(ctx, conf, method, cookies, sid)
  if not csrf_pass then
    core.log.warn("bff-session: csrf reject reason=", tostring(csrf_reason))
    return problem_json(403, "Forbidden", "invalid CSRF token")
  end

  -- Step 4: resolve the sid into the current access token via the Auth
  -- Service. The gateway holds no store handle — /internal/resolve looks up the
  -- session, slides the idle window, refreshes if near expiry, and returns the
  -- token. No gateway-side cache, so a server-side session delete is visible on
  -- the very next request (instant revocation).
  local access_token, action, rotation = resolve_session(conf, sid)
  if action == "401_clear" then
    -- 404 (session gone) or 409 (invalidated). Evict the now-useless cookie;
    -- the browser sees a no-session response (top-level nav -> 302 login,
    -- XHR -> 401).
    expire_session_cookie(scheme)
    return no_session_response(ctx, conf, scheme, host, uri)
  elseif action == "503" then
    core.response.set_header("Retry-After", "1")
    return problem_json(503, "Service Unavailable", "session resolution temporarily unavailable")
  elseif action == "502" then
    return problem_json(502, "Bad Gateway", "session resolution failed")
  end
  -- action == "ok": access_token holds the bearer to inject.

  -- Step 5: header shaping. Strip inbound Cookie + hop-by-hop, including
  -- extension headers named by Connection, then inject the bearer.
  -- core.request.set_header sets BOTH ctx headers (visible to later
  -- plugins) and the upstream request.
  local connection_header = core.request.header(ctx, "Connection")
  local connection_tokens = {}
  if connection_header then
    for token in connection_header:gmatch("[^,]+") do
      local normalized = token:gsub("^%s+", ""):gsub("%s+$", ""):lower()
      if normalized ~= "" then
        connection_tokens[normalized] = true
      end
    end
  end
  for header_name, _ in pairs(HOP_BY_HOP) do
    -- nil clears the header from the upstream request.
    core.request.set_header(ctx, header_name, nil)
  end
  for header_name, _ in pairs(connection_tokens) do
    core.request.set_header(ctx, header_name, nil)
  end
  for header_name, _ in pairs(IDENTITY_HEADERS) do
    -- Strip client-supplied identity headers before proxying (defense in depth).
    core.request.set_header(ctx, header_name, nil)
  end
  core.request.set_header(ctx, "Authorization", "Bearer " .. access_token)

  -- Defense in depth: also stash a marker so the header_filter phase
  -- can add Cache-Control: no-store on the response. RS already sets
  -- this, but we add it on every path that exits through us.
  ctx.bff_session_added_bearer = true

  -- A6: the resolve rotated the sid. Stash it so header_filter re-issues the
  -- session cookie on the way back (cookie work belongs in the response phase,
  -- not here where we are still shaping the upstream request).
  if rotation then
    ctx.bff_rotated_sid = rotation.sid
    ctx.bff_rotated_max_age = rotation.max_age
    ctx.bff_rotated_csrf = rotation.csrf
    -- Drive the re-issued cookie's name/Secure from the route's allow_insecure_sid
    -- flag (the same signal the ACCEPT path uses), NOT the spoofable
    -- X-Forwarded-Proto-derived scheme — otherwise a forged proto could make the
    -- gateway re-issue a bare `sid` the plugin then rejects (accept/re-issue skew).
    ctx.bff_allow_insecure_sid = conf.allow_insecure_sid
  end
end

function _M.header_filter(conf, ctx)
  -- Add no-store on responses for which we injected the bearer. We do
  -- NOT remove the upstream's Cache-Control — if RS sent something more
  -- restrictive we want it to win. APISIX core.response.set_header
  -- overwrites; using add_header would be wrong here. The RS contract
  -- (see SPEC §"API Behavior") already mandates no-store; this is
  -- belt-and-braces for unexpected paths.
  if ctx.bff_session_added_bearer then
    if not ngx.header["Cache-Control"] then
      ngx.header["Cache-Control"] = "no-store"
    end
  end

  -- A6: the resolve rotated the sid. Re-issue BOTH session cookies with the new
  -- values so the browser uses them from the next request: the opaque sid cookie
  -- (HttpOnly) AND the signed-CSRF XSRF-TOKEN cookie (SPA-readable) — the latter
  -- is sid-bound, so without it every write would 403 after a rotation. Same
  -- name/attributes as the Auth Service's login cookies, with the Secure/__Host-
  -- decision taken from the route's allow_insecure_sid flag (mirroring the accept
  -- path), and Max-Age = the session's remaining absolute lifetime so rotation
  -- never shortens persistence. Invisible to the SPA beyond the cookie swap.
  if ctx.bff_rotated_sid then
    ngx.header["Set-Cookie"] = build_rotation_cookies(
      ctx.bff_rotated_sid, ctx.bff_rotated_csrf,
      ctx.bff_rotated_max_age, ctx.bff_allow_insecure_sid)
  end
end

return _M
