--
-- bff-session — APISIX Lua plugin
--
-- Source of truth:
--   docs/specs/SPEC-0001-core-oidc-flows.md
--     §"API Gateway Architecture (APISIX)"
--     §7.1 /internal/refresh contract
--     §7.2 sess:{sid} schema (tolerant reader)
--     §7.3 signed CSRF contract
--   docs/goals/GOAL-0005-api-gateway.md
--
-- Pipeline executed in the APISIX `access` phase on every matched
-- /api/** request:
--   1. Read session cookie (__Host-sid in HTTPS, sid in HTTP).
--   2. No cookie -> Fetch-Metadata classifier (navigation -> 302
--      /auth/login?return_to=..., else -> 401 problem+json).
--   3. GET sess:{sid} from Valkey; tolerant read of access_token +
--      access_token_expires_at.
--   4. Signed CSRF validation on POST/PUT/DELETE/PATCH.
--   5. Refresh delegation when access_token_expires_at is within the
--      refresh window — Client-Credentials cached per worker.
--   6. Strip Cookie + hop-by-hop headers; inject Authorization: Bearer.
--   7. Header_filter phase adds Cache-Control: no-store on the response.
--
-- The plugin's gateway-client identity and the CSRF signing key are supplied
-- via plugin conf in apisix.yaml. No secrets are hard-coded in this module.
--

local core        = require("apisix.core")
local cjson       = require("cjson.safe")
local redis       = require("resty.redis")
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
    "valkey_host", "valkey_port", "auth_service_base",
    "idp_token_url", "gateway_client_id",
    "gateway_client_secret", "cookie_signing_key",
    "refresh_window_seconds",
  },
  properties = {
    valkey_host             = { type = "string" },
    valkey_port             = { type = "integer", minimum = 1, maximum = 65535 },
    valkey_password         = { type = "string" },                   -- optional
    auth_service_base       = { type = "string" },                   -- e.g. http://auth-service:8081
    idp_token_url           = { type = "string" },                   -- IdP /token endpoint for Client Credentials
    gateway_client_id       = { type = "string" },
    gateway_client_secret   = { type = "string" },
    cookie_signing_key      = { type = "string" },                   -- std-base64-encoded 256-bit key
    refresh_window_seconds  = { type = "integer", default = 60 },
    idle_ttl_seconds        = { type = "integer", minimum = 1, default = 1800 },
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

local function get_session_cookie(cookies, scheme)
  -- Prefer __Host-sid when present (production / HTTPS), but accept
  -- bare `sid` in local HTTP mode per SPEC §"Session Cookie".
  if cookies["__Host-sid"] then
    return cookies["__Host-sid"]
  end
  if cookies["sid"] and scheme == "http" then
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
-- Tolerant sess:{sid} reader
-- ---------------------------------------------------------------------

-- Open a short-lived Redis connection. Timeouts are tight because every
-- /api/** request goes through this path; a sluggish Valkey would
-- otherwise queue requests.
local function valkey_connect(conf)
  local red = redis:new()
  red:set_timeouts(200, 200, 200)  -- connect, send, read (ms)
  local ok, err = red:connect(conf.valkey_host, conf.valkey_port)
  if not ok then
    return nil, err
  end
  if conf.valkey_password and conf.valkey_password ~= "" then
    local _, auth_err = red:auth(conf.valkey_password)
    if auth_err then
      return nil, auth_err
    end
  end
  return red
end

local function valkey_release(red)
  if not red then return end
  -- Keep the connection in the pool for reuse; 10s idle, 100 entries.
  local ok, err = red:set_keepalive(10000, 100)
  if not ok then
    -- Pool-set failed (e.g. due to error state); close instead.
    red:close()
    core.log.info("bff-session: redis keepalive failed: ", err)
  end
end

-- Close a connection that must NOT be pooled. After a read error the socket
-- may hold a partial/unread reply; returning it to the keepalive pool would
-- let the next request read those leftover bytes as ITS session payload
-- (cross-session token confusion). Always close, never keepalive, on error.
local function valkey_discard(red)
  if not red then return end
  red:close()
end

-- Returns: access_token, expires_at_iso, absolute_expires_at_iso, err_string
-- err_string nil => success. Any non-nil err_string MUST be treated as
-- "no session" by the caller per SPEC §7.2 rule 4.
local function read_session(conf, sid)
  local red, err = valkey_connect(conf)
  if not red then
    return nil, nil, nil, "valkey_connect: " .. tostring(err)
  end

  local res, get_err = red:get("sess:" .. sid)
  if get_err then
    -- Close (do not pool) a connection whose read failed — see valkey_discard.
    valkey_discard(red)
    return nil, nil, nil, "valkey_get: " .. tostring(get_err)
  end
  valkey_release(red)
  if res == ngx.null or res == nil then
    return nil, nil, nil, "missing"
  end

  local payload, parse_err = cjson.decode(res)
  if not payload then
    return nil, nil, nil, "json_decode: " .. tostring(parse_err)
  end
  -- Tolerant reader: consume only what we need. Anything else is
  -- ignored — including unknown fields the Auth Service may add later
  -- under §7.2 rule 2.
  local access_token = payload.access_token
  local expires_at   = payload.access_token_expires_at
  local absolute_expires_at = payload.absolute_expires_at
  if type(access_token) ~= "string" or access_token == ""
     or type(expires_at) ~= "string" or expires_at == "" then
    return nil, nil, nil, "missing_required_field"
  end
  if absolute_expires_at ~= nil and type(absolute_expires_at) ~= "string" then
    return nil, nil, nil, "malformed_absolute_expires_at"
  end
  return access_token, expires_at, absolute_expires_at, nil
end

-- ---------------------------------------------------------------------
-- ISO-8601 expiry parser
-- ---------------------------------------------------------------------

-- Parse a strict ISO-8601 UTC timestamp ("2025-05-25T17:35:00Z" or with
-- a fractional seconds component). Returns an epoch-seconds integer or
-- nil on parse failure. Anything other than UTC is rejected — the Auth
-- Service writes only UTC per §7.2.
local function parse_iso8601_utc(s)
  if type(s) ~= "string" then return nil end
  -- Pattern: YYYY-MM-DDTHH:MM:SS[.frac]Z
  local y, mo, d, h, mi, se = s:match(
    "^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)%.?%d*Z$")
  if not y then return nil end
  -- os.time treats the table as local time; the standard Lua trick to
  -- get UTC epoch is to compute the offset between os.time(table) and
  -- the same table interpreted in UTC. ngx.time() gives current UTC
  -- epoch; combining ngx.time + os.date("!*t", ngx.time()) lets us
  -- derive the offset.
  local t = os.time({
    year  = tonumber(y), month = tonumber(mo), day = tonumber(d),
    hour  = tonumber(h), min   = tonumber(mi), sec = tonumber(se),
    isdst = false,
  })
  if not t then return nil end
  local utc_now   = ngx_time()
  local local_now = os.time(os.date("*t", utc_now))
  local offset    = local_now - utc_now
  return t - offset
end

local function slide_session_ttl(conf, sid, absolute_expires_at_iso)
  if not absolute_expires_at_iso then
    return true
  end
  local absolute_expires_at = parse_iso8601_utc(absolute_expires_at_iso)
  if not absolute_expires_at then
    return nil, "malformed_absolute_expires_at"
  end
  local remaining = absolute_expires_at - ngx_time()
  if remaining <= 0 then
    return nil, "absolute_expired"
  end
  local ttl = math.min(conf.idle_ttl_seconds, remaining)
  if ttl <= 0 then
    return nil, "absolute_expired"
  end

  local red, err = valkey_connect(conf)
  if not red then
    return nil, "valkey_connect: " .. tostring(err)
  end
  local ok, expire_err = red:expire("sess:" .. sid, ttl)
  if expire_err then
    valkey_discard(red)
    return nil, "valkey_expire: " .. tostring(expire_err)
  end
  valkey_release(red)
  if ok ~= 1 then
    return nil, "missing"
  end
  return true
end

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
-- /internal/refresh delegation
-- ---------------------------------------------------------------------

-- Returns: status_code, error_string
-- status_code is the upstream /internal/refresh HTTP status (200, 401,
-- 404, 409, 502, or 0 for transport failure).
local function call_internal_refresh(conf, sid, cc_token)
  local url = conf.auth_service_base .. "/internal/refresh"
  local httpc = http.new()
  -- Connect 1s + read 5s per SPEC §"Timeouts and circuit breaker".
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
    return 0, tostring(err)
  end
  return res.status, nil
end

-- Drive the full refresh flow per §7.1 Gateway-side response table.
-- Returns: action_string. The caller maps actions to browser responses.
--   "ok"        -> proceed (sess:{sid} has been updated; re-read it)
--   "401_clear" -> 401 to browser + clear cookie (404 / 409 cases)
--   "503"       -> 503 with Retry-After: 1 (502 case; do NOT clear cookie)
--   "502"       -> 502 to browser (after CC-token retry exhausted)
local function refresh_session(conf, sid)
  local cc_token, cc_err = get_cc_token(conf, false)
  if not cc_token then
    core.log.error("bff-session: cc token fetch failed: ", cc_err)
    return "502"
  end

  local status, transport_err = call_internal_refresh(conf, sid, cc_token)
  if status == 200 then
    return "ok"
  end
  if status == 404 or status == 409 then
    -- Session was logged out, or refresh was rejected by the IdP
    -- (invalid_grant). Auth Service has
    -- already deleted sess:{sid} on the 409 path and the cookie is now
    -- useless. The browser sees 401 and the SPA initiates fresh login.
    return "401_clear"
  end
  if status == 401 then
    -- Our own CC token failed at Auth Service. Invalidate cache, fetch
    -- a fresh one, retry exactly ONCE per §7.1 handling table.
    core.log.warn("bff-session: auth-service 401 on /internal/refresh; retrying with fresh CC token")
    local new_token, new_err = get_cc_token(conf, true)
    if not new_token then
      core.log.error("bff-session: cc token re-fetch failed: ", new_err)
      return "502"
    end
    local retry_status = call_internal_refresh(conf, sid, new_token)
    if retry_status == 200 then return "ok" end
    if retry_status == 404 or retry_status == 409 then return "401_clear" end
    -- Second 401 (or any other terminal failure) -> 502 + audit log.
    core.log.error("bff-session: refresh failed after CC retry; status=", tostring(retry_status))
    return "502"
  end
  -- 502 or transport failure -> 503 to browser; session still valid.
  if status == 502 or status == 0 then
    if transport_err then
      core.log.warn("bff-session: /internal/refresh transport error: ", transport_err)
    end
    return "503"
  end
  -- Unknown status — treat as server fault but do not clear cookie.
  core.log.error("bff-session: unexpected /internal/refresh status: ", tostring(status))
  return "503"
end

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
  local sid = get_session_cookie(cookies, scheme)
  if not sid or sid == "" then
    return no_session_response(ctx, conf, scheme, host, uri)
  end

  -- Step 3: tolerant Valkey read.
  local access_token, expires_at_iso, absolute_expires_at_iso, read_err = read_session(conf, sid)
  if read_err then
    -- "missing" = no sess record (logged-out / expired); other err
    -- strings are infra-level. Log only the err class; the sid is not
    -- a token but is still sensitive enough that we do not log it.
    if read_err == "missing" or read_err == "missing_required_field"
       or read_err:sub(1, 12) == "json_decode:" then
      core.log.info("bff-session: no session for sid (reason=", read_err, ")")
      expire_session_cookie(scheme)
      return no_session_response(ctx, conf, scheme, host, uri)
    end
    -- Connect/get failure -> 502; the cookie may still be valid.
    core.log.error("bff-session: valkey failure: ", read_err)
    return problem_json(502, "Bad Gateway", "session store unavailable")
  end

  -- Step 4: signed CSRF on state-changing methods. Done before refresh
  -- so we don't burn a refresh slot on a forged request.
  local csrf_pass, csrf_reason = csrf_ok(ctx, conf, method, cookies, sid)
  if not csrf_pass then
    core.log.warn("bff-session: csrf reject reason=", tostring(csrf_reason))
    return problem_json(403, "Forbidden", "invalid CSRF token")
  end

  -- Step 5: refresh window.
  local expires_at = parse_iso8601_utc(expires_at_iso)
  if not expires_at then
    -- Malformed expiry => treat as no session per tolerant reader rule.
    core.log.info("bff-session: malformed access_token_expires_at; treating as no session")
    expire_session_cookie(scheme)
    return no_session_response(ctx, conf, scheme, host, uri)
  end
  local slide_ok, slide_err = slide_session_ttl(conf, sid, absolute_expires_at_iso)
  if not slide_ok then
    if slide_err == "absolute_expired" or slide_err == "missing"
       or slide_err == "malformed_absolute_expires_at" then
      core.log.info("bff-session: session ttl slide rejected (reason=", tostring(slide_err), ")")
      expire_session_cookie(scheme)
      return no_session_response(ctx, conf, scheme, host, uri)
    end
    core.log.error("bff-session: valkey ttl slide failure: ", tostring(slide_err))
    return problem_json(502, "Bad Gateway", "session store unavailable")
  end
  if expires_at - ngx_time() <= conf.refresh_window_seconds then
    local action = refresh_session(conf, sid)
    if action == "401_clear" then
      expire_session_cookie(scheme)
      return problem_json(401, "Unauthorized", "session ended")
    elseif action == "503" then
      core.response.set_header("Retry-After", "1")
      return problem_json(503, "Service Unavailable", "refresh temporarily unavailable")
    elseif action == "502" then
      return problem_json(502, "Bad Gateway", "refresh failed")
    end
    -- action == "ok" -> re-read sess:{sid} to pick up rotated token.
    local new_token, _, _, re_err = read_session(conf, sid)
    if re_err or not new_token then
      core.log.error("bff-session: re-read after refresh failed: ", tostring(re_err))
      return problem_json(502, "Bad Gateway", "session re-read failed")
    end
    access_token = new_token
  end

  -- Step 6: header shaping. Strip inbound Cookie + hop-by-hop, including
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
  core.request.set_header(ctx, "Authorization", "Bearer " .. access_token)

  -- Defense in depth: also stash a marker so the header_filter phase
  -- can add Cache-Control: no-store on the response. RS already sets
  -- this, but we add it on every path that exits through us.
  ctx.bff_session_added_bearer = true
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
end

return _M
