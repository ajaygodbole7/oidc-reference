-- Unit tests for bff-session.lua's pure helper functions, run by test-lua-unit.sh
-- inside the pinned APISIX image (bare LuaJIT). Covers constant_time_equals — the
-- constant-time byte comparison under signed-CSRF and HMAC validation.
--
-- The HMAC digest (hmac_b64url) and the full csrf_ok validator need OpenResty's
-- resty.hmac and ngx.encode_base64, which are NOT present in bare LuaJIT; they are
-- covered end-to-end by the live signed-CSRF battery in test-gateway-behavior.sh
-- (no-CSRF / unsigned / mismatched / forged-HMAC / cross-session / valid).

-- Stub the I/O deps so the plugin module loads under bare LuaJIT.
package.preload["apisix.core"] = function()
  return { log = { error = function() end, warn = function() end, info = function() end } }
end
package.preload["cjson.safe"] = function()
  return { encode = function() return "{}" end, decode = function() return {} end }
end
package.preload["resty.http"] = function() return { new = function() return {} end } end
package.preload["resty.hmac"] = function() return {} end
package.preload["resty.lock"] = function() return {} end
ngx = { time = os.time, var = {}, shared = {} }

local plugin = dofile(arg[1] or "plugins/bff-session.lua")
local eq = plugin._constant_time_equals
assert(type(eq) == "function",
    "bff-session.lua must export _constant_time_equals for tests")

local failures = 0
local function check(label, got, want)
  if got ~= want then
    failures = failures + 1
    io.stderr:write(string.format("FAIL %s: got %s, want %s\n",
        label, tostring(got), tostring(want)))
  else
    print(string.format("ok   %s -> %s", label, tostring(got)))
  end
end

-- Equality (must be true)
check("equal strings", eq("abc123", "abc123"), true)
check("empty strings", eq("", ""), true)

-- Inequality at equal length (must be false, no early exit)
check("differ same length", eq("abc123", "abc124"), false)
check("differ first byte", eq("Xbc123", "abc123"), false)
check("differ last byte", eq("abc123", "abc12X"), false)

-- Length mismatch (must be false)
check("shorter first", eq("abc", "abc123"), false)
check("longer first", eq("abc123", "abc"), false)

-- Non-string / nil inputs (must be false, never error)
check("nil first", eq(nil, "abc"), false)
check("nil second", eq("abc", nil), false)
check("both nil", eq(nil, nil), false)
check("number arg", eq(123, "123"), false)

-- HMAC-length (64-byte) vectors: identical match, one-byte mutation does not.
local long = string.rep("a", 63) .. "b"
check("long identical", eq(long, long), true)
check("long one-byte differ", eq(long, string.rep("a", 63) .. "c"), false)

-- get_session_cookie: __Host-sid is honored unconditionally; the bare `sid`
-- fallback is accepted ONLY when allow_insecure_sid is true (B3 — not inferred
-- from a spoofable scheme). The strings below are the cookie VALUES returned.
local gsc = plugin._get_session_cookie
assert(type(gsc) == "function",
    "bff-session.lua must export _get_session_cookie for tests")
check("__Host-sid honored (flag off)", gsc({ ["__Host-sid"] = "h1" }, false), "h1")
check("__Host-sid honored (flag on)", gsc({ ["__Host-sid"] = "h1" }, true), "h1")
check("__Host-sid wins over bare sid", gsc({ ["__Host-sid"] = "h1", ["sid"] = "s1" }, false), "h1")
check("bare sid accepted when allowed", gsc({ ["sid"] = "s1" }, true), "s1")
check("bare sid REJECTED by default", gsc({ ["sid"] = "s1" }, false), nil)
check("no cookie -> nil", gsc({}, true), nil)

-- build_rotation_cookies (A6): the Set-Cookie strings re-issued on rotation. The
-- PROD branch (__Host-sid + Secure) is never reached by the plain-HTTP live e2e,
-- and SameSite parity with the login cookies (sid=Lax, XSRF-TOKEN=Strict) is what
-- lets a later logout's clearCookie evict them.
local brc = plugin._build_rotation_cookies
assert(type(brc) == "function",
    "bff-session.lua must export _build_rotation_cookies for tests")
local function has(s, sub) return s ~= nil and string.find(s, sub, 1, true) ~= nil end
local function checkc(label, cond) check(label, cond and true or false, true) end

-- Prod: HTTPS, allow_insecure_sid = false
local prod = brc("rsid", "val.hmac", 3600, false)
checkc("prod sid is __Host-sid", has(prod[1], "__Host-sid=rsid"))
checkc("prod sid HttpOnly", has(prod[1], "; HttpOnly"))
checkc("prod sid SameSite=Lax", has(prod[1], "; SameSite=Lax"))
checkc("prod sid Secure", has(prod[1], "; Secure"))
checkc("prod sid Max-Age", has(prod[1], "; Max-Age=3600"))
checkc("prod xsrf present", prod[2] ~= nil)
checkc("prod xsrf name", has(prod[2], "XSRF-TOKEN=val.hmac"))
checkc("prod xsrf SameSite=Strict", has(prod[2], "; SameSite=Strict"))
checkc("prod xsrf Secure", has(prod[2], "; Secure"))
checkc("prod xsrf NOT HttpOnly", not has(prod[2], "HttpOnly"))

-- Local: HTTP, allow_insecure_sid = true
local dev = brc("dsid", "val.hmac", 1800, true)
checkc("dev sid is bare sid", has(dev[1], "sid=dsid") and not has(dev[1], "__Host-"))
checkc("dev sid no Secure", not has(dev[1], "Secure"))
checkc("dev xsrf no Secure", not has(dev[2], "Secure"))
checkc("dev xsrf SameSite=Strict", has(dev[2], "; SameSite=Strict"))

-- No CSRF -> only the sid cookie is emitted
local nocsrf = brc("nsid", nil, 100, false)
checkc("no-csrf -> single cookie", nocsrf[2] == nil)

-- expire_session_cookie (P2): the eviction cookie name/Secure key on the route's
-- allow_insecure_sid flag, NOT a spoofable forwarded scheme. Otherwise a spoofed
-- X-Forwarded-Proto could make prod clear "sid" and leave the live __Host-sid in
-- the browser (repeated 401/redirect). Mirrors the accept + rotation paths.
local esc = plugin._expire_session_cookie_header
assert(type(esc) == "function",
    "bff-session.lua must export _expire_session_cookie_header for tests")
-- Prod (flag off): clear __Host-sid, WITH Secure, Max-Age=0.
checkc("evict prod clears __Host-sid", has(esc(false), "__Host-sid="))
checkc("evict prod Max-Age=0", has(esc(false), "; Max-Age=0"))
checkc("evict prod HttpOnly", has(esc(false), "; HttpOnly"))
checkc("evict prod SameSite=Lax", has(esc(false), "; SameSite=Lax"))
checkc("evict prod Secure", has(esc(false), "; Secure"))
-- Local HTTP (flag on): clear the bare sid, NO Secure (or the browser rejects it).
checkc("evict dev clears bare sid", has(esc(true), "sid=") and not has(esc(true), "__Host-"))
checkc("evict dev Max-Age=0", has(esc(true), "; Max-Age=0"))
checkc("evict dev no Secure", not has(esc(true), "Secure"))

if failures > 0 then
  io.stderr:write(string.format("test-pure-fns: %d FAIL\n", failures))
  os.exit(1)
end
print("test-pure-fns: PASS (constant_time_equals)")
