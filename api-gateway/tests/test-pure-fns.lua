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

if failures > 0 then
  io.stderr:write(string.format("test-pure-fns: %d FAIL\n", failures))
  os.exit(1)
end
print("test-pure-fns: PASS (constant_time_equals)")
