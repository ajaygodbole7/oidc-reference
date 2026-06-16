-- Cross-language signed-CSRF fixture parity for bff-session.lua.
--
-- Runs under OpenResty's `resty` binary inside the pinned APISIX image, not
-- bare LuaJIT, so the real resty.hmac and ngx.encode_base64 implementations are
-- exercised. This is the gateway-side twin of auth-service's CsrfFixtureTest.

package.preload["apisix.core"] = function()
  return {
    log = { error = function() end, warn = function() end, info = function() end },
    request = {
      header = function(ctx, name)
        return ctx.headers and ctx.headers[name] or nil
      end,
    },
  }
end
package.preload["resty.http"] = function() return { new = function() return {} end } end
package.preload["resty.lock"] = function() return {} end

local cjson = require("cjson.safe")
local plugin_path = arg[1] or "api-gateway/plugins/bff-session.lua"
local fixture_path = arg[2] or "schema/csrf-fixture.json"

local function read_all(path)
  local fh, err = io.open(path, "rb")
  assert(fh, "failed to open " .. path .. ": " .. tostring(err))
  local body = fh:read("*a")
  fh:close()
  return body
end

local fixture = assert(cjson.decode(read_all(fixture_path)))
local inputs = assert(fixture.inputs)
local expected = assert(fixture.expected)
local plugin = dofile(plugin_path)

assert(type(plugin._hmac_b64url) == "function",
    "bff-session.lua must export _hmac_b64url for CSRF fixture tests")
assert(type(plugin._csrf_ok) == "function",
    "bff-session.lua must export _csrf_ok for CSRF fixture tests")

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

local key = ngx.decode_base64(inputs.signing_key_base64)
assert(key and key ~= "", "fixture signing_key_base64 must decode")

local message = inputs.token_value .. ":" .. inputs.sid
local hmac_b64url = assert(plugin._hmac_b64url(key, message))
check("hmac_base64url", hmac_b64url, expected.hmac_base64url)
check("signed_token_formula",
    inputs.token_value .. "." .. hmac_b64url,
    expected.signed_token)

local ctx = { headers = { ["X-XSRF-TOKEN"] = expected.signed_token } }
local cookies = { ["XSRF-TOKEN"] = expected.signed_token }
local ok, reason = plugin._csrf_ok(ctx, {
  cookie_signing_key = inputs.signing_key_base64,
}, "POST", cookies, inputs.sid)
check("csrf_ok fixture token", ok, true)
check("csrf_ok fixture reason", reason, nil)

local bad_ok, bad_reason = plugin._csrf_ok(ctx, {
  cookie_signing_key = inputs.signing_key_base64,
}, "POST", cookies, inputs.sid .. "-wrong")
check("csrf_ok rejects wrong sid", bad_ok, false)
check("csrf_ok wrong sid reason", bad_reason, "csrf_bad_signature")

if failures > 0 then
  io.stderr:write(string.format("test-csrf-fixture: %d FAIL\n", failures))
  os.exit(1)
end

print("test-csrf-fixture: PASS")
