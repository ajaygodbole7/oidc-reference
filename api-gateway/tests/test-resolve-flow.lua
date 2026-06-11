-- Unit test for bff-session.lua's resolve_session() decision table (SPEC-0001
-- §7.1 gateway-side response table). Run by test-lua-unit.sh inside the pinned
-- APISIX image.
--
-- These branches are otherwise UNTESTED at every layer: the live gateway test
-- covers only the 200 happy path, and forcing a mid-flight 404/409/401/transport
-- failure against the real Auth Service is not deterministically orchestratable.
-- The decision logic is injected with stubbed I/O so every branch is exercised.

package.preload["apisix.core"] = function()
  return { log = { error = function() end, warn = function() end, info = function() end } }
end
-- decode returns a body carrying access_token so resolve_token_from_body can
-- extract it on the 200 path.
package.preload["cjson.safe"]  = function() return {
  encode = function() return "{}" end,
  decode = function() return { access_token = "resolved-token" } end,
} end
package.preload["resty.http"]  = function() return { new = function() return {} end } end
package.preload["resty.hmac"]  = function() return {} end
package.preload["resty.lock"]  = function() return {} end
ngx = { time = os.time, var = {}, shared = {} }

local plugin = dofile(arg[1] or "plugins/bff-session.lua")
local resolve = plugin._resolve_session
assert(type(resolve) == "function",
    "bff-session.lua must export _resolve_session for tests")

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

local conf, sid = {}, "sid-1"

-- deps builder: cc_seq is a list of cc-token results returned in order across
-- get_cc_token calls; resolve_seq is a list of /internal/resolve statuses
-- returned in order across call_internal_resolve calls. On 200 the stub returns
-- a non-empty body so resolve_session extracts the access_token from it.
local function deps(cc_seq, resolve_seq)
  local cc_i, res_i = 0, 0
  local d = { cc_calls = 0, resolve_calls = 0 }
  d.get_cc_token = function(_conf, _force)
    cc_i = cc_i + 1
    d.cc_calls = cc_i
    local entry = cc_seq[cc_i] or { "cc-token", nil }
    return entry[1], entry[2]
  end
  d.call_internal_resolve = function(_conf, _sid, _token)
    res_i = res_i + 1
    d.resolve_calls = res_i
    local entry = resolve_seq[res_i] or { 200 }
    local status = entry[1]
    local body = (status == 200) and '{"access_token":"resolved-token"}' or nil
    return status, body
  end
  return d
end

-- resolve_session returns (access_token, action). The decision table checks the
-- action; the happy paths also verify the token came back.
local function action_of(d)
  local _, action = resolve(conf, sid, d)
  return action
end

-- 1. 200 -> ok, with the access_token extracted from the body
do
  local token, action = resolve(conf, sid, deps({ { "cc", nil } }, { { 200 } }))
  check("status 200 action", action, "ok")
  check("status 200 token", token, "resolved-token")
end

-- 2. 404 -> 401_clear (logged out / session gone server-side)
check("status 404", action_of(deps({ { "cc", nil } }, { { 404 } })), "401_clear")

-- 3. 409 -> 401_clear (invalid_grant; AS already deleted sess:{sid})
check("status 409", action_of(deps({ { "cc", nil } }, { { 409 } })), "401_clear")

-- 4. 502 -> 503 (AS reached IdP-unreachable; session still valid, do not evict)
check("status 502", action_of(deps({ { "cc", nil } }, { { 502 } })), "503")

-- 5. transport failure (status 0) -> 503 (session still valid)
check("transport 0", action_of(deps({ { "cc", nil } }, { { 0 } })), "503")

-- 6. unknown status (500) -> 503, do not evict cookie
check("status 500", action_of(deps({ { "cc", nil } }, { { 500 } })), "503")

-- 7. cc-token fetch fails up front -> 502
check("cc fetch fail", action_of(deps({ { nil, "idp_unreachable" } }, {})), "502")

-- 8. 401 then fresh-CC retry succeeds (200) -> ok (exactly one retry)
do
  local d = deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401 }, { 200 } })
  local token, action = resolve(conf, sid, d)
  check("401 then retry 200 action", action, "ok")
  check("401 then retry 200 token", token, "resolved-token")
  check("  retry used 2 cc tokens", d.cc_calls, 2)
  check("  retry made 2 resolve calls", d.resolve_calls, 2)
end

-- 9. 401 then retry also 401 -> 502 (retry exhausted, do not evict)
do
  local d = deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401 }, { 401 } })
  check("401 then retry 401", select(2, resolve(conf, sid, d)), "502")
  check("  no third resolve attempt", d.resolve_calls, 2)
end

-- 10. 401 then retry 409 -> 401_clear (session died during the dance)
check("401 then retry 409",
  action_of(deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401 }, { 409 } })),
  "401_clear")

-- 11. 401 but fresh-CC re-fetch fails -> 502 (no second resolve attempt)
do
  local d = deps({ { "cc-old", nil }, { nil, "idp_unreachable" } }, { { 401 } })
  check("401 then cc re-fetch fail", select(2, resolve(conf, sid, d)), "502")
  check("  only one resolve attempt", d.resolve_calls, 1)
end

os.exit(failures == 0 and 0 or 1)
