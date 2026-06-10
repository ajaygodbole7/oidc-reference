-- Unit test for bff-session.lua's refresh_session() failure-branch decision
-- table (SPEC-0001 §7.1 gateway-side response table). Run by test-lua-unit.sh
-- inside the pinned APISIX image.
--
-- These branches are otherwise UNTESTED at every layer: the live gateway test
-- (test_expiring_session_triggers_refresh_delegation) covers only the 200
-- happy path, and forcing a mid-flight 404/409/401/transport failure against
-- the real Auth Service is not deterministically orchestratable. The decision
-- logic is injected with stubbed I/O so every branch is exercised here.

package.preload["apisix.core"] = function()
  return { log = { error = function() end, warn = function() end, info = function() end } }
end
package.preload["cjson.safe"]  = function() return { encode = function() return "{}" end, decode = function() return {} end } end
package.preload["resty.redis"] = function() return {} end
package.preload["resty.http"]  = function() return { new = function() return {} end } end
package.preload["resty.hmac"]  = function() return {} end
package.preload["resty.lock"]  = function() return {} end
ngx = { time = os.time, var = {}, shared = {} }

local plugin = dofile(arg[1] or "plugins/bff-session.lua")
local refresh = plugin._refresh_session
assert(type(refresh) == "function",
    "bff-session.lua must export _refresh_session for tests")

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

-- deps builder: cc_seq is a list of cc-token results returned in order across
-- get_cc_token calls; refresh_seq is a list of /internal/refresh statuses
-- returned in order across call_internal_refresh calls. Each as {value, err}.
local function deps(cc_seq, refresh_seq)
  local cc_i, ref_i = 0, 0
  local d = { cc_calls = 0, refresh_calls = 0 }
  d.get_cc_token = function(_conf, _force)
    cc_i = cc_i + 1
    d.cc_calls = cc_i
    local entry = cc_seq[cc_i] or { "cc-token", nil }
    return entry[1], entry[2]
  end
  d.call_internal_refresh = function(_conf, _sid, _token)
    ref_i = ref_i + 1
    d.refresh_calls = ref_i
    local entry = refresh_seq[ref_i] or { 200, nil }
    return entry[1], entry[2]
  end
  return d
end

local conf, sid = {}, "sid-1"

-- 1. 200 -> ok
check("status 200", refresh(conf, sid, deps({ { "cc", nil } }, { { 200, nil } })), "ok")

-- 2. 404 -> 401_clear (logged out / session gone server-side)
check("status 404", refresh(conf, sid, deps({ { "cc", nil } }, { { 404, nil } })), "401_clear")

-- 3. 409 -> 401_clear (invalid_grant; AS already deleted sess:{sid})
check("status 409", refresh(conf, sid, deps({ { "cc", nil } }, { { 409, nil } })), "401_clear")

-- 4. 502 -> 503 (AS reached IdP-unreachable; session still valid, do not evict)
check("status 502", refresh(conf, sid, deps({ { "cc", nil } }, { { 502, nil } })), "503")

-- 5. transport failure (status 0) -> 503 (session still valid)
check("transport 0", refresh(conf, sid, deps({ { "cc", nil } }, { { 0, "connection refused" } })), "503")

-- 6. unknown status (500) -> 503, do not evict cookie
check("status 500", refresh(conf, sid, deps({ { "cc", nil } }, { { 500, nil } })), "503")

-- 7. cc-token fetch fails up front -> 502
check("cc fetch fail", refresh(conf, sid, deps({ { nil, "idp_unreachable" } }, {})), "502")

-- 8. 401 then fresh-CC retry succeeds (200) -> ok (exactly one retry)
do
  local d = deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401, nil }, { 200, nil } })
  check("401 then retry 200", refresh(conf, sid, d), "ok")
  check("  retry used 2 cc tokens", d.cc_calls, 2)
  check("  retry made 2 refresh calls", d.refresh_calls, 2)
end

-- 9. 401 then retry also 401 -> 502 (retry exhausted, do not evict)
do
  local d = deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401, nil }, { 401, nil } })
  check("401 then retry 401", refresh(conf, sid, d), "502")
  check("  no third refresh attempt", d.refresh_calls, 2)
end

-- 10. 401 then retry 409 -> 401_clear (session died during the dance)
check("401 then retry 409",
  refresh(conf, sid, deps({ { "cc-old", nil }, { "cc-new", nil } }, { { 401, nil }, { 409, nil } })),
  "401_clear")

-- 11. 401 but fresh-CC re-fetch fails -> 502 (no second refresh attempt)
do
  local d = deps({ { "cc-old", nil }, { nil, "idp_unreachable" } }, { { 401, nil } })
  check("401 then cc re-fetch fail", refresh(conf, sid, d), "502")
  check("  only one refresh attempt", d.refresh_calls, 1)
end

os.exit(failures == 0 and 0 or 1)
