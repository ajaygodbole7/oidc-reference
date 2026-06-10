-- Unit test for bff-session.lua's parse_iso8601_utc, run by
-- test-lua-unit.sh inside the pinned APISIX image under a matrix of
-- container timezones. The Auth Service writes ISO-8601 UTC timestamps
-- into sess:{sid} (SPEC-0001 §7.2); the parser must return the true UTC
-- epoch no matter what TZ the gateway container runs in. compose.yaml
-- pins TZ=UTC, but the parser must not depend on that pin — a fork that
-- drops the pin must not silently shift every session expiry by the
-- host's UTC offset.

-- Stub the APISIX/OpenResty modules the plugin requires at load time.
-- Only module-level code runs during dofile; the stubs are never called.
package.preload["apisix.core"] = function() return {} end
package.preload["cjson.safe"]  = function() return {} end
package.preload["resty.redis"] = function() return {} end
package.preload["resty.http"]  = function() return {} end
package.preload["resty.hmac"]  = function() return {} end
package.preload["resty.lock"]  = function() return {} end
-- ngx.time() returns seconds-since-epoch; os.time() with no args is the
-- same value (the epoch is timezone-independent).
ngx = { time = os.time, var = {} }

local plugin = dofile(arg[1] or "plugins/bff-session.lua")
local parse = plugin._parse_iso8601_utc
assert(type(parse) == "function",
    "bff-session.lua must export _parse_iso8601_utc for tests")

local tz = os.getenv("TZ") or "(unset)"
local failures = 0
local function check(label, got, want)
  if got ~= want then
    failures = failures + 1
    io.stderr:write(string.format("FAIL %s: got %s, want %s [TZ=%s]\n",
        label, tostring(got), tostring(want), tz))
  else
    print(string.format("ok   %s [TZ=%s]", label, tz))
  end
end

-- Expected epochs computed independently (date -u -d ... +%s):
--   2026-01-01T12:00:00Z = 1767268800
--   2026-07-01T00:30:00Z = 1782865800 (mid-year: catches DST-offset drift)
check("plain UTC timestamp",  parse("2026-01-01T12:00:00Z"),     1767268800)
check("fractional seconds",   parse("2026-01-01T12:00:00.123Z"), 1767268800)
check("DST-season timestamp", parse("2026-07-01T00:30:00Z"),     1782865800)
check("rejects offset form",  parse("2026-01-01T12:00:00+05:30"), nil)
check("rejects missing Z",    parse("2026-01-01T12:00:00"),       nil)
check("rejects non-string",   parse(1767268800),                  nil)

os.exit(failures == 0 and 0 or 1)
