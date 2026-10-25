-- wrk script: every write carries N pipelined GET /plaintext requests
-- (default 16), as in TechEmpower's plaintext test.
--   wrk -s bench/server/pipeline.lua http://127.0.0.1:8080/plaintext -- 16
init = function(args)
  local n = tonumber(args[1]) or 16
  local r = {}
  for i = 1, n do
    r[i] = wrk.format(nil, "/plaintext")
  end
  req = table.concat(r)
end

request = function()
  return req
end
