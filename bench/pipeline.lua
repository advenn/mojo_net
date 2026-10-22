-- wrk script: every write carries N pipelined GET requests (default 16).
--   wrk -s bench/pipeline.lua http://127.0.0.1:8080/ -- 16
init = function(args)
  local n = tonumber(args[1]) or 16
  local r = {}
  for i = 1, n do
    r[i] = wrk.format(nil, "/")
  end
  req = table.concat(r)
end

request = function()
  return req
end
