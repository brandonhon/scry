-- redis-ping.lua: send PING, expect +PONG.
description = "Detect a responsive Redis server via PING/PONG"
ports = {6379}

function run(host, port)
  local body, err = scry.tcp.request(host, port, "PING\r\n", {timeout = 1500, max_bytes = 64})
  if err then return nil, err end
  if body:sub(1, 5) == "+PONG" then
    return "redis: PONG"
  end
  if body:sub(1, 5) == "-NOAUTH" then
    return "redis: auth required"
  end
end
