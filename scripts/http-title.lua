-- http-title.lua: grab the <title> element from an HTTP server.
description = "Extract HTTP <title>"
ports = {80, 8080, 8000, 8888}

function run(host, port)
  local body, err = scry.tcp.request(
    host, port,
    "GET / HTTP/1.0\r\nHost: " .. host .. "\r\nUser-Agent: scry\r\n\r\n",
    {timeout = 3000, max_bytes = 8192}
  )
  if err then return nil, err end
  local title = body:match("<[Tt][Ii][Tt][Ll][Ee][^>]*>(.-)</[Tt][Ii][Tt][Ll][Ee]>")
  if title and #title > 0 then
    return "title: " .. title:gsub("%s+", " "):sub(1, 120)
  end
end
