-- ssh-banner.lua: read the SSH identification string.
description = "Report SSH software version string"
ports = {22, 2222}

function run(host, port)
  local body, err = gscan.tcp.request(host, port, "", {timeout = 1500, max_bytes = 255})
  if err then return nil, err end
  local banner = body:match("^(SSH%-[%d.]+%-[^\r\n]+)")
  if banner then
    return banner
  end
end
