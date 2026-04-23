-- tls-cert-info.lua: dump leaf-cert subject / issuer / expiry.
description = "Leaf TLS cert subject and expiry"
ports = {443, 8443, 9443}

function run(host, port)
  local cert, err = scry.tls.cert(host, port, {timeout = 3000})
  if err then return nil, err end
  local line = "subject=" .. cert.subject .. "; issuer=" .. cert.issuer
    .. "; notAfter=" .. cert.not_after
  if cert.dns_names and #cert.dns_names > 0 then
    line = line .. "; sans=" .. table.concat(cert.dns_names, ",")
  end
  return line
end
