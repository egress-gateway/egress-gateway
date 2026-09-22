local function reject(handle, message)
  handle:respond({[":status"] = "400"}, message)
end

local function hostname(value)
  if not value or #value == 0 or #value > 253 then return nil end
  value = string.lower(value)
  if value:find("[^a-z0-9.-]") or value:sub(-1) == "." or value:find("..", 1, true) then return nil end
  if value:match("^%d+%.%d+%.%d+%.%d+$") then return nil end
  for label in value:gmatch("[^.]+") do
    if #label > 63 or label:sub(1,1) == "-" or label:sub(-1) == "-" then return nil end
  end
  if value:sub(1,1) == "." then return nil end
  return value
end

local function target(authority, scheme)
  if not authority then return nil end
  local name, port = authority:match("^([^:]+):(%d+)$")
  if not name then name = authority end
  name = hostname(name)
  if not name then return nil end
  if port then
    port = tonumber(port)
    if not port or port < 1 or port > 65535 then return nil end
  else
    port = scheme == "https" and 443 or 80
  end
  return name, tostring(port)
end

function envoy_on_request(handle)
  local headers = handle:headers()
  local info = handle:streamInfo()
  local authorized = info:dynamicMetadata():get("gateway.request")
  if authorized then
    if headers:get(":authority") ~= authorized.authority or headers:get(":path") ~= authorized.path or headers:get(":scheme") ~= authorized.scheme then
      handle:respond({[":status"] = "403"}, "authorization changed request target")
    end
    return
  end
  local encoding = headers:get("content-encoding")
  if encoding and encoding ~= "" and string.lower(encoding) ~= "identity" then
    handle:respond({[":status"] = "415"}, "unsupported content encoding")
    return
  end
  local tls = info:downstreamSslConnection()
  -- This filter belongs to the dedicated HTTPS listeners on both roles.
  local scheme = "https"
  if not tls then reject(handle, "TLS required"); return end
  if role == "egress" and not tls:peerCertificateValidated() then
    handle:respond({[":status"] = "403"}, "verified workload identity required")
    return
  end
  local name, port = target(headers:get(":authority"), scheme)
  if not name then reject(handle, "invalid target authority"); return end
  if role == "workload" and tls and hostname(info:requestedServerName()) ~= name then
    reject(handle, "target authority conflicts with TLS server name")
    return
  end
  local path = headers:get(":path")
  if headers:get(":method") == "CONNECT" or not path or path:sub(1,1) ~= "/" then
    reject(handle, "unsupported request target")
    return
  end
  -- Authorization and forwarding consume the same canonical target. Identity
  -- remains the verified TLS principal in the official OPA plugin input.
  headers:replace(":authority", name .. ":" .. port)
  headers:replace(":scheme", scheme)
  headers:replace("x-forwarded-proto", scheme)
  info:dynamicMetadata():set("gateway.request", "authority", name .. ":" .. port)
  info:dynamicMetadata():set("gateway.request", "scheme", scheme)
  info:dynamicMetadata():set("gateway.request", "path", path)
end
