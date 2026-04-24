-- smb-version.lua: SMB1 Negotiate Protocol request → dialect index.
-- Uses the stateful scry.tcp.connect API to issue an SMB negotiate
-- and read the reply, then reports which dialect the server chose.
--
-- SMB2-only servers reply with an SMB2 header (\xfeSMB) which we
-- detect and report generically.
description = "Detect SMB1/SMB2 via Negotiate Protocol"
ports = {139, 445}

-- Canned SMB1 Negotiate Protocol Request, NetBIOS-framed. Built from
-- hex because gopher-lua is Lua 5.1 and lacks \xNN string escapes.
-- Prefix:   00 00 00 85                                   NetBIOS (len 0x85)
-- SMB:      FF 53 4D 42 72 00 00 00 00 18 53 C8 ...       Negotiate
-- Dialects: 02 "PC NETWORK PROGRAM 1.0" 00
--           02 "LANMAN1.0" 00
--           02 "Windows for Workgroups 3.1a" 00
--           02 "LM1.2X002" 00
--           02 "LANMAN2.1" 00
--           02 "NT LM 0.12" 00
local function hex(s) return (scry.util.unhex(s)) end

local negotiate =
  hex("0000008500000000000000000000000000000000000000000000000000000000") ..
  -- The above is a zero-filler; the real frame is below.
  ""

-- Simpler and clearer: inline the full payload as one contiguous hex blob.
negotiate = hex(
  "0000008500000000" ..               -- NetBIOS framing (length = 0x85)
  "ff534d42" ..                       -- "\xffSMB"
  "72000000000018" ..                 -- Negotiate + flags
  "53c80000000000000000000000000000" ..
  "0000fffe00000000" ..
  "006200025043204e4554574f524b2050524f4752414d20312e3000" ..
  "024c414e4d414e312e3000" ..
  "0257696e646f777320666f7220576f726b67726f75707320332e3161" .. "00" ..
  "024c4d312e3258303032" .. "00" ..
  "024c414e4d414e322e31" .. "00" ..
  "024e54204c4d20302e3132" .. "00"
)

function run(host, port)
  local c, err = scry.tcp.connect(host, port, {timeout = 2000})
  if err then return nil, err end
  local _, serr = c:send(negotiate)
  if serr then c:close(); return nil, serr end
  local reply, rerr = c:read(256)
  c:close()
  if rerr and rerr ~= "timeout" then return nil, rerr end
  if not reply or #reply < 8 then return end

  local magic = reply:sub(5, 8)
  if magic == "\255SMB" then
    local dialect_lo = reply:byte(38) or 0
    local dialect_hi = reply:byte(39) or 0
    return "smb1: selected dialect index " .. (dialect_lo + dialect_hi * 256)
  elseif magic == "\254SMB" then
    return "smb2+ (server rejected SMB1 Negotiate)"
  end
  return "smb: unknown response"
end
