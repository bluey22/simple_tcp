-- Wireshark lua dissector for tcp over udp implementation
-- Made by bailey dalton for CSDS325

-- How to use:
-- Go to Help>About Wireshark>Folders>Personal Lua Plugins and click the file location to drag this script into the folder
-- Then go to Analyze>Reload Lua Plugins
-- Afterwards, add the dissected fields as columns to show in the main window

-- UDP port that protocol runs on (default in starter code)
local tcp_over_udp_port = 54321

local p_tcp_over_udp = Proto("tcp_over_udp", "TCP over UDP")

local seq_num = ProtoField.uint32("tcp_over_udp.seq", "SEQ", base.DEC)
local ack_num = ProtoField.uint32("tcp_over_udp.ack", "ACK", base.DEC)
local flags = ProtoField.uint8("tcp_over_udp.flags", "FLAGS", base.HEX)
local payload_len = ProtoField.uint16("tcp_over_udp.payload_len", "Payload Length", base.DEC)
local payload = ProtoField.bytes("tcp_over_udp.payload", "Payload")
local payload_ascii = ProtoField.string("tcp_over_udp.payload_ascii", "Payload (ASCII)")

p_tcp_over_udp.fields = { seq_num, ack_num, flags , payload_len, payload, payload_ascii}

local SYN_FLAG = 0x8
local ACK_FLAG = 0x4
local FIN_FLAG = 0x2
local SACK_FLAG = 0x1

-- decode the flags into readable names
local function decode_flags(flags)
    local flag_names = {}
    if bit32.band(flags, SYN_FLAG) ~= 0 then
        table.insert(flag_names, "SYN")
    end
    if bit32.band(flags, ACK_FLAG) ~= 0 then
        table.insert(flag_names, "ACK")
    end
    if bit32.band(flags, FIN_FLAG) ~= 0 then
        table.insert(flag_names, "FIN")
    end
    if bit32.band(flags, SACK_FLAG) ~= 0 then
        table.insert(flag_names, "SACK")
    end
    return table.concat(flag_names, ", ")  -- the flag names with a comma if multiple
end

-- Function to convert a byte buffer into an ASCII string
-- This function written by ChatGPT
local function payload_to_ascii(tvbuf)
    local payload_ascii = ""
    for i = 0, tvbuf:len() - 1 do
        local byte = tvbuf(i, 1):uint()
        if byte >= 32 and byte <= 126 then  -- Printable ASCII range
            payload_ascii = payload_ascii .. string.char(byte)
        else
            payload_ascii = payload_ascii .. "."
        end
    end
    return payload_ascii
end


function p_tcp_over_udp.dissector(tvbuf, pinfo, tree)
    pinfo.cols.protocol = p_tcp_over_udp.name
    local subtree = tree:add(p_tcp_over_udp, tvbuf(), "TCP over UDP Data")
    subtree:add(seq_num, tvbuf(0, 4))
    subtree:add(ack_num, tvbuf(4, 4))
    subtree:add(payload_len, tvbuf(12, 2))
    
    -- get and parse payload data
    payload_data = tvbuf(14)
    subtree:add(payload, payload_data)
    subtree:add(payload_ascii, payload_to_ascii(payload_data))

    -- get the flag value, then put the readable strings into the info field
    local raw_flags = tvbuf(11, 1):uint()
    subtree:add(flags, tvbuf(11, 1)):append_text(" (" .. decode_flags(raw_flags) .. ")")
    pinfo.cols.info = "(" .. decode_flags(raw_flags) .. ")"
end


DissectorTable.get("udp.port"):add(tcp_over_udp_port, p_tcp_over_udp)
