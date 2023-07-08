-- Wireshark packet dissector for the KingsIsle Network Protocol
-- Documentation: docs/protocol/
-- NOTE: Only intended to be used with game revisions < V_r692052.Wizard_1_440

local kinp_plugin_info = {
  version = "0.1.0",
  author = "Valentin B.",
  description = "Wireshark packet dissector for the KingsIsle Network Protocol",
  repository = "https://github.com/vbe0201/wizproxy"
}
set_plugin_info(kinp_plugin_info)

local kinp_proto = Proto("kinp", "KingsIsle Network Protocol")
local kinp_fields = kinp_proto.fields

-------------------------------------------------------------------------------
-- Session Offer and Session Accept
-------------------------------------------------------------------------------

kinp_fields.session_id = ProtoField.uint16("kinp.session_id", "Session ID", base.DEC)
kinp_fields.timestamp = ProtoField.int32("kinp.timestamp", "Timestamp", base.DEC)
kinp_fields.millis = ProtoField.uint32("kinp.millis", "Milliseconds", base.DEC)

function parse_session_offer(buffer, _, tree)
  tree:add_le(kinp_fields.session_id, buffer(0, 2))
  tree:add_le(kinp_fields.timestamp, buffer(6, 4))
  tree:add_le(kinp_fields.millis, buffer(10, 4))
end

function parse_session_accept(buffer, _, tree)
  tree:add_le(kinp_fields.timestamp, buffer(6, 4))
  tree:add_le(kinp_fields.millis, buffer(10, 4))
  tree:add_le(kinp_fields.session_id, buffer(14, 2))
end

-------------------------------------------------------------------------------
-- Keep Alive and Keep Alive Rsp
-------------------------------------------------------------------------------

kinp_fields.session_minutes = ProtoField.uint16("kinp.session_minutes", "Minutes since session start", base.DEC)
kinp_fields.server_millis = ProtoField.uint32("kinp.server_millis", "Milliseconds since server start", base.DEC)

function parse_keep_alive(buffer, pinfo, tree)
  if pinfo.src_port >= 12000 and pinfo.src_port < 13000 then
    tree:add_le(kinp_fields.server_millis, buffer(2, 4))
  else
    tree:add_le(kinp_fields.session_id, buffer(0, 2))
    tree:add_le(kinp_fields.millis, buffer(2, 2))
    tree:add_le(kinp_fields.session_minutes, buffer(4, 2))
  end
end

function parse_keep_alive_rsp(buffer, pinfo, tree)
  if pinfo.src_port >= 12000 and pinfo.src_port < 13000 then
    tree:add_le(kinp_fields.session_id, buffer(0, 2))
    tree:add_le(kinp_fields.millis, buffer(2, 2))
    tree:add_le(kinp_fields.session_minutes, buffer(4, 2))
  else
    tree:add_le(kinp_fields.server_millis, buffer(2, 4))
  end
end

-------------------------------------------------------------------------------
-- DML messages
-------------------------------------------------------------------------------

dml_protocol_ids = {
  [1]  = "Base Messages",
  [2]  = "Extended Base Messages",
  [5]  = "Game Messages",
  [7]  = "Login Messages",
  [8]  = "Patch Messages",
  [9]  = "Pet Messages",
  [10] = "Script Messages",
  [11] = "Test Manager Messages",
  [12] = "Wizard Messages",
  [15] = "Move Behavior Messages",
  [16] = "Physics Messages",
  [19] = "AISClient Messages",
  [25] = "Sob Blocks Messages",
  [40] = "Skull Riders Messages",
  [41] = "Doodle Doug Messages",
  [42] = "MG1 Messages",
  [43] = "MG2 Messages",
  [44] = "MG3 Messages",
  [45] = "MG4 Messages",
  [46] = "MG5 Messages",
  [47] = "MG6 Messages",
  [50] = "Wizard Housing",
  [51] = "Duel Messages",
  [52] = "Quest Messages",
  [53] = "Wizard2 Messages",
  [54] = "Catch A Key Messages",
  [55] = "Game2 Messages",
  [56] = "Wizard3 Messages",
  [57] = "Cantrips Messages",
}

kinp_fields.dml_proto_id = ProtoField.uint8("kinp.dml_proto_id", "DML Protocol ID", base.DEC, dml_protocol_ids)
kinp_fields.dml_msg_order = ProtoField.uint8("kinp.dml_msg_order", "DML Message Order", base.DEC)
kinp_fields.dml_msg_len = ProtoField.uint16("kinp.dml_msg_len", "DML Message Length", base.HEX)
kinp_fields.dml_raw_msg = ProtoField.bytes("kinp.dml_raw_msg", "Raw DML Message data")

function parse_dml_payload(buffer, _, tree)
  local dml_msg_len = buffer(2, 2)

  tree:add(kinp_fields.dml_proto_id, buffer(0, 1))
  tree:add(kinp_fields.dml_msg_order, buffer(1, 1))
  tree:add_le(kinp_fields.dml_msg_len, dml_msg_len)
  tree:add(kinp_fields.dml_raw_msg, buffer(4, dml_msg_len:le_uint() - 4))
end

-------------------------------------------------------------------------------

kinp_ctrl_opcodes = {
  [0] = "Session Offer",
  [3] = "Keep Alive",
  [4] = "Keep Alive Rsp",
  [5] = "Session Accept"
}

kinp_data_opcodes = {
  [0] = "DML Message"
}

ctrl_packet = {
  [0] = parse_session_offer,
  [3] = parse_keep_alive,
  [4] = parse_keep_alive_rsp,
  [5] = parse_session_accept
}

data_packet = {
  [0] = parse_dml_payload
}

kinp_fields.is_ctrl = ProtoField.bool("kinp.is_ctrl", "Is Control Message")
kinp_fields.op_ctrl = ProtoField.uint8("kinp.op_ctrl", "Control Opcode", base.DEC, kinp_ctrl_opcodes)
kinp_fields.op_data = ProtoField.uint8("kinp.op_data", "Data Opcode", base.DEC, kinp_data_opcodes)

function kinp_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = kinp_proto.name

  if buffer(0, 2):le_uint() ~= 0xF00D then
    return false
  end

  local body_start
  if buffer(2, 2):le_uint() >= 0x8000 then
    body_start = 8
  else
    body_start = 4
  end

  local is_ctrl_message = buffer(body_start, 1):uint() ~= 0
  local opcode = buffer(body_start + 1, 1):uint()

  local subtree = tree:add(kinp_proto, buffer(), "KingsIsle Network Protocol")
  subtree:add(kinp_fields.is_ctrl, buffer(4, 1))
  if is_ctrl_message then
    subtree:add(kinp_fields.op_ctrl, buffer(body_start + 1, 1))
  end

  local parser = is_ctrl_message and ctrl_packet[opcode] or data_packet[opcode]
  if parser ~= nil then
    parser(buffer(body_start + 4), pinfo, subtree)
  end

  return true
end

local tcp_table = DissectorTable.get("tcp.port")
for port = 12000,12900,100 do
  tcp_table:add(port, kinp_proto)
end
