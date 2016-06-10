--require("bit")

mist_protocol = Proto("Mist",  "The Chat Protocol")


msg_type =ProtoField.uint16("Mist.MessageType","MessageType",base.DEC)
user = ProtoField.string("Mist.User","User","Text")
msglen = ProtoField.uint8("Mist.Length","Message Length",base.DEC)
message = ProtoField.string("Mist.Message","Message","Text")
mist_protocol.fields = {msg_type,user,msglen,message}
					
function mist_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = mist_protocol.name;
	
	subtree = tree:add(mist_protocol,buffer())
	
	mtype = buffer(0,2):le_uint()
	mtype_str = "Connect"
	
	if mtype == 3 then mtype_str = "Disconnect" end
	if mtype == 4 then mtype_str = "ChatMessage" end
	subtree:add_le(msg_type,buffer(0,2)):append_text(" (" .. mtype_str .. ")")
	subtree:add(user,buffer(2,5))
	
	if mtype == 4 then
		subtree:add_le(msglen,buffer(7,2))
		subtree:add(message,buffer(9,buffer(7,2):le_uint()))
	end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8888,mist_protocol)