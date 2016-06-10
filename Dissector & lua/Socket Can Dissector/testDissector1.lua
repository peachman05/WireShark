--require("bit")
do
		CAN_Mo_protocol = Proto("CAN_Mo",  "The CAN Modify Protocol")
		data1 = ProtoField.bytes("CAN_Mo.Data1","Data 1",base.DEC)
		data2 = ProtoField.bytes("CAN_Mo.Data2","Data 2",base.DEC)
		CAN_Mo_protocol.fields = {data1,data2}
		encap_tbl = DissectorTable.get("wtap_encap")
		can_dis   = encap_tbl:get_dissector(wtap_encaps.SOCKETCAN)			  
		print("hello world!")
		
		function CAN_Mo_protocol.dissector(buffer, pinfo, tree)

			can_dis:call(buffer, pinfo, tree)			
			pinfo.cols.protocol = CAN_Mo_protocol.name;  -- fields name to Protocol column			
			subtree = tree:add(CAN_Mo_protocol,buffer()) -- create Head  Description of Detail			
			length = buffer(4,1):le_uint()
			if length > 0 and length <=4 then
				subtree:add(data1,buffer(8,length ))				
			end			
			if length > 4 then
				subtree:add(data1,buffer(8,4 ))
				subtree:add(data2,buffer(12,length - 4))
			end
			
		end
		
		encap_tbl:add(wtap_encaps.SOCKETCAN,CAN_Mo_protocol) -- You can use 125 instead wtap_encaps.SOCKETCAN.

end 
