-- This is the main dissector for all winshark based dissector
-- This dissector will parse all meta infos for ETW packet captured
-- throw the ETW backend for lib pcap

etw_proto = Proto("ETW","Event Trace for Windows");

local header_size = ProtoField.uint16("etw.header.Size", "Size", base.DEC);
local header_type = ProtoField.uint16("etw.header.HeaderType", "HeaderType", base.DEC);
local header_flags = ProtoField.uint16("etw.header.Flags", "Flags", base.DEC);
local header_eventproperty = ProtoField.uint16("etw.header.EventProperty", "EventProperty", base.DEC);
local header_threadid = ProtoField.uint32("etw.header.ThreadId", "ThreadId", base.DEC);
local header_processid = ProtoField.uint32("etw.header.ProcessId", "ProcessId", base.DEC);
local header_timestamp = ProtoField.uint64("etw.header.TimeStamp", "TimeStamp", base.DEC);
local header_providerid = ProtoField.guid("etw.header.ProviderId", "ProviderId", base.DEC);
local header_processtime = ProtoField.uint64("etw.header.ProcessorTime", "ProcessorTime", base.DEC);
local header_activityid = ProtoField.guid("etw.header.ActivityId", "ActivityId", base.DEC);

local header_eventdescriptor_id = ProtoField.uint16("etw.header.EventDescriptor.Id", "Id", base.DEC);
local header_eventdescriptor_version = ProtoField.uint8("etw.header.EventDescriptor.Version", "Version", base.DEC);
local header_eventdescriptor_channel = ProtoField.uint8("etw.header.EventDescriptor.Channel", "Channel", base.DEC);
local header_eventdescriptor_level = ProtoField.uint8("etw.header.EventDescriptor.Level", "Level", base.DEC);
local header_eventdescriptor_opcode = ProtoField.uint8("etw.header.EventDescriptor.Opcode", "Opcode", base.DEC);
local header_eventdescriptor_task = ProtoField.uint16("etw.header.EventDescriptor.Task", "Task", base.DEC);
local header_eventdescriptor_keyword = ProtoField.uint64("etw.header.EventDescriptor.Keyword", "Keyword", base.HEX);

local header_extendeddatalength = ProtoField.uint16("etw.header.ExtendedDataLength", "ExtendedDataLength", base.DEC);
local header_extendeddata = ProtoField.bytes("etw.ExtendedData", "ExtendedData", base.NONE);
local header_extendeddatatype = ProtoField.uint16("etw.ExtendedData.Type", "ExtType", base.DEC);
local header_extendeddatasize = ProtoField.uint16("etw.ExtendedData.Size", "DataSize", base.DEC);


etw_proto.fields = {
	header_size,
	header_type,
	header_flags,
	header_eventproperty,
	header_threadid,
	header_processid,
	header_timestamp,
	header_providerid,
	header_processtime,
	header_activityid,
	header_eventdescriptor_id,
	header_eventdescriptor_version,
	header_eventdescriptor_channel,
	header_eventdescriptor_level,
	header_eventdescriptor_opcode,
	header_eventdescriptor_task,
	header_eventdescriptor_keyword,
	header_extendeddatalength,
	header_extendeddatasize,
	header_extendeddatatype,
	header_extendeddata
}

-- declate the personnal etw dissector table
etw_dissector_table = DissectorTable.new("etw", "Event Tracing for Windows", ftypes.STRING)

function etw_proto.dissector(buffer, pinfo, tree)
	length = buffer:len();
	if length == 0 then return end

	pinfo.cols.protocol = etw_proto.name;
	
	local etw = tree:add(etw_proto, buffer());
	local event_header = etw:add(buffer(0, 80), "EventHeader")
	
	event_header:add_le(header_size, buffer(0, 2));
	event_header:add_le(header_type, buffer(2, 2));
	event_header:add_le(header_flags, buffer(4, 2));
	event_header:add_le(header_eventproperty, buffer(6, 2));
	event_header:add_le(header_threadid, buffer(8, 4));
	event_header:add_le(header_processid, buffer(12, 4));
	event_header:add_le(header_timestamp, buffer(16, 8));
	event_header:add_le(header_providerid, buffer(24, 16));
	
	local event_descriptor = event_header:add(buffer(40, 16), "EventDescriptor");
	event_descriptor:add_le(header_eventdescriptor_id, buffer(40, 2));
	event_descriptor:add_le(header_eventdescriptor_version, buffer(42, 1));
	event_descriptor:add_le(header_eventdescriptor_channel, buffer(43, 1));
	event_descriptor:add_le(header_eventdescriptor_level, buffer(44, 1));
	event_descriptor:add_le(header_eventdescriptor_opcode, buffer(45, 1));
	event_descriptor:add_le(header_eventdescriptor_task, buffer(46, 2));
	event_descriptor:add_le(header_eventdescriptor_keyword, buffer(48, 8));
	
	event_header:add_le(header_processtime, buffer(56, 8));
	event_header:add_le(header_activityid, buffer(64, 16));
	event_header:add_le(header_extendeddatalength, buffer(80, 2));
	
	-- convert to string guid
	-- Provider id is the switch use by sub dissector
	-- Tracelogging use trcelogging string as identifier
	local providerid = string.format("%08x-%04x-%04x-%04x-%04x%04x%04x", 
		buffer(24, 4):le_uint(), 
		buffer(28, 2):le_uint(), 
		buffer(30, 2):le_uint(), 
		buffer(32, 2):uint(), buffer(34, 2):uint(), buffer(36, 2):uint(), buffer(38, 2):uint()
	);
	
	extended_data_length = buffer(80, 2):le_uint();
	local extended_data = etw:add_le(header_extendeddata, buffer(82, extended_data_length));
	
	local offset = 0;
	local index = 0;
	while offset < extended_data_length do
		local ext_type = buffer(82 + offset, 2):le_uint()
		local size = buffer(82 + offset + 2, 2):le_uint()
		local data = extended_data:add(buffer(82 + offset, size + 4), string.format("[%d]", index))
		
		index = index + 1
		
		data:add_le(header_extendeddatatype, buffer(82 + offset, 2))
		data:add_le(header_extendeddatasize, buffer(82 + offset + 2, 2))
		data:add(buffer(82 + offset + 4, size), "Data")
		
		-- detecting trace logging protocol
		-- tracelogging encompass its scheme directly into extended data
		if ext_type == 11 then 
			providerid = "Tracelogging"
		end
		
		offset = offset + size + 4;
	end
	
	-- select corect dissector and pass UserData
	etw:add(buffer(82 + extended_data_length, length - 82 - extended_data_length), "UserData")
	etw_dissector_table:try(providerid, buffer(82 + extended_data_length, length - 82 - extended_data_length):tvb(), pinfo, tree);
		
end

