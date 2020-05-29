
local proto = Proto("Microsoft-Windows-NDIS-PacketCapture", "Microsoft-Windows-NDIS-PacketCapture")
local event_id = Field.new("etw.header.EventDescriptor.Id")
local event_version = Field.new("etw.header.EventDescriptor.Version")
local dissector_table = DissectorTable.new("Microsoft-Windows-NDIS-PacketCapture", "Microsoft-Windows-NDIS-PacketCapture 2ed6006e-4729-4609-b423-3ee7bcd678ef", ftypes.STRING)
function proto.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local id = event_id()
    local version = event_version()
	dissector_table:try(tostring(id) .. "." .. tostring(version) , buffer, pinfo, tree)
end
local etw_dissector_table = DissectorTable.get("etw")
etw_dissector_table:add("2ed6006e-4729-4609-b423-3ee7bcd678ef", proto)

event_proto_1001_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1001.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1001) Version(0)")

event_proto_1001_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1001.MiniportIfIndex", "MiniportIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1001.LowerIfIndex", "LowerIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1001.FragmentSize", "FragmentSize", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.1001.Fragment", "Fragment", base.NONE), ProtoField.uint64("Microsoft-Windows-NDIS-PacketCapture.1001.GftFlowEntryId", "GftFlowEntryId", base.DEC), ProtoField.uint64("Microsoft-Windows-NDIS-PacketCapture.1001.GftOffloadInformation", "GftOffloadInformation", base.DEC) }


function event_proto_1001_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1001_0.name
	
	local fields = tree:add(event_proto_1001_0, buffer())
	local index = 0
	
    local MiniportIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1001_0.fields[1], buffer(index, 4))
    index = index + 4


    local LowerIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1001_0.fields[2], buffer(index, 4))
    index = index + 4


    local FragmentSize_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1001_0.fields[3], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1001_0.fields[4], buffer(index, FragmentSize_value))
    index = index + FragmentSize_value


    local GftFlowEntryId_value = buffer(index, 8):le_uint64()
    fields:add_le(event_proto_1001_0.fields[5], buffer(index, 8))
    index = index + 8


    local GftOffloadInformation_value = buffer(index, 8):le_uint64()
    fields:add_le(event_proto_1001_0.fields[6], buffer(index, 8))
    index = index + 8
	
	local ethernet = Dissector.get("eth_withoutfcs")
	ethernet:call(buffer(12, FragmentSize_value):tvb() , pinfo , tree )

end

dissector_table:add("1001.0", event_proto_1001_0)

event_proto_1002_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1002.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1002) Version(0)")

event_proto_1002_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1002.MiniportIfIndex", "MiniportIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1002.LowerIfIndex", "LowerIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1002.MetadataSize", "MetadataSize", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.1002.Metadata", "Metadata", base.NONE) }


function event_proto_1002_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1002_0.name
	
	local fields = tree:add(event_proto_1002_0, buffer())
	local index = 0
	
    local MiniportIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1002_0.fields[1], buffer(index, 4))
    index = index + 4


    local LowerIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1002_0.fields[2], buffer(index, 4))
    index = index + 4


    local MetadataSize_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1002_0.fields[3], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1002_0.fields[4], buffer(index, MetadataSize_value))
    index = index + MetadataSize_value


end

dissector_table:add("1002.0", event_proto_1002_0)

event_proto_1003_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1003.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1003) Version(0)")

event_proto_1003_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.MiniportIfIndex", "MiniportIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.LowerIfIndex", "LowerIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.SourcePortId", "SourcePortId", base.DEC), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1003.SourcePortName", "SourcePortName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1003.SourceNicName", "SourceNicName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1003.SourceNicType", "SourceNicType", base.UNICODE), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.DestinationCount", "DestinationCount", base.DEC), ProtoField.double("Microsoft-Windows-NDIS-PacketCapture.1003.Destination", "Destination", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.FragmentSize", "FragmentSize", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.1003.Fragment", "Fragment", base.NONE), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1003.OOBDataSize", "OOBDataSize", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.1003.OOBData", "OOBData", base.NONE) }


function event_proto_1003_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1003_0.name
	
	local fields = tree:add(event_proto_1003_0, buffer())
	local index = 0
	
    local MiniportIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[1], buffer(index, 4))
    index = index + 4


    local LowerIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[2], buffer(index, 4))
    index = index + 4


    local SourcePortId_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[3], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1003_0.fields[4], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1003_0.fields[5], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1003_0.fields[6], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    local DestinationCount_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[7], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1003_0.fields[8], buffer(index, 8))
    index = index + 8


    local FragmentSize_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[9], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1003_0.fields[10], buffer(index, FragmentSize_value))
    index = index + FragmentSize_value


    local OOBDataSize_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1003_0.fields[11], buffer(index, 4))
    index = index + 4


    fields:add_le(event_proto_1003_0.fields[12], buffer(index, OOBDataSize_value))
    index = index + OOBDataSize_value


end

dissector_table:add("1003.0", event_proto_1003_0)

event_proto_1011_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1011.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1011) Version(0)")

event_proto_1011_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1011.RulesCount", "RulesCount", base.DEC) }


function event_proto_1011_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1011_0.name
	
	local fields = tree:add(event_proto_1011_0, buffer())
	local index = 0
	
    local RulesCount_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1011_0.fields[1], buffer(index, 4))
    index = index + 4


end

dissector_table:add("1011.0", event_proto_1011_0)

event_proto_1012_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1012.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1012) Version(0)")

event_proto_1012_0.fields = { ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1012.FriendlyName", "FriendlyName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1012.UniqueName", "UniqueName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1012.ServiceName", "ServiceName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1012.Version", "Version", base.UNICODE) }


function event_proto_1012_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1012_0.name
	
	local fields = tree:add(event_proto_1012_0, buffer())
	local index = 0
	
    fields:add_le(event_proto_1012_0.fields[1], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1012_0.fields[2], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1012_0.fields[3], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1012_0.fields[4], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


end

dissector_table:add("1012.0", event_proto_1012_0)

event_proto_1013_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1013.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1013) Version(0)")

event_proto_1013_0.fields = { ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1013.FriendlyName", "FriendlyName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1013.UniqueName", "UniqueName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1013.ServiceName", "ServiceName", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.1013.Version", "Version", base.UNICODE) }


function event_proto_1013_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1013_0.name
	
	local fields = tree:add(event_proto_1013_0, buffer())
	local index = 0
	
    fields:add_le(event_proto_1013_0.fields[1], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1013_0.fields[2], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1013_0.fields[3], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_1013_0.fields[4], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


end

dissector_table:add("1013.0", event_proto_1013_0)

event_proto_1014_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1014.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1014) Version(0)")

event_proto_1014_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1014.MiniportIfIndex", "MiniportIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1014.LowerIfIndex", "LowerIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1014.MediaType", "MediaType", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1014.ReferenceContext", "ReferenceContext", base.DEC) }


function event_proto_1014_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1014_0.name
	
	local fields = tree:add(event_proto_1014_0, buffer())
	local index = 0
	
    local MiniportIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1014_0.fields[1], buffer(index, 4))
    index = index + 4


    local LowerIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1014_0.fields[2], buffer(index, 4))
    index = index + 4


    local MediaType_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1014_0.fields[3], buffer(index, 4))
    index = index + 4


    local ReferenceContext_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1014_0.fields[4], buffer(index, 4))
    index = index + 4


end

dissector_table:add("1014.0", event_proto_1014_0)

event_proto_1015_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1015.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1015) Version(0)")

event_proto_1015_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1015.MiniportIfIndex", "MiniportIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1015.LowerIfIndex", "LowerIfIndex", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1015.MediaType", "MediaType", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.1015.ReferenceContext", "ReferenceContext", base.DEC) }


function event_proto_1015_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1015_0.name
	
	local fields = tree:add(event_proto_1015_0, buffer())
	local index = 0
	
    local MiniportIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1015_0.fields[1], buffer(index, 4))
    index = index + 4


    local LowerIfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1015_0.fields[2], buffer(index, 4))
    index = index + 4


    local MediaType_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1015_0.fields[3], buffer(index, 4))
    index = index + 4


    local ReferenceContext_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_1015_0.fields[4], buffer(index, 4))
    index = index + 4


end

dissector_table:add("1015.0", event_proto_1015_0)

event_proto_1016_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.1016.0", "Microsoft-Windows-NDIS-PacketCapture EventId(1016) Version(0)")

event_proto_1016_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.1016.RuleId", "RuleId", base.DEC), ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.1016.Directive", "Directive", base.DEC), ProtoField.uint16("Microsoft-Windows-NDIS-PacketCapture.1016.Length", "Length", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.1016.Value", "Value", base.NONE) }


function event_proto_1016_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_1016_0.name
	
	local fields = tree:add(event_proto_1016_0, buffer())
	local index = 0
	
    local RuleId_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_1016_0.fields[1], buffer(index, 1))
    index = index + 1


    local Directive_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_1016_0.fields[2], buffer(index, 1))
    index = index + 1


    local Length_value = buffer(index, 2):le_uint()
    fields:add_le(event_proto_1016_0.fields[3], buffer(index, 2))
    index = index + 2


    fields:add_le(event_proto_1016_0.fields[4], buffer(index, Length_value))
    index = index + Length_value


end

dissector_table:add("1016.0", event_proto_1016_0)

event_proto_2001_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.2001.0", "Microsoft-Windows-NDIS-PacketCapture EventId(2001) Version(0)")

event_proto_2001_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2001.ErrorCode", "ErrorCode", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2001.Location", "Location", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2001.Context", "Context", base.DEC) }


function event_proto_2001_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_2001_0.name
	
	local fields = tree:add(event_proto_2001_0, buffer())
	local index = 0
	
    local ErrorCode_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2001_0.fields[1], buffer(index, 4))
    index = index + 4


    local Location_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2001_0.fields[2], buffer(index, 4))
    index = index + 4


    local Context_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2001_0.fields[3], buffer(index, 4))
    index = index + 4


end

dissector_table:add("2001.0", event_proto_2001_0)

event_proto_2002_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.2002.0", "Microsoft-Windows-NDIS-PacketCapture EventId(2002) Version(0)")

event_proto_2002_0.fields = { ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2002.ErrorCode", "ErrorCode", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2002.Location", "Location", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.2002.Context", "Context", base.DEC) }


function event_proto_2002_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_2002_0.name
	
	local fields = tree:add(event_proto_2002_0, buffer())
	local index = 0
	
    local ErrorCode_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2002_0.fields[1], buffer(index, 4))
    index = index + 4


    local Location_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2002_0.fields[2], buffer(index, 4))
    index = index + 4


    local Context_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_2002_0.fields[3], buffer(index, 4))
    index = index + 4


end

dissector_table:add("2002.0", event_proto_2002_0)

event_proto_2003_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.2003.0", "Microsoft-Windows-NDIS-PacketCapture EventId(2003) Version(0)")

event_proto_2003_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.2003.RuleId", "RuleId", base.DEC), ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.2003.Directive", "Directive", base.DEC), ProtoField.uint16("Microsoft-Windows-NDIS-PacketCapture.2003.Length", "Length", base.DEC), ProtoField.bytes("Microsoft-Windows-NDIS-PacketCapture.2003.Value", "Value", base.NONE) }


function event_proto_2003_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_2003_0.name
	
	local fields = tree:add(event_proto_2003_0, buffer())
	local index = 0
	
    local RuleId_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_2003_0.fields[1], buffer(index, 1))
    index = index + 1


    local Directive_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_2003_0.fields[2], buffer(index, 1))
    index = index + 1


    local Length_value = buffer(index, 2):le_uint()
    fields:add_le(event_proto_2003_0.fields[3], buffer(index, 2))
    index = index + 2


    fields:add_le(event_proto_2003_0.fields[4], buffer(index, Length_value))
    index = index + Length_value


end

dissector_table:add("2003.0", event_proto_2003_0)

event_proto_3001_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.3001.0", "Microsoft-Windows-NDIS-PacketCapture EventId(3001) Version(0)")

event_proto_3001_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.3001.PreviousState", "PreviousState", base.DEC), ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.3001.NextState", "NextState", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.3001.Location", "Location", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.3001.Context", "Context", base.DEC) }


function event_proto_3001_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_3001_0.name
	
	local fields = tree:add(event_proto_3001_0, buffer())
	local index = 0
	
    local PreviousState_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_3001_0.fields[1], buffer(index, 1))
    index = index + 1


    local NextState_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_3001_0.fields[2], buffer(index, 1))
    index = index + 1


    local Location_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_3001_0.fields[3], buffer(index, 4))
    index = index + 4


    local Context_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_3001_0.fields[4], buffer(index, 4))
    index = index + 4


end

dissector_table:add("3001.0", event_proto_3001_0)

event_proto_3002_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.3002.0", "Microsoft-Windows-NDIS-PacketCapture EventId(3002) Version(0)")

event_proto_3002_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.3002.PreviousState", "PreviousState", base.DEC), ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.3002.NextState", "NextState", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.3002.Location", "Location", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.3002.Context", "Context", base.DEC) }


function event_proto_3002_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_3002_0.name
	
	local fields = tree:add(event_proto_3002_0, buffer())
	local index = 0
	
    local PreviousState_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_3002_0.fields[1], buffer(index, 1))
    index = index + 1


    local NextState_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_3002_0.fields[2], buffer(index, 1))
    index = index + 1


    local Location_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_3002_0.fields[3], buffer(index, 4))
    index = index + 4


    local Context_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_3002_0.fields[4], buffer(index, 4))
    index = index + 4


end

dissector_table:add("3002.0", event_proto_3002_0)

event_proto_5100_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.5100.0", "Microsoft-Windows-NDIS-PacketCapture EventId(5100) Version(0)")

event_proto_5100_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.5100.SourceId", "SourceId", base.DEC), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.5100.RundownId", "RundownId", base.DEC), ProtoField.uint64("Microsoft-Windows-NDIS-PacketCapture.5100.Param1", "Param1", base.DEC), ProtoField.uint64("Microsoft-Windows-NDIS-PacketCapture.5100.Param2", "Param2", base.DEC), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.5100.ParamStr", "ParamStr", base.UNICODE), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.5100.Description", "Description", base.UNICODE) }


function event_proto_5100_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_5100_0.name
	
	local fields = tree:add(event_proto_5100_0, buffer())
	local index = 0
	
    local SourceId_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_5100_0.fields[1], buffer(index, 1))
    index = index + 1


    local RundownId_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_5100_0.fields[2], buffer(index, 4))
    index = index + 4


    local Param1_value = buffer(index, 8):le_uint64()
    fields:add_le(event_proto_5100_0.fields[3], buffer(index, 8))
    index = index + 8


    local Param2_value = buffer(index, 8):le_uint64()
    fields:add_le(event_proto_5100_0.fields[4], buffer(index, 8))
    index = index + 8


    fields:add_le(event_proto_5100_0.fields[5], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    fields:add_le(event_proto_5100_0.fields[6], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


end

dissector_table:add("5100.0", event_proto_5100_0)

event_proto_5101_0 = Proto("Microsoft-Windows-NDIS-PacketCapture.5101.0", "Microsoft-Windows-NDIS-PacketCapture EventId(5101) Version(0)")

event_proto_5101_0.fields = { ProtoField.uint8("Microsoft-Windows-NDIS-PacketCapture.5101.SourceId", "SourceId", base.DEC), ProtoField.string("Microsoft-Windows-NDIS-PacketCapture.5101.SourceName", "SourceName", base.UNICODE), ProtoField.uint32("Microsoft-Windows-NDIS-PacketCapture.5101.IfIndex", "IfIndex", base.DEC), ProtoField.uint16("Microsoft-Windows-NDIS-PacketCapture.5101.LayerCount", "LayerCount", base.DEC), ProtoField.int16("Microsoft-Windows-NDIS-PacketCapture.5101.LayerInfo", "LayerInfo", base.DEC) }


function event_proto_5101_0.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	pinfo.cols.protocol = event_proto_5101_0.name
	
	local fields = tree:add(event_proto_5101_0, buffer())
	local index = 0
	
    local SourceId_value = buffer(index, 1):le_uint()
    fields:add_le(event_proto_5101_0.fields[1], buffer(index, 1))
    index = index + 1


    fields:add_le(event_proto_5101_0.fields[2], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2


    local IfIndex_value = buffer(index, 4):le_uint()
    fields:add_le(event_proto_5101_0.fields[3], buffer(index, 4))
    index = index + 4


    local LayerCount_value = buffer(index, 2):le_uint()
    fields:add_le(event_proto_5101_0.fields[4], buffer(index, 2))
    index = index + 2


    local LayerInfo_value = buffer(index, 2):le_int()
    fields:add_le(event_proto_5101_0.fields[5], buffer(index, 2))
    index = index + 2


end

dissector_table:add("5101.0", event_proto_5101_0)

