-- This is the main tracelogging disector
-- As tracelogging encompass its scheme directly into 
-- Extended data, we need to create dynamic Proto bases on scheme
-- Read from extendedata field from etw dissector

local tracelogging = Proto("Tracelogging", "Tracelogging")

-- field use by Tracelogging to extract scheme
local extended_data_field = Field.new("etw.ExtendedData")

local tl_dissector_table = DissectorTable.new("Tracelogging", "Tracelogging", ftypes.STRING)

-- This function convert scheme type into lua type
-- tree: current tree node use to display type
-- buffer: buffer contain type
-- tag_type: type extracted from scheme
-- tag_name: name extracted from scheme
function parse_field(tree, buffer, tag_type, tag_name)
	tag_name_formated = string.format("%s:", tag_name);
	if tag_type == 1 then local value = buffer(0):le_ustringz(); tree:add(tag_name_formated, value) ; return (value:len() + 1) * 2;
	elseif tag_type == 2 then local value = buffer(0):stringz(); tree:add(tag_name_formated, value) ; return value:len() + 1;
	elseif tag_type == 3 then tree:add(tag_name_formated, buffer(0, 1):le_int()); return 1;
	elseif tag_type == 4 then tree:add(tag_name_formated, buffer(0, 1):le_uint()); return 1;
	elseif tag_type == 5 then tree:add(tag_name_formated, buffer(0, 2):le_int()); return 2;
	elseif tag_type == 6 then tree:add(tag_name_formated, buffer(0, 2):le_uint()); return 2;
	elseif tag_type == 7 then tree:add(tag_name_formated, buffer(0, 4):le_int()); return 4;
	elseif tag_type == 8 then tree:add(tag_name_formated, buffer(0, 4):le_uint()); return 4;
	elseif tag_type == 9 then tree:add(tag_name_formated, buffer(0, 8):le_uint64()); return 8;
	elseif tag_type == 10 then tree:add(tag_name_formated, buffer(0, 8):le_int64()); return 8;
	elseif tag_type == 11 then tree:add(tag_name_formated, buffer(0, 4):le_float()); return 4;
	elseif tag_type == 12 then tree:add(tag_name_formated, buffer(0, 8):le_float()); return 8;
	elseif tag_type == 13 then tree:add(tag_name_formated, buffer(0, 4):le_uint()); return 4;
	elseif tag_type == 14 then return parse_array_field(tree, buffer, tag_type, tag_name);
	elseif tag_type == 15 then tree:add(tag_name_formated, buffer(0, 16)); return 16;
	elseif tag_type == 17 then tree:add(tag_name_formated, buffer(0, 8)); return 8;
	elseif tag_type == 18 then tree:add(tag_name_formated, buffer(0, 16)); return 16;
	elseif tag_type == 20 then tree:add(tag_name_formated, buffer(0, 4):le_uint()); return 4;
	elseif tag_type == 21 then tree:add(tag_name_formated, buffer(0, 8):le_uint()); return 8;
	end
end

-- Parse an array of type as defined by tracelogging macro
-- tree: current tree node use to display type
-- buffer: buffer contain type
-- tag_type: type extracted from scheme
-- tag_name: name extracted from scheme
function parse_array_field(tree, buffer, tag_type, tag_name)
	local i = 0;
	local nb = buffer(0, 2):le_uint();
	local index = 2;
	
	local array = tree:add(tag_name);
	while i < nb do
		index = index + parse_field(array, buffer(index):tvb(), tag_type, string.format("[%d]", i));
		i = i + 1;
	end
	return index
end

-- Tracelogging dissector definition
-- Mainly extract scheme from extendedata parse from etw dissector
-- and create a sub Proto for this scheme if not parsed before
-- WARNING: TL accept that different scheme for same TL name, this not handle by this dissector
function tracelogging.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	
	local name = nil
	local scheme = {}
	
	local extended_data = extended_data_field()():tvb()
	local offset = 0
	
	while offset < extended_data:len() do
		local ext_type = extended_data(offset, 2):le_uint()
		local size = extended_data(offset + 2, 2):le_uint()
		local data = extended_data(offset + 4, size):tvb()
		
		-- detect scheme
		if ext_type == 11 then 
			local size = data(0, 2):le_uint()		
			local tag = data(2, 1):le_uint()
			-- name of the protocol
			name = data(3):stringz():gsub(" ", "_")
			local scheme_data = data(3 + name:len() + 1):tvb()
			local offset_scheme = 0
			local index_tag = 1
			
			while offset_scheme < scheme_data:len() do

				local field_name = scheme_data(offset_scheme):stringz():gsub(" ", "_")
				local tag_in = scheme_data(offset_scheme + field_name:len() + 1, 1):le_uint()
				
				offset_scheme = offset_scheme + field_name:len() + 1 + 1
				-- tag out field ignore
				if bit32.band(tag_in, 0x80) == 0x80 then
					print("tag_out")
					local tag_out = scheme_data(offset_scheme, 1):le_uint()
					if bit32.band(tag_out, 0x80) == 0x80 then
						offset_scheme = offset_scheme + 5
					else
						offset_scheme = offset_scheme + 1
					end
				end
				
				scheme[index_tag] = {tag = tag_in, name = field_name}
				
				index_tag = index_tag + 1
			end
		end
		offset = offset + size + 4
	end
	
	tl_proto = tl_dissector_table:get_dissector(name)

	if tl_proto == nil then
		local tl_proto = Proto(name, name)
		tl_proto.dissector = function(buffer, pinfo, tree)
			pinfo.cols.protocol = tl_proto.name
			
			local proto_tree = tree:add(tl_proto, buffer())
			local index = 0
			-- loop over all scheme entry and parse them
			for i, element in ipairs(scheme) do
				local tag_type = bit32.band(element.tag, 0x1F)
				local is_array = bit32.band(element.tag, 0x20) == 0x20 or bit32.band(element.tag, 0x40) == 0x40
				if is_array then 
					index = index + parse_array_field(proto_tree, buffer(index):tvb(), tag_type, element.name)
				else
					index = index + parse_field(proto_tree, buffer(index):tvb(), tag_type, element.name)
				end
			end
		end
		
		tl_dissector_table:add(name, tl_proto)
	end
	
	tl_dissector_table:try(name, buffer, pinfo, tree)
end

local etw_dissector_table = DissectorTable.get("etw")
etw_dissector_table:add("Tracelogging", tracelogging)