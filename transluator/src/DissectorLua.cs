using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Xml.Serialization;
using Microsoft.Diagnostics.Tracing.Parsers;
using System.Linq;

namespace Transluator
{
    static class DissectorLUATemplate
    {
        public const string PROVIDER = @"
local proto = Proto(""{0}"", ""{0}"")
local event_id = Field.new(""winshark.header.EventDescriptor.Id"")
local event_version = Field.new(""winshark.header.EventDescriptor.Version"")
local dissector_table = DissectorTable.new(""{0}"", ""{0} {1}"", ftypes.STRING)
local protocols = {{}}
local current_protocol = nil
function proto.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local id = event_id()
    local version = event_version()
	dissector_table:try(tostring(id) .. ""."" .. tostring(version) , buffer, pinfo, tree)
end
local winshark_dissector_table = DissectorTable.get(""winshark"")
winshark_dissector_table:add(""{1}"", proto)
";
        public const string EVENT_HEADER = @"current_protocol = Proto(""{0}.{1}.{2}"", ""{0} EventId({1}) Version({2})"")";
        public const string EVENT_FIELD_NAME = @"{0}_{1}";
        public const string EVENT_FIELD = @"{1}(""{2}.{3}.{4}.{0}"", ""{0}"", {5})";
        public const string EVENT_PROTO_FIELD = @"current_protocol.fields = {{ {0} }}";

        public const string EVENT_DECLARATION = @"
function current_protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local event_proto_{0}_{1} = protocols[""{0}.{1}""]
	pinfo.cols.protocol = event_proto_{0}_{1}.name
	pinfo.cols.info = event_proto_{0}_{1}.description
	
	local fields = tree:add(event_proto_{0}_{1}, buffer())
	local index = 0
	{2}
end
protocols[""{0}.{1}""] = current_protocol
dissector_table:add(""{0}.{1}"", current_protocol)
";
        public const string EVENT_FIELD_DECLARATION_WITH_VALUE = @"
    local {{3}}_value = buffer(index, {0}):{1}()
    fields:add_le(event_proto_{{0}}_{{1}}.fields[{{2}}], buffer(index, {0}))
    index = index + {0}
";
        public const string EVENT_FIELD_DECLARATION_SIMPLE = @"
    fields:add_le(event_proto_{{0}}_{{1}}.fields[{{2}}], buffer(index, {0}))
    index = index + {0}
";

        public const string EVENT_FIELD_DECLARATION_UZSTRING = @"
    fields:add_le(event_proto_{0}_{1}.fields[{2}], buffer(index, (buffer(index):le_ustringz():len() + 1) * 2), tostring(buffer(index):le_ustringz()))
    index = index + (buffer(index):le_ustringz():len() + 1) * 2
";

        public const string EVENT_FIELD_DECLARATION_ANSISTRING = @"
    fields:add_le(event_proto_{0}_{1}.fields[{2}], buffer(index, (buffer(index):stringz():len() + 1)), tostring(buffer(index):stringz()))
    index = index + (buffer(index):stringz():len() + 1)
";

        public const string EVENT_FIELD_DECLARATION_WITH_LENGTH = @"
    fields:add_le(event_proto_{0}_{1}.fields[{2}], buffer(index, {3}_value))
    index = index + {3}_value
";

        public const string EVENT_FIELD_DECLARATION_SID = @"
    fields:add_le(event_proto_{0}_{1}.fields[{2}], buffer(index, 8 + buffer(index + 1, 1):le_int() * 4))
    index = index + 8 + buffer(index + 1, 1):le_int() * 4
";

        public static readonly Dictionary<Data.InType, Tuple<string, string, string>> EVENT_DATA_TYPE_CONVERT = new Dictionary<Data.InType, Tuple<string, string, string>>()
        {
            { Data.InType.Binary, new Tuple<string, string, string>("ProtoField.bytes", "base.NONE", EVENT_FIELD_DECLARATION_WITH_LENGTH) },
            { Data.InType.Int8, new Tuple<string, string, string>("ProtoField.int8", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 1, "le_int")) },
            { Data.InType.Int16, new Tuple<string, string, string>("ProtoField.int16", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 2, "le_int")) },
            { Data.InType.Int32, new Tuple<string, string, string>("ProtoField.int32", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 4, "le_int")) },
            { Data.InType.Int64, new Tuple<string, string, string>("ProtoField.int64", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_int64")) },
            { Data.InType.UInt16, new Tuple<string, string, string>("ProtoField.uint16", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 2, "le_uint")) },
            { Data.InType.UInt32, new Tuple<string, string, string>("ProtoField.uint32", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 4, "le_uint")) },
            { Data.InType.UInt64, new Tuple<string, string, string>("ProtoField.uint64", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_uint64")) },
            { Data.InType.UInt8, new Tuple<string, string, string>("ProtoField.uint8", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 1, "le_uint")) },
            { Data.InType.GUID, new Tuple<string, string, string>("ProtoField.guid", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_SIMPLE, 16)) },
            { Data.InType.UnicodeString, new Tuple<string, string, string>("ProtoField.string", "base.UNICODE", EVENT_FIELD_DECLARATION_UZSTRING) },
            { Data.InType.AnsiString, new Tuple<string, string, string>("ProtoField.string", "base.ASCII", EVENT_FIELD_DECLARATION_ANSISTRING) },
            { Data.InType.Boolean, new Tuple<string, string, string>("ProtoField.int8", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 1,"le_uint")) },
            { Data.InType.Double, new Tuple<string, string, string>("ProtoField.double", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_float")) },
            { Data.InType.HexInt32, new Tuple<string, string, string>("ProtoField.int32", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 4, "le_int")) },
            { Data.InType.HexInt64, new Tuple<string, string, string>("ProtoField.int64", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_int64")) },
            { Data.InType.FILETIME, new Tuple<string, string, string>("ProtoField.int64", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_int64")) },
            { Data.InType.Pointer, new Tuple<string, string, string>("ProtoField.int64", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 8, "le_int64")) },
            { Data.InType.SYSTEMTIME, new Tuple<string, string, string>("ProtoField.bytes", "base.NONE", string.Format(EVENT_FIELD_DECLARATION_SIMPLE, 16)) },
            { Data.InType.SID, new Tuple<string, string, string>("ProtoField.bytes", "base.NONE", EVENT_FIELD_DECLARATION_SID) },
            { Data.InType.Float, new Tuple<string, string, string>("ProtoField.float", "base.DEC", string.Format(EVENT_FIELD_DECLARATION_WITH_VALUE, 4, "le_float")) },
        };

    }

    public static class ProviderExtensions
    {
        public static string FormatProviderName(this Provider provider)
        {
            return provider.name.Replace(" ", "_");
        }
    }

	class DissectorLUA
	{

        public Manifest Manifest { get; private set; }

        private static void GenerateProvider(Provider provider, StreamWriter writer)
        {
            writer.WriteLine(string.Format(DissectorLUATemplate.PROVIDER, provider.FormatProviderName(), provider.guid));
        }

        private static void GenerateEvent(Event etwEvent, Provider provider, StreamWriter writer)
        {
            writer.WriteLine(string.Format(DissectorLUATemplate.EVENT_HEADER, provider.FormatProviderName(), etwEvent.value, etwEvent.version));
            var template = provider.templates.Where(x => x.tid == etwEvent.template).Single();
            var fields_declaration = template.datas.Select(
                x => string.Format(
                    DissectorLUATemplate.EVENT_FIELD,
                    x.name,
                    DissectorLUATemplate.EVENT_DATA_TYPE_CONVERT[x.inType].Item1,
                    provider.FormatProviderName(),
                    etwEvent.value,
                    etwEvent.version,
                    DissectorLUATemplate.EVENT_DATA_TYPE_CONVERT[x.inType].Item2
                )
            );

            writer.WriteLine("\n" + 
                string.Format(
                    DissectorLUATemplate.EVENT_PROTO_FIELD, 
                    string.Join(", ", fields_declaration)
                ) + "\n"
            );

            // build the core parser
            var result = "";
            var index = 1;

            foreach (var data in template.datas)
            {
                if(data.inType == Data.InType.Binary)
                {
                    if(data.length != null)
                    {
                        result += string.Format(DissectorLUATemplate.EVENT_DATA_TYPE_CONVERT[data.inType].Item3, etwEvent.value, etwEvent.version, index, data.length.Replace(" ", "")) + "\n";
                    }
                    else if(data.name == "hash")
                    {
                        result += string.Format(string.Format(DissectorLUATemplate.EVENT_FIELD_DECLARATION_SIMPLE, 16), etwEvent.value, etwEvent.version, index) + "\n";
                    }
                    else if(data.name == "SHA1Hash")
                    {
                        result += string.Format(string.Format(DissectorLUATemplate.EVENT_FIELD_DECLARATION_SIMPLE, 20), etwEvent.value, etwEvent.version, index) + "\n";
                    }
                    else if(data.name == "CredKeyIdentifier")
                    {
                        result += string.Format(string.Format(DissectorLUATemplate.EVENT_FIELD_DECLARATION_SIMPLE, 32), etwEvent.value, etwEvent.version, index) + "\n";
                    }
                }
                else if(data.length != null)
                {
                    result += string.Format(DissectorLUATemplate.EVENT_FIELD_DECLARATION_WITH_LENGTH, etwEvent.value, etwEvent.version, index, data.length.Replace(" ", "")) + "\n";
                }
                else
                {
                    result += string.Format(DissectorLUATemplate.EVENT_DATA_TYPE_CONVERT[data.inType].Item3, etwEvent.value, etwEvent.version, index, data.name) + "\n";
                }
                index++;
            }

            writer.WriteLine(string.Format(DissectorLUATemplate.EVENT_DECLARATION, etwEvent.value, etwEvent.version, result));
        }

        public DissectorLUA(Manifest source)
        {
            this.Manifest = source;
        }

        public void create(Stream output)
        {
            using (var s = new StreamWriter(output))
            {
                GenerateProvider(this.Manifest.instrumentation.events.provider, s);

                // delete all event with same value and version (exist in scheme)
                var eventSet = new HashSet<Event>(this.Manifest.instrumentation.events.provider.events, new EventComparer());

                foreach (var etwEvent in eventSet)
                {
                    if(etwEvent.template == null)
                    {
                        continue;
                    }
                    GenerateEvent(etwEvent, this.Manifest.instrumentation.events.provider, s);
                }
            }
        }
	}
}
