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
    static class DissectorPythonTemplate
    {
        public const string PROVIDER = @"# -*- coding: utf-8 -*-
""""""
{0}
GUID : {1}
""""""
from construct import Int8sl, Int8ul, Int16ul, Int16sl, Int32sl, Int32ul, Int64sl, Int64ul, Bytes, Double, Float32l, Struct
from etl.utils import WString, CString, SystemTime, Guid
from etl.dtyp import Sid
from etl.parsers.etw.core import Etw, declare, guid
";

        public const string EVENT_TEMPLATE = @"
@declare(guid=guid(""{0}""), event_id={1}, version={2})
class {3}_{1}_{2}(Etw):
    pattern = Struct(
{4}
    )
";
        public const string EVENT_FIELD = @"        ""{0}"" / {1}";
        public const string EVENT_FIELD_WITH_LENTH = @"        ""{0}"" / Bytes(lambda this: this.{1})";
        public const string EVENT_FIELD_STATIC_LENGTH = @"        ""{0}"" / Bytes({1})";

        public static readonly Dictionary<Data.InType, string> EVENT_DATA_TYPE_CONVERT = new Dictionary<Data.InType, string>()
        {
            { Data.InType.Binary, "Bytes" },
            { Data.InType.Int8, "Int8sl" },
            { Data.InType.Int16, "Int16sl" },
            { Data.InType.Int32, "Int32sl" },
            { Data.InType.Int64, "Int64sl" },
            { Data.InType.UInt16, "Int16ul" },
            { Data.InType.UInt32, "Int32ul" },
            { Data.InType.UInt64, "Int64ul" },
            { Data.InType.UInt8, "Int8ul" },
            { Data.InType.GUID, "Guid" },
            { Data.InType.UnicodeString, "WString" },
            { Data.InType.AnsiString, "CString" },
            { Data.InType.Boolean, "Int8ul" },
            { Data.InType.Double, "Double" },
            { Data.InType.HexInt32, "Int32ul" },
            { Data.InType.HexInt64, "Int64ul" },
            { Data.InType.FILETIME, "Int64ul" },
            { Data.InType.Pointer, "Int64ul" },
            { Data.InType.SYSTEMTIME, "SystemTime" },
            { Data.InType.SID, "Sid" },
            { Data.InType.Float, "Float32l" },
        };

    }


	class DissectorPython
	{

        public Manifest Manifest { get; private set; }

        private static void GenerateProvider(Provider provider, StreamWriter writer)
        {
            writer.WriteLine(string.Format(DissectorPythonTemplate.PROVIDER, provider.name, provider.guid));
        }

        private static void GenerateEvent(Event etwEvent, Provider provider, StreamWriter writer)
        {
            Console.WriteLine("{0}_{1}_{2}", provider.name.Replace("-", "_").Replace(" ", "_"), etwEvent.value, etwEvent.version);
            var template = provider.templates.Where(x => x.tid == etwEvent.template).Single();
            var fields_declaration = new List<string>();


            foreach (var data in template.datas)
            {
                if (data.inType == Data.InType.Binary)
                {
                    if (data.length != null)
                    {
                        fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD_WITH_LENTH, data.name, data.length.Replace(" ", "")));
                    }
                    else if (data.name == "hash")
                    {
                        fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD_STATIC_LENGTH, data.name, 16));
                    }
                    else if (data.name == "SHA1Hash")
                    {
                        fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD_STATIC_LENGTH, data.name, 20));
                    }
                    else if (data.name == "CredKeyIdentifier")
                    {
                        fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD_STATIC_LENGTH, data.name, 32));
                    }
                }
                else if (data.length != null)
                {
                    fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD_WITH_LENTH, data.name, data.length.Replace(" ", "")));
                }
                else
                {
                    fields_declaration.Add(string.Format(DissectorPythonTemplate.EVENT_FIELD, data.name, DissectorPythonTemplate.EVENT_DATA_TYPE_CONVERT[data.inType]));
                }
            }

            writer.WriteLine(
                string.Format(
                    DissectorPythonTemplate.EVENT_TEMPLATE, provider.guid, etwEvent.value, etwEvent.version, provider.name.Replace("-", "_").Replace(" ", "_"),
                    string.Join(",\n", fields_declaration)
                )
            );
        }

        public DissectorPython(Manifest source)
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
