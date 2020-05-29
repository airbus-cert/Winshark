using System;
using System.Xml;
using System.Xml.Serialization;
using System.IO;
using System.Collections.Generic;

namespace Transluator
{
    [XmlType("map")]
    public class Map
    {
        [XmlAttribute]
        public string message;

        [XmlAttribute]
        public string value;
    }

    [XmlType("valueMap")]
    public class ValueMap
    {
        [XmlAttribute]
        public string name;

        [XmlElement("map")]
        public List<Map> maps;
    }

    public class Maps
    {
        [XmlElement("valueMap")]
        public List<ValueMap> valueMaps;
    }

    [XmlType("opcode")]
    public class Opcode
    {
        [XmlAttribute]
        public string name;

        [XmlAttribute]
        public string message;

        [XmlAttribute]
        public string value;
    }

    [XmlType("task")]
    public class Task
    {
        [XmlAttribute]
        public string name;

        [XmlAttribute]
        public string message;

        [XmlAttribute]
        public string value;

        public List<Opcode> opcodes;
    }

    [XmlType("event")]
    public class Event
    {
        public enum Level
        {
            [XmlEnum(Name = "win:Informational")]
            Informational,
            [XmlEnum(Name = "win:Verbose")]
            Verbose,
            [XmlEnum(Name = "win:Warning")]
            Warning,
            [XmlEnum(Name = "win:Error")]
            Error,
            [XmlEnum(Name = "win:Critical")]
            Critical,
            [XmlEnum(Name = "win:Always")]
            Always
        }

        [XmlAttribute]
        public string value;

        [XmlAttribute]
        public string symbol;

        [XmlAttribute]
        public int version;

        [XmlAttribute]
        public string task;

        [XmlAttribute]
        public Level level;

        [XmlAttribute]
        public string template;

        [XmlAttribute]
        public string keywords;

        [XmlAttribute]
        public string opcode;
    }

    public class EventComparer : IEqualityComparer<Event>
    {
        public bool Equals(Event x, Event y)
        {
            return x.value == y.value && x.version == y.version;
        }

        public int GetHashCode(Event obj)
        {
            return obj.value.GetHashCode() ^ obj.version.GetHashCode();
        }
    }


    [XmlType("data")]
    public class Data
    {
        [XmlAttribute]
        public string name;

        public enum InType
        {
            [XmlEnum(Name = "win:UnicodeString")]
            UnicodeString,
            [XmlEnum(Name = "win:AnsiString")]
            AnsiString,
            [XmlEnum(Name = "win:GUID")]
            GUID,
            [XmlEnum(Name = "win:UInt32")]
            UInt32,
            [XmlEnum(Name = "win:HexInt32")]
            HexInt32,
            [XmlEnum(Name = "win:HexInt64")]
            HexInt64,
            [XmlEnum(Name = "win:Boolean")]
            Boolean,
            [XmlEnum(Name = "win:UInt16")]
            UInt16,
            [XmlEnum(Name = "win:Binary")]
            Binary,
            [XmlEnum(Name = "win:UInt64")]
            UInt64,
            [XmlEnum(Name = "win:Double")]
            Double,
            [XmlEnum(Name = "win:UInt8")]
            UInt8,
            [XmlEnum(Name = "win:Int8")]
            Int8,
            [XmlEnum(Name = "win:Int16")]
            Int16,
            [XmlEnum(Name = "win:Int32")]
            Int32,
            [XmlEnum(Name = "win:Int64")]
            Int64,
            [XmlEnum(Name = "win:FILETIME")]
            FILETIME,
            [XmlEnum(Name = "win:Pointer")]
            Pointer,
            [XmlEnum(Name = "win:SYSTEMTIME")]
            SYSTEMTIME,
            [XmlEnum(Name = "win:SID")]
            SID,
            [XmlEnum(Name = "win:Float")]
            Float
        }

        [XmlAttribute]
        public InType inType;

        [XmlAttribute]
        public string length;

        [XmlAttribute]
        public string count;

        [XmlAttribute]
        public string map;
    }

    [XmlType("template")]
    public class Template
    {
        [XmlAttribute]
        public string tid;

        [XmlElement("data")]
        public List<Data> datas;
    }

    [XmlType("keyword")]
    public class Keyword
    {
        [XmlAttribute]
        public string name;

        [XmlAttribute]
        public string message;

        [XmlAttribute]
        public string mask;
    }

    public class Provider
    {
        [XmlAttribute]
        public string name;

        [XmlAttribute]
        public Guid guid;

        [XmlAttribute]
        public string resourceFileName;

        [XmlAttribute]
        public string messageFileName;

        [XmlAttribute]
        public string symbol;

        [XmlAttribute]
        public string source;

        public List<Keyword> keywords;

        public List<Task> tasks;

        public List<Event> events;

        public List<Template> templates;

        public List<ValueMap> maps;
    }

    public class Events
    {
        public Provider provider;
    }
    
    public class Instrumentation
    {
        public Events events;
    }

    [XmlType("string")]
    public class String
    {
        [XmlAttribute]
        public string id;

        [XmlAttribute]
        public string value;
    }

    public class Resources
    {
        [XmlAttribute]
        public string culture;

        public List<String> stringTable;
    }

    public class Localization
    {
        public Resources resources;
    }

    [XmlRootAttribute("instrumentationManifest", Namespace = "http://schemas.microsoft.com/win/2004/08/events")]
    public class Manifest
    {
        public Instrumentation instrumentation;
        public Localization localization;
    }
}
