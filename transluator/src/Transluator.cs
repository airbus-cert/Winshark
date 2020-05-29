using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Xml.Serialization;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Linq;

namespace Transluator
{
    /// <summary>
    /// This the main class of transluator
    /// </summary>
	static class Transluator
	{
        static void PrintUsage()
        {
            Console.WriteLine("Welcome Transluator");
            Console.WriteLine("\tCreate dissector for one provider");
            Console.WriteLine("\ttransluator.exe PROVIDER_NAME OUTPUT_FILE_PATH");
            Console.WriteLine("\tEx : Transluator.exe Microsoft-Windows-Sysmon c:\\temp\\Microsoft-Windows-Sysmon.lua");
            Console.WriteLine("");
            Console.WriteLine("\tCreate dissectors for all providers published on local machine");
            Console.WriteLine("\ttransluator.exe OUTPUT_FOLDER");
            Console.WriteLine("\tEx : Transluator.exe ");
        }

        /// <summary>
        /// Create dissector for one provider
        /// </summary>
        /// <param name="providerName">Name of provider</param>
        /// <param name="outputPath">Path to putput file</param>
        static void CreateDissectorFromProvider(string providerName, string outputPath)
        {
            try
            {
                var xml = RegisteredTraceEventParser.GetManifestForRegisteredProvider(providerName);
                XmlSerializer serializer = new XmlSerializer(typeof(Manifest));

                using (TextReader reader = new StringReader(xml))
                {
                    Manifest manifest = (Manifest)serializer.Deserialize(reader);
                    using (var stream = new FileStream(outputPath, FileMode.Create))
                    {
                        new DissectorLUA(manifest).create(stream);
                    }
                }
            }
            catch (System.ApplicationException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (System.InvalidOperationException)
            {
                // sometimes XML generate by RegisteredTraceEventParser can't be parsed by the microsoft parser...
            }
        }

        /// <summary>
        /// Main function (entry point) 
        /// </summary>
        /// <param name="args">Provider Name as first parameter, Output file as second parameter</param>
        static int Main(string[] args)
		{
            if(args.Length == 1)
            {
                foreach (var providerName in TraceEventProviders.GetPublishedProviders().Select(x => TraceEventProviders.GetProviderName(x)))
                {
                    Console.WriteLine("Create dissector for provider " + providerName);
                    if(providerName == "TPM")
                    {
                        continue;
                    }

                    // Ignore this provider during install
                    // because we made it by hand to handle
                    // upper layer
                    if(providerName == "Microsoft-Windows-NDIS-PacketCapture")
                    {
                        continue;
                    }

                    if(System.Environment.OSVersion.Version.Major == 6 && System.Environment.OSVersion.Version.Minor == 1)
                    {
                        if (providerName == "Microsoft-Windows-UIAutomationCore")
                        {
                            Console.WriteLine("Ignore provider " + providerName + " on Windows 7");
                            continue;
                        }
                    }
                    Directory.CreateDirectory(args[0]);
                    CreateDissectorFromProvider(providerName, Path.Combine(args[0], providerName.Replace("-", "_").Replace(" ", "_") + ".lua"));
                }
            }
            else if (args.Length == 2)
            {
                CreateDissectorFromProvider(args[0], args[1]);
                return 0;
            }
            else
            {
                PrintUsage();
            }

            return 0;
        }
	}
}
