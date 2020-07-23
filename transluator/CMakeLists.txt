set(TRANSLUATOR_SRC
	src/DissectorLua.cs
	src/DissectorPython.cs
	src/Manifest.cs
	src/Transluator.cs
)

add_executable(Transluator ${TRANSLUATOR_SRC})
set_property(TARGET Transluator PROPERTY VS_DOTNET_TARGET_FRAMEWORK_VERSION "v4.5")
set_property(TARGET Transluator PROPERTY VS_DOTNET_REFERENCES
	"System"
	"System.Xml"
	"System.Runtime"
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/Microsoft.Diagnostics.Tracing.TraceEvent.dll"
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/Microsoft.Diagnostics.FastSerialization.dll"
)

install(TARGETS Transluator DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/Microsoft.Diagnostics.Tracing.TraceEvent.dll" DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/Microsoft.Diagnostics.FastSerialization.dll" DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/Dia2Lib.dll" DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/OSExtensions.dll" DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Microsoft.Diagnostics.Tracing.TraceEvent.2.0.36/lib/net45/TraceReloggerLib.dll" DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/scripts/WinsharkUpdate.bat" DESTINATION .)