# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

# Project
project(Winshark LANGUAGES C CXX CSharp VERSION 1.1.0)

# Config
set_property(GLOBAL PROPERTY USE_FOLDERS ON)


SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /WX")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd /WX")

# Include libpcap
set(LIBRARY_NAME wpcap CACHE STRING "Library name")
set(PCAP_TYPE "etw" CACHE STRING "Packet capture type" FORCE)
add_subdirectory(libpcap)
set_property(TARGET can_set_rfmon_test PROPERTY FOLDER "libpcap")
set_property(TARGET capturetest PROPERTY FOLDER "libpcap")
set_property(TARGET filtertest PROPERTY FOLDER "libpcap")
set_property(TARGET findalldevstest PROPERTY FOLDER "libpcap")
set_property(TARGET fuzz_both PROPERTY FOLDER "libpcap")
set_property(TARGET fuzz_filter PROPERTY FOLDER "libpcap")
set_property(TARGET fuzz_pcap PROPERTY FOLDER "libpcap")
set_property(TARGET opentest PROPERTY FOLDER "libpcap")
set_property(TARGET wpcap PROPERTY FOLDER "libpcap")
set_property(TARGET wpcap_static PROPERTY FOLDER "libpcap")
set_property(TARGET reactivatetest PROPERTY FOLDER "libpcap")
set_property(TARGET rpcapd PROPERTY FOLDER "libpcap")
set_property(TARGET SerializeTarget PROPERTY FOLDER "libpcap")
set_property(TARGET testprogs PROPERTY FOLDER "libpcap")
set_property(TARGET threadsignaltest PROPERTY FOLDER "libpcap")
set_property(TARGET uninstall PROPERTY FOLDER "libpcap")

install(TARGETS wpcap DESTINATION .)

# Install dissector write by hand
add_subdirectory(dissector)

# Add tool to create new dissector from manifest based ETW
add_subdirectory(transluator)

# Summary
message(STATUS "Configuration summary")
message(STATUS "Project name                 : ${PROJECT_NAME}")
message(STATUS "Project version              : ${PROJECT_VERSION}")

# CPack part
set(CPACK_GENERATOR "WIX")
set(CPACK_WIX_UPGRADE_GUID "c64ed0aa-c54a-4590-93fb-72e152edefb7")
set(CPACK_WIX_UNINSTALL "1")
set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/install/patch.xml")
include(CPack)
