# DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
cmake_minimum_required(VERSION 3.20)
project(dnspysql VERSION 0.0.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# libnethost.lib is built against the static CRT; match it everywhere.
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# libxsql is consumed unmodified (see THIRD_PARTY_NOTICES.md).
# The thin-client part of libxsql brings its bundled HTTP library (cpp-httplib) for --http / --remote.
set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)
add_subdirectory(external/libxsql EXCLUDE_FROM_ALL)

# --- .NET hosting (nethost) ---------------------------------------------------
# nethost ships in the .NET SDK's apphost pack; pick the newest installed one.
if(WIN32)
  set(_rid win-x64)
else()
  set(_rid linux-x64)
endif()
find_program(DOTNET_EXE dotnet
  # the per-user installs the runtime host finds too (dotnet-install.ps1, Visual Studio's per-user SDK)
  HINTS "$ENV{DOTNET_ROOT}" "$ENV{ProgramFiles}/dotnet" "$ENV{HOME}/.dotnet" "$ENV{USERPROFILE}/.dotnet"
        "$ENV{LOCALAPPDATA}/Microsoft/dotnet" /usr/share/dotnet /usr/lib/dotnet
  REQUIRED)
get_filename_component(_dotnet_root "${DOTNET_EXE}" DIRECTORY)
# Prefer the portable RID; distro-packaged SDKs (e.g. Ubuntu's dotnet-sdk-8.0) ship the pack
# under a distro RID such as ubuntu.24.04-x64 instead.
set(_nethost_headers "")
foreach(_pack_glob "Microsoft.NETCore.App.Host.${_rid}" "Microsoft.NETCore.App.Host.*")
  file(GLOB _found "${_dotnet_root}/packs/${_pack_glob}/*/runtimes/*/native/nethost.h")
  list(SORT _found COMPARE NATURAL ORDER DESCENDING)
  list(APPEND _nethost_headers ${_found})
endforeach()
if(NOT _nethost_headers)
  message(FATAL_ERROR "nethost not found under ${_dotnet_root}/packs (install the .NET SDK)")
endif()
list(GET _nethost_headers 0 _nethost_header)
get_filename_component(NETHOST_DIR "${_nethost_header}" DIRECTORY)
message(STATUS "nethost: ${NETHOST_DIR}")

add_executable(dnspysql
  src/main.cpp
  src/engine.cpp
  src/schema.cpp
  src/query.cpp
  src/mcp.cpp
  src/http.cpp
)
target_include_directories(dnspysql PRIVATE src "${NETHOST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(dnspysql PRIVATE NETHOST_USE_AS_STATIC DNSPYSQL_VERSION="${PROJECT_VERSION}")

# The commit the binary is built from, for --version: regenerated on every build (a configure-time value would go
# stale after the next commit), rewritten only when it changes.
add_custom_target(dnspysql_build_info
  COMMAND "${CMAKE_COMMAND}" -DSRC=${CMAKE_CURRENT_SOURCE_DIR} -DOUT=${CMAKE_CURRENT_BINARY_DIR}/generated/build_info.hpp
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_info.cmake"
  BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/generated/build_info.hpp"
  VERBATIM)
add_dependencies(dnspysql dnspysql_build_info)
if(WIN32)
  target_link_libraries(dnspysql PRIVATE xsql::xsql "${NETHOST_DIR}/libnethost.lib")
  target_compile_definitions(dnspysql PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
  target_compile_options(dnspysql PRIVATE /utf-8 /W4 /permissive-)
  target_sources(dnspysql PRIVATE src/dnspysql.manifest)
else()
  target_link_libraries(dnspysql PRIVATE xsql::xsql "${NETHOST_DIR}/libnethost.a" ${CMAKE_DL_LIBS})
endif()

# --- managed engine -----------------------------------------------------------
set(ENGINE_PROJECT "${CMAKE_CURRENT_SOURCE_DIR}/engine/DnSpySql.Engine/DnSpySql.Engine.csproj")
file(GLOB_RECURSE ENGINE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/engine/DnSpySql.Engine/*.cs"
  "${CMAKE_CURRENT_SOURCE_DIR}/engine/DnSpySql.Engine/Guides/*.md")
list(FILTER ENGINE_SOURCES EXCLUDE REGEX "/(obj|bin)/")
# The engine is compiled ahead of time (ReadyToRun) for the build platform: every query starts a process, and JIT
# compiling the table and function registrations is most of the start-up time. Turn it off for offline builds
# (it downloads the crossgen compiler from NuGet).
option(DNSPYSQL_READY_TO_RUN "Publish the managed engine as ReadyToRun" ON)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(_rid_arch arm64)
else()
  set(_rid_arch x64)
endif()
if(WIN32)
  set(ENGINE_RID "win-${_rid_arch}")
elseif(APPLE)
  set(ENGINE_RID "osx-${_rid_arch}")
else()
  set(ENGINE_RID "linux-${_rid_arch}")
endif()
if(DNSPYSQL_READY_TO_RUN)
  set(ENGINE_PUBLISH_FLAGS -r "${ENGINE_RID}" --self-contained false -p:PublishReadyToRun=true)
else()
  set(ENGINE_PUBLISH_FLAGS)
endif()
# The engine links the vendored dnSpyEx decompiler (engine/vendor); rebuild when
# those projects change. Their sources live in the submodule and are not globbed.
file(GLOB VENDOR_PROJECTS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/engine/vendor/*/*.csproj"
  "${CMAKE_CURRENT_SOURCE_DIR}/engine/vendor/*/*.cs")
set(ENGINE_OUT "$<TARGET_FILE_DIR:dnspysql>/engine")
add_custom_target(dnspysql_engine ALL
  COMMAND "${DOTNET_EXE}" publish "${ENGINE_PROJECT}" -c Release --nologo -v q ${ENGINE_PUBLISH_FLAGS} -o "${ENGINE_OUT}"
  DEPENDS ${ENGINE_SOURCES} ${VENDOR_PROJECTS} "${ENGINE_PROJECT}"
  COMMENT "Publishing DnSpySql.Engine"
  VERBATIM)
add_dependencies(dnspysql dnspysql_engine)
