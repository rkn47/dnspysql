// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#pragma once

#include "build_info.hpp"

#ifndef DNSPYSQL_VERSION
#define DNSPYSQL_VERSION "0.0.1"
#endif

namespace dnspysql {
// The release version (CMake's project version): docs/SCHEMA.md and the MCP handshake print it.
inline constexpr const char* kVersion = DNSPYSQL_VERSION;
// The commit the binary is built from (git describe, "-dirty" with uncommitted changes), so a stale build shows.
inline constexpr const char* kCommit = DNSPYSQL_COMMIT;
}
