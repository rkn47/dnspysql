// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#pragma once

#include <mutex>

#include "query.hpp"

namespace dnspysql {

// Serves the Model Context Protocol over stdin/stdout (newline-delimited JSON-RPC 2.0) until EOF. Requests run one at
// a time on a worker thread, so ping and notifications/cancelled are answered while a long query runs (a cancel
// interrupts it).
int serve_mcp(Runner& runner, std::mutex& engine_mu);

}  // namespace dnspysql
