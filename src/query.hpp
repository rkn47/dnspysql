// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
// Running SQL and rendering results (table / json / jsonl / csv / tsv).
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <xsql/database.hpp>

#include "engine.hpp"

namespace dnspysql {

struct StatementOutput {
    size_t index = 0;
    std::string sql;
    bool success = true;
    std::vector<std::string> columns;
    std::vector<std::vector<Cell>> rows;
    int64_t changes = 0;     // rows changed by INSERT/UPDATE/DELETE
    bool truncated = false;  // stopped at max_rows
    double elapsed_ms = 0;
    std::string error;
    std::string notice;      // from the engine: files written next to a save, dnSpy.xml synced (one per line)
};

struct RunOptions {
    size_t max_rows = 100000;
    bool continue_on_error = false;
};

// Must run before the database is opened: records the SQLite connection (through sqlite3_auto_extension, so
// libxsql needs no change) for the statement timeout and interrupts of pure-SQL work.
void capture_sqlite_connection();

// Runs scripts statement by statement. Around each statement it tells the engine (undo grouping, timeout,
// cancellation) and applies the engine's statement timeout to SQLite too. interrupt() may be called from any
// thread (Ctrl+C, POST /cancel, MCP notifications/cancelled).
class Runner {
public:
    Runner(xsql::Database& db, Engine& engine);
    ~Runner();

    std::vector<StatementOutput> run(const std::string& script, const RunOptions& opts = {});
    void interrupt();
    Engine& engine() { return engine_; }
    xsql::Database& db() { return db_; }

private:
    bool stop_requested() const;
    static int progress(void* self);

    xsql::Database& db_;
    Engine& engine_;
    std::atomic<bool> interrupted_{false};
    std::atomic<int64_t> deadline_ms_{0};  // steady-clock ms; 0 = none
};

enum class Format { Table, Json, Jsonl, Csv, Tsv };

// table | json | jsonl | csv | tsv (also "text" = table); throws on anything else.
Format parse_format(const std::string& name);

// One CLI/REPL/HTTP rendering of a script's results; `visible` escapes invisible characters for table output.
std::string render(Engine& engine, const std::vector<StatementOutput>& results, Format f);
// The idasql/ghidrasql JSON envelope.
nlohmann::json envelope(const std::vector<StatementOutput>& results, bool include_sql = false);

}  // namespace dnspysql
