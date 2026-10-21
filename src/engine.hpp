// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
// Native side of the engine bridge: hosts the .NET runtime in-process and
// speaks the tagged-cell wire format defined in engine/DnSpySql.Engine/Wire.cs.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace dnspysql {

struct Cell {
    enum Tag : uint8_t { Null = 0, Int = 1, Real = 2, Text = 3, Blob = 4 };
    Tag tag = Null;
    int64_t i = 0;
    double d = 0;
    std::string s;  // text or blob bytes

    static Cell null() { return {}; }
    static Cell integer(int64_t v) { Cell c; c.tag = Int; c.i = v; return c; }
    static Cell real(double v) { Cell c; c.tag = Real; c.d = v; return c; }
    static Cell text(std::string v) { Cell c; c.tag = Text; c.s = std::move(v); return c; }
    static Cell blob(std::string v) { Cell c; c.tag = Blob; c.s = std::move(v); return c; }

    std::string to_string() const;
};

// One table row as produced by the engine. `key` is the SQLite rowid.
struct NRow {
    int64_t key = 0;
    std::vector<Cell> vals;
};

struct EngineError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Engine {
public:
    // engine_dir contains DnSpySql.Engine.dll and its runtimeconfig/deps files.
    void start(const std::filesystem::path& engine_dir);

    // Creates the session; options is a JSON object (read_only, no_project, project, timeout_ms, max_rows,
    // ref_paths, sqlite_version). Must come first.
    void init(const std::string& options_json);
    std::string describe();
    int open(const std::string& path);
    // Reports a view's columns (JSON [[name, type], ...]) for the engine's catalog tables.
    void view_columns(const std::string& view, const std::string& columns_json);
    // Statement boundaries: undo grouping, timeout and cancellation in the engine.
    // Returns the statement timeout in ms (0 = none), which the host also applies to SQLite.
    int64_t begin_statement();
    // Returns the statement's notices (sidecar files written, dnSpy.xml synced), one per line; empty when none.
    std::string end_statement();
    // Cancels the running statement's managed work. Safe to call from another thread.
    void interrupt();

    // A constraint SQLite pushed down: column index, SQLite operator code (EQ 2, GT 4, LE 8, LT 16, GE 32), value.
    struct Constraint {
        int column;
        int op;
        Cell value;
    };
    // Scans are cursors read in batches, so LIMIT stops early. The engine applies every constraint itself (SQLite
    // does not re-check them). `used` is SQLite's colUsed: only those columns are computed, the others come back
    // NULL. A batch shorter than `n` means the cursor is done (and closed).
    // Opens a cursor and returns it with its first batch of up to `first` rows (a point lookup needs one call).
    int64_t scan_open(const std::string& table, uint64_t used, const std::vector<Constraint>& constraints, size_t first,
                      std::vector<NRow>& rows);
    std::vector<NRow> scan_next(int64_t cursor, size_t n);
    void scan_close(int64_t cursor);
    // Row count of a full scan, without building the rows.
    size_t count(const std::string& table);
    std::optional<NRow> get(const std::string& table, int64_t key);
    void update(const std::string& table, int64_t key, const std::string& col, const Cell& val);
    // INSERT: one value per declared column (NULL where the statement gave none); returns the new row key.
    int64_t insert(const std::string& table, const std::vector<Cell>& values);
    void remove(const std::string& table, int64_t key);
    Cell invoke(const std::string& fn, const std::vector<Cell>& args);
    // docs/SCHEMA.md text generated from the live catalog.
    std::string schema_md();
    // Paths of modules with unsaved changes, one per line.
    std::string dirty();
    // Escapes invisible, bidi and private-use characters as \uXXXX for terminal output.
    std::string visible(const std::string& text);
    // "[id] path (name, kind, target framework)" for the load line.
    std::string module_summary(int id);
    // JSON object for GET /status.
    std::string status();

private:
    // x64/arm64 have a single calling convention, matching [UnmanagedCallersOnly].
    using CallFn = int (*)(const char*, const uint8_t*, int, uint8_t**, int*);
    using FreeFn = void (*)(uint8_t*);

    std::string call(const char* op, const std::vector<Cell>& args);

    CallFn call_ = nullptr;
    FreeFn free_ = nullptr;
};

}  // namespace dnspysql
