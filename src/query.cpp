// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include "query.hpp"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <sstream>
#include <stdexcept>

#include <sqlite3.h>
#include <xsql/cli/table_printer.hpp>
#include <xsql/interruption.hpp>
#include <xsql/script.hpp>

namespace dnspysql {

namespace {

constexpr int kSqliteInteger = 1, kSqliteFloat = 2, kSqliteBlob = 4, kSqliteNull = 5;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

Cell read_cell(const xsql::Statement& st, int col) {
    switch (st.column_type(col)) {
        case kSqliteNull: return Cell::null();
        case kSqliteInteger: return Cell::integer(st.int64_value(col));
        case kSqliteFloat: return Cell::real(st.double_value(col));
        case kSqliteBlob: {
            auto b = st.blob(col);
            return Cell::blob(std::string(b.begin(), b.end()));
        }
        default: return Cell::text(st.text(col));
    }
}

std::string hex_bytes(const std::string& s, size_t max = std::string::npos) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    const size_t n = std::min(s.size(), max);
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        auto c = static_cast<unsigned char>(s[i]);
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 15]);
    }
    return out;
}

// Shortest round-trip text of a double, like .NET's "R".
std::string real_text(double d) {
    char buf[64];
    for (int prec = 15; prec <= 17; prec++) {
        std::snprintf(buf, sizeof buf, "%.*g", prec, d);
        if (std::strtod(buf, nullptr) == d) break;
    }
    return buf;
}

// Cell text: NULL, x'..' blobs (64 bytes shown), round-trip reals; cut at max characters.
std::string cell_text(const Cell& c, size_t max = std::string::npos) {
    std::string s;
    switch (c.tag) {
        case Cell::Null: s = "NULL"; break;
        case Cell::Blob:
            s = c.s.size() <= 64 ? "x'" + hex_bytes(c.s) + "'"
                                 : "x'" + hex_bytes(c.s, 64) + "...' (" + std::to_string(c.s.size()) + " bytes)";
            break;
        case Cell::Real: s = real_text(c.d); break;
        default: s = c.to_string(); break;
    }
    if (s.size() > max) s = max <= 3 ? s.substr(0, max) : s.substr(0, max - 3) + "...";
    return s;
}

bool plain_ascii(const std::string& s) {
    for (unsigned char ch : s)
        if (!(ch >= 0x20 && ch < 0x7F) && ch != '\n' && ch != '\t') return false;
    return true;
}

std::string visible(Engine& eng, const std::string& s) {
    if (plain_ascii(s)) return s;
    try {
        return eng.visible(s);
    } catch (...) {
        return s;
    }
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    for (size_t p = 0; (p = s.find(from, p)) != std::string::npos; p += to.size()) s.replace(p, from.size(), to);
    return s;
}

std::string render_table(Engine& eng, const StatementOutput& r) {
    if (!r.success) return "error: " + r.error;
    if (r.columns.empty()) return r.changes > 0 ? "(" + std::to_string(r.changes) + " row(s) changed)" : "ok";
    // A single wide text cell (decompiled code...) prints as is, apart from invisible characters.
    if (r.columns.size() == 1 && r.rows.size() == 1 && r.rows[0][0].tag == Cell::Text &&
        r.rows[0][0].s.find('\n') != std::string::npos) {
        auto v = visible(eng, replace_all(r.rows[0][0].s, "\r", ""));
        while (!v.empty() && (v.back() == '\n' || v.back() == ' ' || v.back() == '\t')) v.pop_back();
        return v;
    }
    std::vector<std::string> cols;
    for (const auto& c : r.columns) cols.push_back(visible(eng, c));
    std::vector<std::vector<std::string>> rows;
    rows.reserve(r.rows.size());
    for (const auto& row : r.rows) {
        std::vector<std::string> cells;
        for (const auto& c : row) {
            auto s = replace_all(replace_all(replace_all(cell_text(c, 200), "\r", ""), "\n", "\\n"), "\t", " ");
            cells.push_back(visible(eng, s));
        }
        rows.push_back(std::move(cells));
    }
    std::string out = xsql::cli::print_table(cols, rows);
    while (!out.empty() && out.back() == '\n') out.pop_back();
    out += "\n(" + std::to_string(r.rows.size()) + (r.rows.size() == 1 ? " row" : " rows") + (r.truncated ? ", truncated" : "") + ")";
    return out;
}

std::string render_delimited(const StatementOutput& r, char sep) {
    if (!r.success) return "error: " + r.error;
    auto q = [sep](const std::string& s) {
        if (sep == ',' && s.find_first_of(",\"\n") != std::string::npos) return "\"" + replace_all(s, "\"", "\"\"") + "\"";
        return replace_all(replace_all(s, "\t", " "), "\n", "\\n");
    };
    std::string out;
    for (size_t c = 0; c < r.columns.size(); c++) out += (c ? std::string(1, sep) : "") + q(r.columns[c]);
    out += "\n";
    for (const auto& row : r.rows) {
        for (size_t c = 0; c < row.size(); c++) out += (c ? std::string(1, sep) : "") + (row[c].tag == Cell::Null ? "" : q(cell_text(row[c])));
        out += "\n";
    }
    while (!out.empty() && (out.back() == '\n' || out.back() == ' ')) out.pop_back();
    return out;
}

nlohmann::json json_value(const Cell& c) {
    switch (c.tag) {
        case Cell::Null: return nullptr;
        case Cell::Int: return c.i;
        case Cell::Real: return std::isfinite(c.d) ? nlohmann::json(c.d) : nlohmann::json(real_text(c.d));
        case Cell::Blob: return hex_bytes(c.s);
        default: return c.s;
    }
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) out += (i ? sep : "") + parts[i];
    return out;
}

// The connection libxsql opened (see capture_sqlite_connection). The latest one wins: Database::open() closes the
// connection it replaces, so keeping the first would leave a dangling pointer.
std::atomic<sqlite3*> g_connection{nullptr};

extern "C" int record_connection(sqlite3* db, char**, const sqlite3_api_routines*) {
    g_connection = db;
    return SQLITE_OK;
}

}  // namespace

void capture_sqlite_connection() { sqlite3_auto_extension(reinterpret_cast<void (*)()>(&record_connection)); }

// SQLite's progress handler stops pure-SQL work (a runaway recursive CTE, a huge sort) on interrupt or timeout;
// libxsql's interrupt checker covers its table loops, and the engine its own work.
Runner::Runner(xsql::Database& db, Engine& engine) : db_(db), engine_(engine) {
    if (sqlite3* c = g_connection.load()) sqlite3_progress_handler(c, 10000, &Runner::progress, this);
}

Runner::~Runner() {
    if (sqlite3* c = g_connection.load()) sqlite3_progress_handler(c, 0, nullptr, nullptr);
}

int Runner::progress(void* self) { return static_cast<Runner*>(self)->stop_requested() ? 1 : 0; }

bool Runner::stop_requested() const {
    const int64_t deadline = deadline_ms_.load();
    return interrupted_.load() || (deadline > 0 && now_ms() > deadline);
}

void Runner::interrupt() {
    interrupted_ = true;
    if (sqlite3* c = g_connection.load()) sqlite3_interrupt(c);
    try {
        engine_.interrupt();
    } catch (...) {
    }
}

std::vector<StatementOutput> Runner::run(const std::string& script, const RunOptions& opts) {
    std::vector<StatementOutput> out;
    std::vector<std::string> statements;
    std::string error;
    if (!xsql::collect_statements(script, statements, error)) {
        StatementOutput r;
        r.sql = script;
        r.success = false;
        r.error = error;
        out.push_back(std::move(r));
        return out;
    }
    // libxsql's table loops poll this between rows; the engine stops its own work (scans, the decompiler) through
    // the statement's cancellation, which interrupt() and the timeout trigger too.
    xsql::ScopedInterruptChecker checker([this] { return stop_requested(); });

    for (size_t i = 0; i < statements.size(); i++) {
        StatementOutput r;
        r.index = i;
        r.sql = statements[i];
        const auto started = std::chrono::steady_clock::now();
        interrupted_ = false;
        try {
            const int64_t timeout = engine_.begin_statement();
            deadline_ms_ = timeout > 0 ? now_ms() + timeout : 0;
        } catch (const std::exception& e) {
            r.success = false;
            r.error = e.what();
        }
        if (r.success) {
            auto st = db_.prepare_statement(r.sql);
            if (!st.valid()) {
                r.success = false;
                r.error = !st.error().empty() ? st.error() : !db_.last_error().empty() ? db_.last_error() : "failed to prepare statement";
            } else {
                const int ncols = st.column_count();
                for (int c = 0; c < ncols; c++) r.columns.push_back(st.column_name(c));
                for (;;) {
                    auto step = st.step();
                    if (step == xsql::StepResult::row) {
                        if (opts.max_rows && r.rows.size() >= opts.max_rows) {
                            r.truncated = true;
                            break;
                        }
                        std::vector<Cell> row;
                        row.reserve(static_cast<size_t>(ncols));
                        for (int c = 0; c < ncols; c++) row.push_back(read_cell(st, c));
                        r.rows.push_back(std::move(row));
                    } else if (step == xsql::StepResult::done) {
                        break;
                    } else {
                        r.success = false;
                        r.error = !st.error().empty() ? st.error() : !db_.last_error().empty() ? db_.last_error() : "statement failed";
                        if (stop_requested()) r.error = "interrupted (timeout or cancel)";
                        break;
                    }
                }
                if (ncols == 0 && r.success) r.changes = db_.changes();
            }
        }
        try {
            r.notice = engine_.end_statement();
        } catch (...) {
        }
        deadline_ms_ = 0;
        r.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
        const bool failed = !r.success;
        out.push_back(std::move(r));
        if (failed && !opts.continue_on_error) break;
    }
    return out;
}

Format parse_format(const std::string& name) {
    if (name == "table" || name == "text") return Format::Table;
    if (name == "json") return Format::Json;
    if (name == "jsonl") return Format::Jsonl;
    if (name == "csv") return Format::Csv;
    if (name == "tsv") return Format::Tsv;
    throw std::runtime_error("unknown format '" + name + "' (table | json | jsonl | csv | tsv)");
}

nlohmann::json envelope(const std::vector<StatementOutput>& results, bool include_sql) {
    nlohmann::json arr = nlohmann::json::array();
    size_t total_rows = 0;
    double total_ms = 0;
    nlohmann::json first_error = nullptr;
    for (const auto& r : results) {
        nlohmann::json rows = nlohmann::json::array();
        for (const auto& row : r.rows) {
            nlohmann::json jr = nlohmann::json::array();
            for (const auto& c : row) jr.push_back(json_value(c));
            rows.push_back(std::move(jr));
        }
        nlohmann::json o = {
            {"statement_index", r.index},
            {"success", r.success},
            {"columns", r.columns},
            {"rows", std::move(rows)},
            {"row_count", r.rows.size()},
            {"changes", r.changes},
            {"truncated", r.truncated},
            {"elapsed_ms", std::round(r.elapsed_ms * 1000) / 1000},
            {"error", r.success ? nlohmann::json(nullptr) : nlohmann::json(r.error)},
        };
        if (include_sql) o["sql"] = r.sql;
        if (!r.notice.empty()) o["notice"] = r.notice;
        arr.push_back(std::move(o));
        total_rows += r.rows.size();
        total_ms += r.elapsed_ms;
        if (!r.success && first_error.is_null()) first_error = r.index;
    }
    return {
        {"success", first_error.is_null()},
        {"statement_count", results.size()},
        {"results", std::move(arr)},
        {"row_count_total", total_rows},
        {"elapsed_ms_total", std::round(total_ms * 1000) / 1000},
        {"first_error_index", first_error},
    };
}

std::string render(Engine& engine, const std::vector<StatementOutput>& results, Format f) {
    std::vector<std::string> parts;
    switch (f) {
        case Format::Json:
            return envelope(results).dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
        case Format::Jsonl:
            for (const auto& r : results) {
                if (!r.success) {
                    parts.push_back(nlohmann::json{{"error", r.error}}.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
                    continue;
                }
                for (const auto& row : r.rows) {
                    nlohmann::json o = nlohmann::json::object();
                    for (size_t c = 0; c < row.size() && c < r.columns.size(); c++) o[r.columns[c]] = json_value(row[c]);
                    parts.push_back(o.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
                }
            }
            return join(parts, "\n");
        case Format::Csv:
        case Format::Tsv:
            for (const auto& r : results) parts.push_back(render_delimited(r, f == Format::Csv ? ',' : '\t'));
            return join(parts, "\n\n");
        default:
            for (const auto& r : results) parts.push_back(render_table(engine, r));
            return join(parts, "\n\n");
    }
}

}  // namespace dnspysql
