// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <xsql/database.hpp>

#include "engine.hpp"
#include "http.hpp"
#include "mcp.hpp"
#include "query.hpp"
#include "schema.hpp"
#include "version.hpp"

namespace fs = std::filesystem;
using namespace dnspysql;

namespace {

const char* kUsage =
    "dnspysql - SQL over .NET assemblies (dnSpy's model as tables)\n"
    "\n"
    "usage: dnspysql [options] <assembly|module|exe>...\n"
    "\n"
    "  -c, --command SQL     run SQL and exit (repeatable, runs in order)\n"
    "  -f, --file PATH       run a SQL script file (repeatable, runs in order with -c)\n"
    "  -i, --interactive     start the REPL (default when no -c/-f/--http/--mcp)\n"
    "      --format FMT      table | json | jsonl | csv | tsv   (default table)\n"
    "      --http [PORT]     serve the HTTP API (default port 8081; 0 = any free port)\n"
    "      --bind ADDR       HTTP bind address (default 127.0.0.1; use 0.0.0.0 in containers)\n"
    "      --token TOKEN     require 'Authorization: Bearer TOKEN' (or X-XSQL-Token) on HTTP\n"
    "      --mcp             serve the Model Context Protocol over stdio\n"
    "      --remote URL      send -c/-f SQL to a running dnspysql HTTP server instead (uses --token, --format)\n"
    "      --ref DIR         extra directory with referenced assemblies (repeatable; e.g. .NET Framework refs on Linux)\n"
    "      --readonly        refuse every write (tables and functions)\n"
    "      --project PATH    annotation store (default: <first input>.dnspysql.json)\n"
    "      --no-project      keep annotations in memory only\n"
    "      --dnspy-xml PATH  dnSpy settings file kept in step with breakpoints/bookmarks: auto (default), off, or a path\n"
    "      --timeout MS      per-statement timeout\n"
    "      --max-rows N      row cap per statement for output (default 100000)\n"
    "      --continue        keep running statements after an error\n"
    "      --schema-md       print the schema reference (docs/SCHEMA.md) and exit\n"
    "      --engine DIR      directory holding DnSpySql.Engine.dll (default: <exe dir>/engine)\n"
    "      --version         print version and exit\n"
    "  -h, --help            this help\n"
    "\n"
    "Examples:\n"
    "  dnspysql app.dll -c \"SELECT full_name, method_count FROM types ORDER BY method_count DESC LIMIT 10\"\n"
    "  dnspysql app.dll -c \"SELECT * FROM analyze WHERE target = resolve('App.License::IsValid')\"\n"
    "  dnspysql app.dll -c \"SELECT set_body_stub(resolve('App.License::IsValid'), 1)\" -c \"SELECT save('app.patched.dll')\"\n"
    "  dnspysql app.dll -c \"SELECT bp_set(resolve('App.License::IsValid'))\" -c \"SELECT bp_export('C:/dnSpy/dnSpy.xml')\"\n"
    "  dnspysql app.dll --http 8081 --token secret\n";

const char* kReplHelp =
    ".tables [pattern]        list tables (with domain and write support)\n"
    ".schema [table]          columns of a table (pushdown/required/writable markers)\n"
    ".functions [pattern]     list SQL functions\n"
    ".mode table|json|jsonl|csv|tsv\n"
    ".modules                 loaded modules\n"
    ".open PATH               load another assembly\n"
    ".info                    binary summary\n"
    ".undo [n] / .redo [n]    undo/redo statements\n"
    ".save PATH [module]      save the current (or given) module\n"
    ".read FILE               run a SQL script\n"
    ".timeout MS              per-statement timeout\n"
    ".http start [port] | stop\n"
    ".help / .quit\n"
    "SQL statements end with ';' (multi-line input is accumulated). Ctrl+C cancels the running statement.\n";

fs::path exe_dir() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    return fs::path(std::wstring(buf, n)).parent_path();
#else
    return fs::canonical("/proc/self/exe").parent_path();
#endif
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + p.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string sql_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) out += c == '\'' ? std::string("''") : std::string(1, c);
    return out + "'";
}

// Ctrl+C: the handler only sets a flag; a watcher thread interrupts the running statement, since SQLite and the
// .NET engine must not be called from a signal handler.
std::atomic<bool> g_sigint{false};
#ifdef _WIN32
BOOL WINAPI on_ctrl(DWORD type) {
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) return FALSE;
    g_sigint = true;
    return TRUE;
}
#else
extern "C" void on_sigint(int) { g_sigint = true; }
#endif

class CtrlC {
public:
    // Ctrl+C calls `on_interrupt` (from a watcher thread) instead of ending the process.
    explicit CtrlC(std::function<void()> on_interrupt) : fn_(std::move(on_interrupt)) {
#ifdef _WIN32
        SetConsoleCtrlHandler(on_ctrl, TRUE);
#else
        std::signal(SIGINT, on_sigint);
#endif
        thread_ = std::thread([this] {
            while (!stop_) {
                if (g_sigint.exchange(false)) fn_();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        });
    }
    ~CtrlC() {
        stop_ = true;
        thread_.join();
#ifdef _WIN32
        SetConsoleCtrlHandler(on_ctrl, FALSE);
#else
        std::signal(SIGINT, SIG_DFL);
#endif
    }

private:
    std::function<void()> fn_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

struct Shell {
    Runner& runner;
    std::mutex& mu;
    Format fmt;
    RunOptions opts;
    std::unique_ptr<HttpServer> http;

    bool print(const std::string& sql, bool show = true) {
        std::lock_guard<std::mutex> lk(mu);
        auto results = runner.run(sql, opts);
        if (show) {
            auto text = render(runner.engine(), results, fmt);
            if (!text.empty()) std::cout << text << "\n" << std::flush;
        }
        for (const auto& r : results)
            if (!r.notice.empty()) std::cerr << "note: " << r.notice << "\n";
        for (const auto& r : results)
            if (!r.success) return false;
        return true;
    }

    // One dot command; false to quit.
    bool dot(const std::string& line) {
        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;
        std::string arg;
        std::getline(ss, arg);
        arg.erase(0, arg.find_first_not_of(" \t"));
        while (!arg.empty() && (arg.back() == ' ' || arg.back() == '\t')) arg.pop_back();

        if (cmd == ".quit" || cmd == ".exit" || cmd == ".q") return false;
        if (cmd == ".help") {
            std::cout << kReplHelp;
        } else if (cmd == ".tables") {
            print("SELECT table_name, domain, CASE WHEN can_update OR can_insert OR can_delete THEN 'rw' ELSE 'r' END AS access, required_filter, "
                  "description FROM dnspysql_tables" +
                  (arg.empty() ? std::string() : " WHERE table_name LIKE " + sql_quote("%" + arg + "%") + " OR domain = " + sql_quote(arg)) +
                  " ORDER BY domain, table_name");
        } else if (cmd == ".schema") {
            if (arg.empty()) {
                print("SELECT name AS view, sql FROM sqlite_schema WHERE type = 'view'");
                print("SELECT table_name, count(*) AS columns FROM dnspysql_columns GROUP BY table_name");
            } else {
                print("SELECT column_name, type, CASE WHEN writable THEN 'w' ELSE '' END AS w, pushdown, CASE WHEN required THEN 'required' ELSE '' END AS req, "
                      "CASE WHEN hidden THEN 'hidden' ELSE '' END AS hidden, description FROM dnspysql_columns WHERE table_name = " +
                      sql_quote(arg) + " ORDER BY ordinal");
            }
        } else if (cmd == ".functions") {
            print("SELECT signature, domain, CASE WHEN mutates THEN 'writes' ELSE '' END AS writes, description FROM dnspysql_functions" +
                  (arg.empty() ? std::string() : " WHERE name LIKE " + sql_quote("%" + arg + "%") + " OR domain = " + sql_quote(arg)) +
                  " GROUP BY name ORDER BY domain, name");
        } else if (cmd == ".mode") {
            try {
                fmt = parse_format(arg.empty() ? "table" : arg);
            } catch (const std::exception& e) {
                std::cout << e.what() << "\n";
            }
        } else if (cmd == ".modules") {
            print("SELECT id, name, kind, target_framework, machine, dirty, path FROM modules");
        } else if (cmd == ".info") {
            print("SELECT key, value FROM binary");
        } else if (cmd == ".open") {
            print("SELECT open(" + sql_quote(arg) + ") AS module");
        } else if (cmd == ".undo") {
            print("SELECT undo(" + std::string(arg.empty() ? "1" : arg) + ") AS undone");
        } else if (cmd == ".redo") {
            print("SELECT redo(" + std::string(arg.empty() ? "1" : arg) + ") AS redone");
        } else if (cmd == ".save") {
            std::istringstream as(arg);
            std::string path, module;
            as >> path >> module;
            if (path.empty()) std::cout << "usage: .save PATH [module]\n";
            else if (module.empty()) print("SELECT save(" + sql_quote(path) + ") AS saved");
            else print("SELECT save(" + module + ", " + sql_quote(path) + ") AS saved");
        } else if (cmd == ".read") {
            try {
                print(read_file(arg));
            } catch (const std::exception& e) {
                std::cout << "error: " << e.what() << "\n";
            }
        } else if (cmd == ".timeout") {
            print("UPDATE runtime_settings SET value = " + sql_quote(arg) + " WHERE key = 'query_timeout_ms'");
        } else if (cmd == ".http") {
            if (arg.rfind("stop", 0) == 0) {
                http.reset();
                std::cout << "http stopped\n";
            } else {
                std::string p = arg.rfind("start", 0) == 0 ? arg.substr(5) : arg;
                int port = 8081;
                try {
                    if (p.find_first_not_of(" \t") != std::string::npos) port = std::stoi(p);
                } catch (...) {
                }
                http.reset();
                http = std::make_unique<HttpServer>(runner, mu, "127.0.0.1", port, "");
                if (!http->start()) {
                    std::cout << "cannot listen on port " << port << "\n";
                    http.reset();
                }
            }
        } else {
            std::cout << "unknown command " << cmd << " (.help)\n";
        }
        return true;
    }

    void run(size_t modules) {
        std::cerr << "dnspysql " << kVersion << " - " << modules << " module(s) loaded. .help for help, .quit to exit\n";
        CtrlC ctrl([this] { runner.interrupt(); });
        std::string buffer, line;
        for (;;) {
            std::cerr << (buffer.empty() ? "dnspysql> " : "     ...> ") << std::flush;
            if (!std::getline(std::cin, line)) break;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (buffer.empty()) {
                auto first = line.find_first_not_of(" \t");
                if (first != std::string::npos && line[first] == '.') {
                    if (!dot(line.substr(first))) break;
                    continue;
                }
            }
            buffer += line + "\n";
            if (!sqlite3_complete(buffer.c_str())) continue;
            std::string sql;
            sql.swap(buffer);
            print(sql);
        }
    }
};

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    // Binary stdout: "\n" stays "\n", as on Linux (consoles still start a new line on LF).
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::vector<std::pair<bool, std::string>> commands;  // (is file, text)
    std::vector<std::string> inputs, refs;
    std::string engine_arg, format = "table", bind = "127.0.0.1", token, remote, project, dnspy_xml;
    int http_port = -1;
    bool mcp = false, interactive = false, cont = false, read_only = false, no_project = false, schema_md = false;
    long long timeout_ms = 0, max_rows = 100000;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto value = [&](const char* opt) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string(opt) + " needs a value");
            return argv[++i];
        };
        try {
            if (a == "-h" || a == "--help" || a == "/?") { std::cout << kUsage; return 0; }
            if (a == "--version") {
                std::cout << "dnspysql " << kVersion << " (sqlite " << sqlite3_libversion() << ")\n"
                          << "Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms (LICENSE, NOTICE); no warranty.\n"
                          << "Built on dnlib, dnSpyEx's decompiler and libxsql by Elias Bachaalany (https://github.com/0xeb/libxsql).\n"
                          << "See THIRD_PARTY_NOTICES.md.\n";
                return 0;
            }
            if (a == "-c" || a == "--command") commands.emplace_back(false, value("-c"));
            else if (a == "-f" || a == "--file") commands.emplace_back(true, value("-f"));
            else if (a == "-i" || a == "--interactive") interactive = true;
            else if (a == "--engine") engine_arg = value("--engine");
            else if (a == "--mcp") mcp = true;
            else if (a == "--format") { format = value("--format"); parse_format(format); }
            else if (a == "--http") {
                http_port = 8081;
                if (i + 1 < argc && std::string(argv[i + 1]).find_first_not_of("0123456789") == std::string::npos) http_port = std::stoi(argv[++i]);
            }
            else if (a == "--bind") bind = value("--bind");
            else if (a == "--token") token = value("--token");
            else if (a == "--remote") remote = value("--remote");
            else if (a == "--ref") refs.push_back(value("--ref"));
            else if (a == "--readonly") read_only = true;
            else if (a == "--project") project = value("--project");
            else if (a == "--no-project") no_project = true;
            else if (a == "--dnspy-xml") dnspy_xml = value("--dnspy-xml");
            else if (a == "--timeout") timeout_ms = std::stoll(value("--timeout"));
            else if (a == "--max-rows") max_rows = std::stoll(value("--max-rows"));
            else if (a == "--continue") cont = true;
            else if (a == "--schema-md") schema_md = true;
            else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
            else inputs.push_back(a);
        } catch (const std::exception& e) {
            std::cerr << "dnspysql: " << e.what() << "\ntry --help\n";
            return 2;
        }
    }

    if (!remote.empty()) {
        std::vector<std::string> scripts;
        try {
            for (const auto& [is_file, text] : commands) scripts.push_back(is_file ? read_file(text) : text);
        } catch (const std::exception& e) {
            std::cerr << "dnspysql: " << e.what() << "\n";
            return 1;
        }
        return run_remote(remote, token, format, scripts, cont);
    }

    Engine engine;
    try {
        engine.start(engine_arg.empty() ? exe_dir() / "engine" : fs::path(engine_arg));
        nlohmann::json opts = {
            {"sqlite_version", sqlite3_libversion()}, {"version", kVersion}, {"read_only", read_only},
            {"no_project", no_project || schema_md}, {"timeout_ms", timeout_ms}, {"max_rows", max_rows}, {"ref_paths", refs},
        };
        if (!project.empty()) opts["project"] = project;
        if (!dnspy_xml.empty()) opts["dnspy_xml"] = dnspy_xml;
        engine.init(opts.dump());
    } catch (const std::exception& e) {
        std::cerr << "dnspysql: " << e.what() << "\n";
        return 1;
    }
    if (schema_md) {
        try {
            std::cout << engine.schema_md();
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "dnspysql: " << e.what() << "\n";
            return 1;
        }
    }
    for (const auto& in : inputs) {
        try {
            int id = engine.open(in);
            if (!mcp) std::cerr << engine.module_summary(id) << "\n";
        } catch (const std::exception& e) {
            std::cerr << "dnspysql: cannot load " << in << ": " << e.what() << "\n";
            return 1;
        }
    }

    Schema schema;
    try {
        schema = Schema::parse(engine.describe());
    } catch (const std::exception& e) {
        std::cerr << "dnspysql: bad schema from engine: " << e.what() << "\n";
        return 1;
    }

    capture_sqlite_connection();
    xsql::Database db;  // opens ":memory:" itself; opening again would close the connection just captured
    if (!db.is_open()) {
        std::cerr << "dnspysql: failed to open SQLite: " << db.last_error() << "\n";
        return 1;
    }
    Registry registry(engine, schema);
    try {
        registry.install(db);
    } catch (const std::exception& e) {
        std::cerr << "dnspysql: " << e.what() << "\n";
        return 1;
    }

    Runner runner(db, engine);
    std::mutex engine_mu;
    Shell shell{runner, engine_mu, parse_format(format), {static_cast<size_t>(max_rows), cont}, nullptr};

    int rc = 0;
    for (const auto& [is_file, text] : commands) {
        std::string sql;
        try {
            sql = is_file ? read_file(text) : text;
        } catch (const std::exception& e) {
            std::cerr << "dnspysql: " << e.what() << "\n";
            return 1;
        }
        if (!shell.print(sql)) {
            rc = 1;
            if (!cont) break;
        }
    }

    if (mcp) return serve_mcp(runner, engine_mu);
    if (http_port >= 0) {
        auto server = std::make_unique<HttpServer>(runner, engine_mu, bind, http_port, token);
        if (!server->start()) {
            std::cerr << "dnspysql: cannot listen on " << bind << ":" << http_port << "\n";
            return 1;
        }
        if (interactive) {
            shell.http = std::move(server);
            shell.run(inputs.size());
            shell.http.reset();
            return rc;
        }
        CtrlC ctrl([&server] { server->stop(); });
        server->wait();
        return rc;
    }
    if (interactive || commands.empty()) shell.run(inputs.size());
    return rc;
}
