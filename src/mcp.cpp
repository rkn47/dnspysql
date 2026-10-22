// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include "mcp.hpp"

#include <condition_variable>
#include <deque>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "version.hpp"

namespace dnspysql {

namespace {

using json = nlohmann::json;

const char* kQueryDoc =
    "Run SQL (SQLite dialect) against the loaded .NET assemblies. How-to guides for each workflow: the dnspysql_guide tool "
    "(or SELECT text FROM dnspysql_guides WHERE topic = 'basics'; topics basics, explore, triage, unpack, dnspy); read basics first. "
    "Tables mirror dnSpy: modules, types, methods, fields, params, "
    "properties, events, custom_attributes, typerefs, memberrefs, user_strings, resources, resource_elements, il, locals, "
    "exception_handlers, blocks, cfg_edges, xrefs, call_edges, callers, callees, string_refs, analyze (TVF), pseudocode, "
    "pseudocode_lines, pseudocode_refs, baml, search (TVF), jump_entities, pe_*, md_*, file_bytes, byte_search, method_bodies, heap_entries, "
    "file_map, resource_images, api_docs, protections, string_decryptors, pdb_*, comments, bookmarks, tags, kv, breakpoints, module_breakpoints, exception_settings, "
    "dnspy_debugger_settings, dnspy_watch, dnspy_documents, dnspy_tabs. Entities are keyed by `handle` (module<<32 | metadata token). "
    "Discover with: SELECT * FROM dnspysql_tables; SELECT * FROM dnspysql_columns WHERE table_name='...'; SELECT * FROM dnspysql_functions. "
    "Tables marked required_filter need that WHERE clause (e.g. pseudocode WHERE handle = ...). "
    "Decompilation uses dnSpy's own engine (decompile(handle), pseudocode). "
    "Data helpers for decoding configs/payloads: REGEXP, regexp_extract, base64_decode, text_decode(blob,'utf-16le'), xor, concat_bytes (|| makes text of blobs), decompress, "
    "decrypt(data, 'aes'|'des'|'3des'|'rc2'|'rc4', key, iv, mode, padding) (try_decrypt: NULL instead of an error, for trying a key "
    "over many values), pbkdf2, sha256, entropy. "
    "Triage: field_inits (constants stored by constructors: the config), capabilities (injection, persistence, download/execute, ... "
    "at the call; bp_set(method, offset) breaks there), iocs (URLs, IPs, domains, webhooks, tokens, wallets, mutex names, also inside base64 "
    "literals, decrypted strings and text resources), embedded_pes (PE files in the file bytes and resources, also compressed: "
    "SELECT open_bytes(data) FROM embedded_pes WHERE is_dotnet opens each next stage, one module per payload), decryptor_calls (each decryptor call with its literal arguments and its plaintext, computed by interpreting the "
    "decryptor's IL: the sample never runs; emulation says why when it cannot; SELECT inline_strings() puts the plaintexts into the code as ldstr, "
    "undoable, so decompile() and a saved copy show them), emulate(method, args...) for any static method; "
    "text_iocs WHERE text = ... finds indicators in any text, split_text cuts delimited configs, int_at(blob, offset, size) reads "
    "integers from containers. "
    "When protections reports anti-tamper (method bodies encrypted until runtime), SELECT untamper() decrypts them statically "
    "and returns a new module id to analyze instead (modules.origin = 'untamper', derived_from = the original). It has every name "
    "of the original: follow handles, or use_module(id) first, since resolve() searches the current module first. "
    "Triage a sample with SELECT name, kind, confidence, evidence FROM protections (protector, decoy markers, anti-debug/anti-VM, "
    "anti-tamper, string encryption, control flow, proxy calls, encrypted resources) and string_decryptors (ranked candidates; "
    "breakpoints on one show plaintext in dnSpy). "
    "SELECT value FROM binary WHERE key='anomalies' lists packer/protector hints (overlay, wiped headers, anti-tamper); method_bodies "
    "(invalid headers, IL that does not decode), file_map (gaps and their entropy) and resource_images + image_pixels(data, 'rgb') "
    "(payloads hidden in bitmaps) show them in detail. pseudocode_refs WHERE handle = ... maps names in decompiled code to handles "
    "and gives the decompiled variable names to use in breakpoint conditions; api_docs WHERE member = ... explains framework calls. "
    "Writes (UPDATE/INSERT/DELETE, set_body_stub, compile_method, edit_type, il_*, ...) are journaled: undo(n)/redo(n). "
    "For an analysis-only task, SELECT set_setting('read_only', 1) first: every write is then refused for the rest of the "
    "session (it cannot be switched off). "
    "Load a sample with SELECT open('path'); it is only parsed, never run. A payload decoded with the data helpers loads as a module "
    "of its own with SELECT open_bytes(blob, 'name') (e.g. open_bytes(decompress(data)) on a resource). "
    "Memory is only released by SELECT close(id), which takes a module and every stage that came out of it out of the session: "
    "with several samples, close each one when you are done with it. "
    "Annotate for dnSpy: set_comment(handle, [il_offset,] text), tag(handle, tag), INSERT INTO bookmarks (handle, offset, name, "
    "category, comment), and rename obfuscated names with UPDATE types/methods/fields/params SET name = ... (rename parameters "
    "and methods before their type: resolve() takes current names and returns NULL for unknown ones). "
    "save('path') writes the annotated assembly plus <path minus extension>.xml (comments and tags as XML documentation, which "
    "dnSpyEx shows as /// comments) and <path>.dnspysql.json; keep the original sample and save to a new path. "
    "Breakpoints (bp_set, bp_set_decompiled, bp_trace, break_on_exception), bookmarks and exception settings are merged into "
    "dnSpy's settings file (dnSpy.xml) after each statement that changes them, naming the last saved copy of the module; "
    "a 'note:' after a result reports it. dnSpy reads dnSpy.xml at startup and overwrites it on exit: when the note says "
    "dnSpy is running, ask the user to close it, then SELECT dnspy_sync(). export_project(dir) writes a VS solution.";

// Protocol revisions this server speaks, newest first (initialize negotiates one of them).
const char* kProtocolVersions[] = {"2025-06-18", "2025-03-26", "2024-11-05"};

json result(const json& id, json r) { return {{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(r)}}; }
json error(const json& id, int code, const std::string& msg) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", msg}}}};
}

json tool(const std::string& name, const std::string& desc, json props, std::vector<std::string> required = {}) {
    return {{"name", name}, {"description", desc},
            {"inputSchema", {{"type", "object"}, {"properties", std::move(props)}, {"required", required}}}};
}

// Lenient argument readers: clients (and models) send "10" for 10 and "true" for true.
std::optional<long long> as_int(const json& args, const char* k) {
    if (!args.contains(k) || args[k].is_null()) return std::nullopt;
    const auto& v = args[k];
    if (v.is_number_integer()) return v.get<long long>();
    if (v.is_number()) return static_cast<long long>(v.get<double>());
    if (v.is_string()) return std::stoll(v.get<std::string>());
    throw std::runtime_error(std::string("'") + k + "' must be an integer");
}

std::optional<bool> as_bool(const json& args, const char* k) {
    if (!args.contains(k) || args[k].is_null()) return std::nullopt;
    const auto& v = args[k];
    if (v.is_boolean()) return v.get<bool>();
    if (v.is_number()) return v.get<double>() != 0;
    if (v.is_string()) {
        auto s = v.get<std::string>();
        if (s == "true" || s == "1" || s == "yes") return true;
        if (s == "false" || s == "0" || s == "no") return false;
    }
    throw std::runtime_error(std::string("'") + k + "' must be a boolean");
}

class Server {
public:
    Server(Runner& runner, std::mutex& mu) : runner_(runner), mu_(mu) {}

    int run() {
        std::thread worker([this] { work(); });
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.size() >= 3 && line.compare(0, 3, "\xEF\xBB\xBF") == 0) line.erase(0, 3);
            if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
            json msg;
            try {
                msg = json::parse(line);
            } catch (const std::exception& e) {
                send(error(nullptr, -32700, std::string("parse error: ") + e.what()));
                continue;
            }
            if (!msg.is_object()) {
                send(error(nullptr, -32600, "invalid request: expected a JSON-RPC request object (batches are not supported)"));
                continue;
            }
            const std::string method = msg.value("method", "");
            if (method == "notifications/cancelled") {
                if (msg.contains("params") && msg["params"].contains("requestId")) cancel(msg["params"]["requestId"].dump());
                continue;
            }
            if (method == "ping") {
                if (msg.contains("id")) send(result(msg["id"], json::object()));
                continue;
            }
            {
                std::lock_guard<std::mutex> lk(q_mu_);
                queue_.push_back(std::move(msg));
            }
            q_cv_.notify_one();
        }
        {
            std::lock_guard<std::mutex> lk(q_mu_);
            closed_ = true;
        }
        q_cv_.notify_one();
        worker.join();
        return 0;
    }

private:
    void work() {
        for (;;) {
            json msg;
            {
                std::unique_lock<std::mutex> lk(q_mu_);
                q_cv_.wait(lk, [this] { return closed_ || !queue_.empty(); });
                if (queue_.empty()) return;
                msg = std::move(queue_.front());
                queue_.pop_front();
            }
            const std::string key = msg.contains("id") ? msg["id"].dump() : "";
            {
                std::lock_guard<std::mutex> lk(gate_);
                if (!key.empty() && cancelled_.erase(key)) continue;  // cancelled while queued: no response
                running_ = key;
            }
            std::optional<json> reply;
            try {
                reply = handle(msg);
            } catch (const std::exception& e) {
                reply = error(msg.value("id", json(nullptr)), -32603, std::string("internal error: ") + e.what());
            }
            {
                std::lock_guard<std::mutex> lk(gate_);
                running_.clear();
                if (!key.empty() && cancelled_.erase(key)) continue;  // the client gave up on it: MCP says not to respond
            }
            if (reply) send(*reply);
        }
    }

    void cancel(const std::string& id) {
        std::lock_guard<std::mutex> lk(gate_);
        cancelled_.insert(id);
        if (running_ == id) runner_.interrupt();
    }

    void send(const json& reply) {
        std::lock_guard<std::mutex> lk(out_mu_);
        std::cout << reply.dump(-1, ' ', false, json::error_handler_t::replace) << "\n" << std::flush;
    }

    std::string query_text(const std::string& sql, const RunOptions& o, const std::string& fmt, bool& failed) {
        std::lock_guard<std::mutex> lk(mu_);
        auto results = runner_.run(sql, o);
        failed = false;
        for (const auto& r : results) failed = failed || !r.success;
        if (fmt == "json") return envelope(results).dump(-1, ' ', false, json::error_handler_t::replace);
        std::string text = render(runner_.engine(), results, parse_format(fmt));
        for (const auto& r : results)
            if (!r.notice.empty()) text += "\n\nnote: " + r.notice;
        return text;
    }

    static std::string quote(const std::string& s) {
        std::string q = "'";
        for (char c : s) q += c == '\'' ? std::string("''") : std::string(1, c);
        return q + "'";
    }

    // The rows of one statement, for the server's own lookups (the guides); throws its error.
    std::vector<std::vector<Cell>> rows(const std::string& sql) {
        std::lock_guard<std::mutex> lk(mu_);
        auto results = runner_.run(sql, {100000, false});
        if (results.empty()) return {};
        if (!results.back().success) throw std::runtime_error(results.back().error);
        return results.back().rows;
    }

    // A guide (dnspysql_guides), with the assembly to work on when the client names one.
    std::string guide_text(const std::string& topic, const std::string& path) {
        auto r = rows("SELECT text FROM dnspysql_guides WHERE topic = " + quote(topic));
        if (r.empty() || r[0].empty()) throw std::invalid_argument("no guide '" + topic + "'; the guides are: " + guide_names());
        std::string text = r[0][0].s;
        if (!path.empty())
            text = "Work on this assembly: " + path + "\nLoad it with SELECT open(" + quote(path) + ") (it is only parsed, never run), "
                   "then follow the guide below.\n\n" + text;
        return text;
    }

    std::string guide_names() {
        std::string names;
        for (const auto& row : rows("SELECT topic FROM dnspysql_guides")) names += (names.empty() ? "" : ", ") + row[0].s;
        return names;
    }

    std::optional<json> handle(const json& msg) {
        const json id = msg.value("id", json(nullptr));
        if (!msg.contains("method") || !msg["method"].is_string())
            return id.is_null() ? std::nullopt : std::optional<json>(error(id, -32600, "invalid request: 'method' must be a string"));
        const std::string method = msg["method"];
        const json p = msg.value("params", json::object());
        if (method == "initialize") {
            std::string version = kProtocolVersions[0];
            const std::string asked = p.value("protocolVersion", "");
            for (const char* v : kProtocolVersions)
                if (asked == v) version = v;
            return result(id, {{"protocolVersion", version},
                               {"capabilities", {{"tools", {{"listChanged", false}}}, {"prompts", {{"listChanged", false}}}}},
                               {"serverInfo", {{"name", "dnspysql"}, {"version", kVersion}}},
                               {"instructions", kQueryDoc}});
        }
        if (method.rfind("notifications/", 0) == 0) return std::nullopt;
        // The workflow guides as prompts: a client offers them to the user (/triage, ...), with the assembly as an argument.
        if (method == "prompts/list") {
            json prompts = json::array();
            for (const auto& row : rows("SELECT topic, title, description FROM dnspysql_guides"))
                prompts.push_back({{"name", row[0].s}, {"title", row[1].s}, {"description", row[2].s},
                                   {"arguments", json::array({{{"name", "path"}, {"required", false},
                                                               {"description", "absolute path of the assembly to work on (optional)"}}})}});
            return result(id, {{"prompts", prompts}});
        }
        if (method == "prompts/get") {
            const std::string name = p.value("name", "");
            const json args = p.value("arguments", json::object());
            std::string path = args.contains("path") && args["path"].is_string() ? args["path"].get<std::string>() : "";
            try {
                const std::string text = guide_text(name, path);
                return result(id, {{"description", "DnSpySql guide: " + name},
                                   {"messages", json::array({{{"role", "user"}, {"content", {{"type", "text"}, {"text", text}}}}})}});
            } catch (const std::invalid_argument& e) {
                return error(id, -32602, e.what());
            }
        }
        if (method == "tools/list") {
            json query_props = {
                {"sql", {{"type", "string"}, {"description", "one or more SQL statements"}}},
                {"continue_on_error", {{"type", "boolean"}}},
                {"max_rows", {{"type", "integer"}, {"description", "row cap per statement (default 500)"}}},
                {"format", {{"type", "string"}, {"enum", {"table", "json", "tsv"}}, {"description", "default table"}}},
            };
            json schema_props = {{"table", {{"type", "string"}, {"description", "table name; omit for the table list"}}}};
            json guide_props = {{"topic", {{"type", "string"}, {"description", "basics, explore, triage, unpack or dnspy; omit for the list"}}}};
            return result(id, {{"tools", json::array({
                tool("dnspysql_query", kQueryDoc, query_props, {"sql"}),
                tool("dnspysql_schema", "Describe tables (all, or one table's columns) and SQL functions", schema_props),
                tool("dnspysql_guide", "How to use DnSpySql for a task: rules, handles, workflows and the queries for them. "
                     "Read 'basics' first, then the guide for the task (explore, triage, unpack, dnspy)", guide_props),
                // Names of earlier DnSpySql versions.
                tool("sql", "Run SQL; same as dnspysql_query with a `query` argument and JSON output",
                     {{"query", {{"type", "string"}, {"description", "SQL to run"}}}}, {"query"}),
                tool("schema", "Same as dnspysql_schema", schema_props),
            })}});
        }
        if (method == "tools/call") {
            const std::string name = p.value("name", "");
            const json args = p.value("arguments", json::object());
            try {
                std::string text;
                bool failed = false;
                if (name == "dnspysql_query" || name == "sql") {
                    const char* key = name == "sql" ? "query" : "sql";
                    if (!args.contains(key) || !args[key].is_string()) throw std::runtime_error(std::string(key) + " is required (a string)");
                    RunOptions o;
                    o.continue_on_error = as_bool(args, "continue_on_error").value_or(false);
                    o.max_rows = static_cast<size_t>(as_int(args, "max_rows").value_or(name == "sql" ? 2000 : 500));
                    const std::string fmt = args.value("format", name == "sql" ? std::string("json") : std::string("table"));
                    text = query_text(args[key].get<std::string>(), o, fmt, failed);
                } else if (name == "dnspysql_schema" || name == "schema") {
                    const std::string table = args.value("table", "");
                    std::string sql;
                    if (table.empty())
                        sql = "SELECT table_name, domain, required_filter, description FROM dnspysql_tables ORDER BY domain, table_name; "
                              "SELECT signature, domain, mutates, description FROM dnspysql_functions GROUP BY name ORDER BY domain, name";
                    else {
                        std::string esc;
                        for (char c : table) esc += c == '\'' ? std::string("''") : std::string(1, c);
                        sql = "SELECT column_name, type, writable, pushdown, required, hidden, description FROM dnspysql_columns WHERE table_name = '" +
                              esc + "' ORDER BY ordinal";
                    }
                    text = query_text(sql, {100000, false}, "table", failed);
                } else if (name == "dnspysql_guide") {
                    const std::string topic = args.value("topic", "");
                    if (topic.empty()) {
                        text = query_text("SELECT topic, title, description FROM dnspysql_guides", {100, false}, "table", failed);
                    } else {
                        try {
                            text = guide_text(topic, "");
                        } catch (const std::invalid_argument& e) {
                            text = std::string("error: ") + e.what();
                            failed = true;
                        }
                    }
                } else {
                    return error(id, -32602, "unknown tool " + name);
                }
                return result(id, {{"content", json::array({{{"type", "text"}, {"text", text}}})}, {"isError", failed}});
            } catch (const std::exception& e) {
                return result(id, {{"content", json::array({{{"type", "text"}, {"text", std::string("error: ") + e.what()}}})}, {"isError", true}});
            }
        }
        return id.is_null() ? std::nullopt : std::optional<json>(error(id, -32601, "method not found: " + method));
    }

    Runner& runner_;
    std::mutex& mu_;
    std::mutex q_mu_, gate_, out_mu_;
    std::condition_variable q_cv_;
    std::deque<json> queue_;
    bool closed_ = false;
    std::string running_;
    std::set<std::string> cancelled_;
};

}  // namespace

int serve_mcp(Runner& runner, std::mutex& engine_mu) {
    std::ios::sync_with_stdio(false);
    // std::cin is tied to std::cout: every read would flush cout from the reader thread while the worker writes a
    // reply, and the unsynchronized buffer then repeats one reply and drops another.
    std::cin.tie(nullptr);
    return Server(runner, engine_mu).run();
}

}  // namespace dnspysql
