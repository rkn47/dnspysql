// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include "engine.hpp"

#include <cstdlib>
#include <cstring>

#include <coreclr_delegates.h>
#include <hostfxr.h>
#include <nethost.h>

#ifdef _WIN32
#include <windows.h>
#define STR(s) L##s
#else
#include <dlfcn.h>
#define STR(s) s
#endif

namespace dnspysql {

namespace {

void* load_lib(const char_t* path) {
#ifdef _WIN32
    return ::LoadLibraryW(path);
#else
    return dlopen(path, RTLD_LAZY | RTLD_LOCAL);
#endif
}

void* get_export(void* lib, const char* name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(::GetProcAddress(static_cast<HMODULE>(lib), name));
#else
    return dlsym(lib, name);
#endif
}

std::string hex(int rc) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", static_cast<unsigned>(rc));
    return buf;
}

// --- wire encoding (see Wire.cs) ---------------------------------------------

void put_u32(std::string& out, uint32_t v) {
    char b[4];
    std::memcpy(b, &v, 4);  // little-endian hosts only (x64/arm64)
    out.append(b, 4);
}

void put_cell(std::string& out, const Cell& c) {
    out.push_back(static_cast<char>(c.tag));
    switch (c.tag) {
        case Cell::Null: break;
        case Cell::Int: { char b[8]; std::memcpy(b, &c.i, 8); out.append(b, 8); break; }
        case Cell::Real: { char b[8]; std::memcpy(b, &c.d, 8); out.append(b, 8); break; }
        case Cell::Text:
        case Cell::Blob:
            put_u32(out, static_cast<uint32_t>(c.s.size()));
            out.append(c.s);
            break;
    }
}

struct Reader {
    const std::string& buf;
    size_t pos = 0;

    void need(size_t n) const {
        if (pos + n > buf.size()) throw EngineError("truncated engine response");
    }
    uint32_t u32() {
        need(4);
        uint32_t v;
        std::memcpy(&v, buf.data() + pos, 4);
        pos += 4;
        return v;
    }
    Cell cell() {
        need(1);
        Cell c;
        c.tag = static_cast<Cell::Tag>(static_cast<uint8_t>(buf[pos++]));
        switch (c.tag) {
            case Cell::Null: break;
            case Cell::Int: need(8); std::memcpy(&c.i, buf.data() + pos, 8); pos += 8; break;
            case Cell::Real: need(8); std::memcpy(&c.d, buf.data() + pos, 8); pos += 8; break;
            case Cell::Text:
            case Cell::Blob: {
                uint32_t n = u32();
                need(n);
                c.s.assign(buf.data() + pos, n);
                pos += n;
                break;
            }
            default: throw EngineError("bad cell tag in engine response");
        }
        return c;
    }
};

std::vector<Cell> decode_list(const std::string& buf) {
    Reader r{buf};
    uint32_t n = r.u32();
    std::vector<Cell> out;
    out.reserve(n);
    for (uint32_t i = 0; i < n; i++) out.push_back(r.cell());
    return out;
}

std::vector<NRow> decode_rows(const std::string& buf) {
    Reader r{buf};
    uint32_t ncols = r.u32();
    uint32_t nrows = r.u32();
    if (ncols == 0) throw EngineError("engine rowset without key column");
    std::vector<NRow> rows(nrows);
    for (auto& row : rows) {
        Cell key = r.cell();
        row.key = key.i;
        row.vals.reserve(ncols - 1);
        for (uint32_t c = 1; c < ncols; c++) row.vals.push_back(r.cell());
    }
    return rows;
}

}  // namespace

std::string Cell::to_string() const {
    switch (tag) {
        case Int: return std::to_string(i);
        case Real: return std::to_string(d);
        case Text:
        case Blob: return s;
        default: return {};
    }
}

void Engine::start(const std::filesystem::path& engine_dir) {
    char_t buffer[1024];
    size_t size = sizeof(buffer) / sizeof(char_t);
    int rc = get_hostfxr_path(buffer, &size, nullptr);
#ifndef _WIN32
    // nethost checks DOTNET_ROOT, /etc/dotnet and /usr/{share,lib}/dotnet; also accept
    // the per-user location dotnet-install.sh uses, so ~/.dotnet works without setup.
    if (rc != 0) {
        if (const char* home = std::getenv("HOME")) {
            const std::string root = std::string(home) + "/.dotnet";
            get_hostfxr_parameters params{sizeof(get_hostfxr_parameters), nullptr, root.c_str()};
            size = sizeof(buffer) / sizeof(char_t);
            rc = get_hostfxr_path(buffer, &size, &params);
        }
    }
#else
    // Likewise the per-user installs of dotnet-install.ps1 (%USERPROFILE%\.dotnet) and of the SDK installer
    // (%LOCALAPPDATA%\Microsoft\dotnet), so an MCP client starting dnspysql needs no DOTNET_ROOT.
    for (const auto& [var, sub] : {std::pair{L"USERPROFILE", L"\\.dotnet"}, std::pair{L"LOCALAPPDATA", L"\\Microsoft\\dotnet"}}) {
        if (rc == 0) break;
        wchar_t* base = nullptr;
        size_t len = 0;
        if (_wdupenv_s(&base, &len, var) != 0 || !base) continue;
        const std::wstring root = std::wstring(base) + sub;
        free(base);
        if (!std::filesystem::exists(root + L"\\host\\fxr")) continue;
        get_hostfxr_parameters params{sizeof(get_hostfxr_parameters), nullptr, root.c_str()};
        size = sizeof(buffer) / sizeof(char_t);
        rc = get_hostfxr_path(buffer, &size, &params);
    }
#endif
    if (rc != 0)
        throw EngineError("could not locate the .NET runtime (hostfxr), rc=" + hex(rc) +
                          ". Install the .NET 8 runtime or later (or set DOTNET_ROOT).");

    void* lib = load_lib(buffer);
    if (!lib) throw EngineError("failed to load hostfxr");

    auto init = reinterpret_cast<hostfxr_initialize_for_runtime_config_fn>(
        get_export(lib, "hostfxr_initialize_for_runtime_config"));
    auto get_delegate = reinterpret_cast<hostfxr_get_runtime_delegate_fn>(
        get_export(lib, "hostfxr_get_runtime_delegate"));
    auto close = reinterpret_cast<hostfxr_close_fn>(get_export(lib, "hostfxr_close"));
    if (!init || !get_delegate || !close) throw EngineError("hostfxr is missing expected exports");

    const auto config = engine_dir / "DnSpySql.Engine.runtimeconfig.json";
    const auto dll = engine_dir / "DnSpySql.Engine.dll";
    if (!std::filesystem::exists(dll))
        throw EngineError("engine not found: " + dll.string());

    hostfxr_handle ctx = nullptr;
    rc = init(config.c_str(), nullptr, &ctx);
    // 0 = Success, 1 = Success_HostAlreadyInitialized, 2 = Success_DifferentRuntimeProperties
    if ((rc != 0 && rc != 1 && rc != 2) || !ctx) {
        if (ctx) close(ctx);
        throw EngineError("failed to initialize the .NET runtime, rc=" + hex(rc));
    }

    load_assembly_and_get_function_pointer_fn load = nullptr;
    rc = get_delegate(ctx, hdt_load_assembly_and_get_function_pointer, reinterpret_cast<void**>(&load));
    close(ctx);
    if (rc != 0 || !load) throw EngineError("failed to get the runtime loader delegate, rc=" + hex(rc));

    const char_t* type = STR("DnSpySql.Exports, DnSpySql.Engine");
    rc = load(dll.c_str(), type, STR("Call"), UNMANAGEDCALLERSONLY_METHOD, nullptr,
              reinterpret_cast<void**>(&call_));
    if (rc != 0 || !call_) throw EngineError("failed to bind Exports.Call, rc=" + hex(rc));
    rc = load(dll.c_str(), type, STR("Free"), UNMANAGEDCALLERSONLY_METHOD, nullptr,
              reinterpret_cast<void**>(&free_));
    if (rc != 0 || !free_) throw EngineError("failed to bind Exports.Free, rc=" + hex(rc));
}

std::string Engine::call(const char* op, const std::vector<Cell>& args) {
    if (!call_) throw EngineError("engine not started");
    std::string req;
    put_u32(req, static_cast<uint32_t>(args.size()));
    for (const auto& a : args) put_cell(req, a);

    uint8_t* resp = nullptr;
    int len = 0;
    int status = call_(op, reinterpret_cast<const uint8_t*>(req.data()), static_cast<int>(req.size()), &resp, &len);
    std::string out(reinterpret_cast<const char*>(resp), static_cast<size_t>(len));
    free_(resp);
    if (status != 0) throw EngineError(out);
    return out;
}

void Engine::init(const std::string& options_json) { call("init", {Cell::text(options_json)}); }

std::string Engine::describe() { return call("describe", {}); }

int Engine::open(const std::string& path) {
    auto r = decode_list(call("open", {Cell::text(path)}));
    return r.empty() ? 0 : static_cast<int>(r[0].i);
}

void Engine::view_columns(const std::string& view, const std::string& columns_json) {
    call("view_columns", {Cell::text(view), Cell::text(columns_json)});
}

Engine::StatementLimits Engine::begin_statement() {
    auto r = decode_list(call("begin_statement", {}));
    StatementLimits limits;
    if (r.size() > 0) limits.timeout_ms = r[0].i;
    if (r.size() > 1) limits.max_rows = r[1].i;
    return limits;
}
std::string Engine::end_statement() {
    auto r = decode_list(call("end_statement", {}));
    return r.empty() ? std::string() : r[0].s;
}
void Engine::interrupt() { call("interrupt", {}); }

int64_t Engine::scan_open(const std::string& table, uint64_t used, const std::vector<Constraint>& constraints,
                          size_t first, std::vector<NRow>& rows) {
    std::vector<Cell> args;
    args.reserve(4 + 3 * constraints.size());
    args.push_back(Cell::text(table));
    args.push_back(Cell::integer(static_cast<int64_t>(used)));
    args.push_back(Cell::integer(static_cast<int64_t>(first)));
    args.push_back(Cell::integer(static_cast<int64_t>(constraints.size())));
    for (const auto& c : constraints) {
        args.push_back(Cell::integer(c.column));
        args.push_back(Cell::integer(c.op));
        args.push_back(c.value);
    }
    const std::string resp = call("scan_open", args);
    if (resp.size() < 8) throw EngineError("scan_open returned no cursor");
    int64_t id;
    std::memcpy(&id, resp.data(), 8);
    rows = decode_rows(resp.substr(8));
    return id;
}

std::vector<NRow> Engine::scan_next(int64_t cursor, size_t n) {
    return decode_rows(call("scan_next", {Cell::integer(cursor), Cell::integer(static_cast<int64_t>(n))}));
}

void Engine::scan_close(int64_t cursor) {
    call("scan_close", {Cell::integer(cursor)});
}

size_t Engine::count(const std::string& table) {
    auto r = decode_list(call("count", {Cell::text(table)}));
    return r.empty() ? 0 : static_cast<size_t>(r[0].i);
}

std::optional<NRow> Engine::get(const std::string& table, int64_t key) {
    auto rows = decode_rows(call("get", {Cell::text(table), Cell::integer(key)}));
    if (rows.empty()) return std::nullopt;
    return std::move(rows[0]);
}

void Engine::update(const std::string& table, int64_t key, const std::string& col, const Cell& val) {
    call("update", {Cell::text(table), Cell::integer(key), Cell::text(col), val});
}

int64_t Engine::insert(const std::string& table, const std::vector<Cell>& values) {
    std::vector<Cell> args;
    args.reserve(values.size() + 1);
    args.push_back(Cell::text(table));
    args.insert(args.end(), values.begin(), values.end());
    auto r = decode_list(call("insert", args));
    return r.empty() ? 0 : r[0].i;
}

std::string Engine::schema_md() {
    auto r = decode_list(call("schema_md", {}));
    return r.empty() ? std::string() : r[0].s;
}

std::string Engine::visible(const std::string& text) {
    auto r = decode_list(call("visible", {Cell::text(text)}));
    return r.empty() ? text : r[0].s;
}

std::string Engine::module_summary(int id) {
    auto r = decode_list(call("module_summary", {Cell::integer(id)}));
    return r.empty() ? std::string() : r[0].s;
}

std::string Engine::status() {
    auto r = decode_list(call("status", {}));
    return r.empty() ? std::string("{}") : r[0].s;
}

std::string Engine::dirty() {
    auto r = decode_list(call("dirty", {}));
    return r.empty() ? std::string() : r[0].s;
}

void Engine::remove(const std::string& table, int64_t key) {
    call("delete", {Cell::text(table), Cell::integer(key)});
}

Cell Engine::invoke(const std::string& fn, const std::vector<Cell>& args) {
    std::vector<Cell> all;
    all.reserve(args.size() + 1);
    all.push_back(Cell::text(fn));
    all.insert(all.end(), args.begin(), args.end());
    auto r = decode_list(call("invoke", all));
    return r.empty() ? Cell::null() : std::move(r[0]);
}

}  // namespace dnspysql
