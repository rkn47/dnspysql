// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include "http.hpp"

#include <chrono>
#include <iostream>

#include <httplib.h>
#include <xsql/thinclient/auth_compare.hpp>

#include "version.hpp"

namespace dnspysql {

using json = nlohmann::json;

namespace {

json error_body(const std::string& msg) { return {{"success", false}, {"error", msg}}; }

void send_json(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(-1, ' ', false, json::error_handler_t::replace), "application/json; charset=utf-8");
}

}  // namespace

struct HttpServer::Impl {
    Runner& runner;
    std::mutex& engine_mu;
    std::string bind, token;
    int port;
    httplib::Server svr;
    std::thread thread;
    std::atomic<bool> busy{false};
    std::atomic<long long> queries{0};
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    std::string last_status = "{}";

    Impl(Runner& r, std::mutex& mu, std::string b, int p, std::string t)
        : runner(r), engine_mu(mu), bind(std::move(b)), token(std::move(t)), port(p) {}

    bool authorized(const httplib::Request& req) const {
        if (token.empty()) return true;
        const auto auth = req.get_header_value("Authorization");
        const auto x = req.get_header_value("X-XSQL-Token");
        return xsql::thinclient::detail::timing_safe_equal(auth, "Bearer " + token) || xsql::thinclient::detail::timing_safe_equal(x, token);
    }

    std::vector<StatementOutput> run(const std::string& sql, const RunOptions& o) {
        std::lock_guard<std::mutex> lk(engine_mu);
        busy = true;
        auto r = runner.run(sql, o);
        busy = false;
        queries++;
        try {
            last_status = runner.engine().status();
        } catch (...) {
        }
        return r;
    }

    void routes() {
        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            if (authorized(req)) return httplib::Server::HandlerResponse::Unhandled;
            send_json(res, 401, error_body("401: missing or bad token (Authorization: Bearer <token>)"));
            return httplib::Server::HandlerResponse::Handled;
        });
        svr.Get("/health", [](const httplib::Request&, httplib::Response& res) { send_json(res, 200, {{"ok", true}}); });
        svr.Get("/status", [this](const httplib::Request&, httplib::Response& res) {
            // The engine serves one caller at a time: while a query runs, report the state after the previous one.
            json st = json::parse(last_status, nullptr, false);
            if (st.is_discarded()) st = json::object();
            if (std::unique_lock<std::mutex> lk(engine_mu, std::try_to_lock); lk.owns_lock()) {
                try {
                    last_status = runner.engine().status();
                    st = json::parse(last_status);
                } catch (...) {
                }
            }
            st["busy"] = busy.load();
            st["queries"] = queries.load();
            st["uptime_s"] = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started).count();
            send_json(res, 200, st);
        });
        svr.Get("/schema", [this](const httplib::Request&, httplib::Response& res) {
            auto r = run("SELECT table_name, domain, description, required_filter FROM dnspysql_tables; "
                         "SELECT table_name, column_name, type, writable, pushdown, required, description FROM dnspysql_columns; "
                         "SELECT signature, domain, mutates, description FROM dnspysql_functions",
                         {100000000, false});
            send_json(res, 200, envelope(r));
        });
        svr.Post("/cancel", [this](const httplib::Request&, httplib::Response& res) {
            const bool was_busy = busy.load();
            runner.interrupt();
            send_json(res, 200, {{"cancelled", was_busy}});
        });
        svr.Post("/shutdown", [this](const httplib::Request&, httplib::Response& res) {
            size_t unsaved = 0;
            if (std::unique_lock<std::mutex> lk(engine_mu, std::try_to_lock); lk.owns_lock()) {
                try {
                    auto d = runner.engine().dirty();
                    for (size_t p = 0; !d.empty() && p != std::string::npos; p = d.find('\n', p + 1)) unsaved++;
                } catch (...) {
                }
            }
            send_json(res, 200, {{"shutting_down", true}, {"unsaved_modules", unsaved}});
            std::thread([this] {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                svr.stop();
            }).detach();
        });
        svr.Post("/query", [this](const httplib::Request& req, httplib::Response& res) {
            std::string sql = req.body;
            bool include_sql = false;
            RunOptions o;
            const auto first = sql.find_first_not_of(" \t\r\n");
            if (first != std::string::npos && sql[first] == '{') {
                try {
                    auto j = json::parse(req.body);
                    if (!j.contains("sql") || !j["sql"].is_string()) throw std::runtime_error("missing 'sql'");
                    sql = j["sql"].get<std::string>();
                    o.continue_on_error = j.value("continue_on_error", false);
                    include_sql = j.value("include_sql", false);
                    if (j.contains("max_rows") && j["max_rows"].is_number_integer()) o.max_rows = j["max_rows"].get<size_t>();
                } catch (const std::exception& e) {
                    send_json(res, 400, error_body(std::string("400: bad JSON body: ") + e.what()));
                    return;
                }
            }
            if (sql.find_first_not_of(" \t\r\n") == std::string::npos) {
                send_json(res, 400, error_body("400: empty SQL"));
                return;
            }
            auto results = run(sql, o);
            const std::string fmt = req.has_param("format") ? req.get_param_value("format") : "json";
            if (fmt == "json") {
                send_json(res, 200, envelope(results, include_sql));
                return;
            }
            Format f;
            try {
                f = parse_format(fmt);
            } catch (const std::exception& e) {
                send_json(res, 400, error_body(std::string("400: ") + e.what()));
                return;
            }
            std::lock_guard<std::mutex> lk(engine_mu);  // table output escapes text through the engine
            res.status = 200;
            res.set_content(render(runner.engine(), results, f), fmt == "csv" ? "text/csv; charset=utf-8" : "text/plain; charset=utf-8");
        });
        svr.set_error_handler([](const httplib::Request&, httplib::Response& res) {
            if (res.status == 404)
                send_json(res, 404, error_body("404: endpoints are POST /query, GET /status, GET /health, GET /schema, POST /cancel, POST /shutdown"));
        });
        svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr ep) {
            std::string msg = "500";
            try {
                if (ep) std::rethrow_exception(ep);
            } catch (const std::exception& e) {
                msg = std::string("500: ") + e.what();
            } catch (...) {
            }
            send_json(res, 500, error_body(msg));
        });
    }
};

HttpServer::HttpServer(Runner& runner, std::mutex& engine_mu, std::string bind, int port, std::string token)
    : impl_(std::make_unique<Impl>(runner, engine_mu, std::move(bind), port, std::move(token))) {
    impl_->routes();
}

HttpServer::~HttpServer() { stop(); }

bool HttpServer::start() {
    if (impl_->port == 0) {
        // --http 0: any free port, reported on stderr
        const int p = impl_->svr.bind_to_any_port(impl_->bind);
        if (p <= 0) return false;
        impl_->port = p;
    } else if (!impl_->svr.bind_to_port(impl_->bind, impl_->port)) {
        return false;
    }
    impl_->thread = std::thread([this] { impl_->svr.listen_after_bind(); });
    std::cerr << "dnspysql http listening on " << url() << (impl_->token.empty() ? "" : " (token required)") << "\n";
    return true;
}

void HttpServer::wait() {
    if (impl_->thread.joinable()) impl_->thread.join();
}

void HttpServer::stop() {
    impl_->svr.stop();
    if (impl_->thread.joinable() && impl_->thread.get_id() != std::this_thread::get_id()) impl_->thread.join();
}

std::string HttpServer::url() const { return "http://" + impl_->bind + ":" + std::to_string(impl_->port) + "/"; }

int run_remote(const std::string& url, const std::string& token, const std::string& format,
               const std::vector<std::string>& scripts, bool continue_on_error) {
    std::string base = url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    httplib::Client cli(base);
    cli.set_read_timeout(std::chrono::hours(24));
    httplib::Headers headers;
    if (!token.empty()) headers.emplace("Authorization", "Bearer " + token);
    const std::string fmt = format == "table" ? "text" : format;
    int rc = 0;
    for (const auto& sql : scripts) {
        json body = {{"sql", sql}, {"continue_on_error", continue_on_error}};
        auto res = cli.Post("/query?format=" + fmt, headers, body.dump(), "application/json");
        if (!res) {
            std::cerr << "dnspysql: cannot reach " << url << ": " << httplib::to_string(res.error()) << "\n";
            return 3;
        }
        std::string text = res->body;
        while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) text.pop_back();
        std::cout << text << "\n";
        if (res->status != 200 || text.find("\"success\":false") != std::string::npos || text.rfind("error:", 0) == 0 ||
            text.find("\nerror:") != std::string::npos)
            rc = 1;
        if (rc != 0 && !continue_on_error) break;
    }
    return rc;
}

}  // namespace dnspysql
