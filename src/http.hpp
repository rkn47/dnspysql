// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
// HTTP API (idasql / ghidrasql shape) and the --remote client.
//   POST /query  raw SQL body, or JSON {sql, continue_on_error, include_sql, max_rows}  [?format=json|text|csv|tsv]
//   GET /status, GET /health, GET /schema, POST /cancel, POST /shutdown
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "query.hpp"

namespace dnspysql {

class HttpServer {
public:
    // `engine_mu` serializes engine access with the REPL; the server holds it while a query runs.
    HttpServer(Runner& runner, std::mutex& engine_mu, std::string bind, int port, std::string token);
    ~HttpServer();

    // Listens on a background thread; false if the address cannot be bound.
    bool start();
    // Blocks until POST /shutdown or stop().
    void wait();
    void stop();
    std::string url() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Sends each -c/-f script to a running DnSpySql HTTP server and prints the answer. Exit code as for local runs:
// 0 ok, 1 a statement failed, 3 the server cannot be reached.
int run_remote(const std::string& url, const std::string& token, const std::string& format,
               const std::vector<std::string>& scripts, bool continue_on_error);

}  // namespace dnspysql
