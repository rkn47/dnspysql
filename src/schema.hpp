// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
// Builds SQLite virtual tables, SQL functions and views from the schema the engine
// describes. Nothing here is table-specific.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include <xsql/database.hpp>
#include <xsql/vtable.hpp>

#include "engine.hpp"

namespace dnspysql {

struct ColumnInfo {
    std::string name, type, doc;
    // none | eq | unique | range: the filters the engine answers for this column.
    std::string pushdown = "none";
    bool writable = false, hidden = false, required = false, argument = false;
};

struct TableInfo {
    std::string name, doc, domain, required_hint;
    bool insertable = false, deletable = false;
    double estimated_rows = 10000, cost_per_row = 1;
    std::vector<ColumnInfo> columns;
};

struct FunctionInfo {
    std::string name, signature, doc, domain;
    int args = 0;  // -1 = variadic; one entry per overload
    bool mutates = false;
};

struct ViewInfo {
    std::string name, sql;
};

struct Schema {
    std::vector<TableInfo> tables;
    std::vector<FunctionInfo> functions;
    std::vector<ViewInfo> views;

    static Schema parse(const std::string& json);
};

// Owns the table definitions; must outlive the database it registered into.
class Registry {
public:
    Registry(Engine& engine, Schema schema) : engine_(engine), schema_(std::move(schema)) {}

    // Registers tables and functions, then creates the views and reports their columns to the engine.
    void install(xsql::Database& db);
    const Schema& schema() const { return schema_; }

private:
    void add_table(xsql::Database& db, const TableInfo& t);
    void add_function(xsql::Database& db, const FunctionInfo& f);

    Engine& engine_;
    Schema schema_;
    std::vector<std::unique_ptr<xsql::GeneratorTableDef<NRow>>> defs_;
};

}  // namespace dnspysql
