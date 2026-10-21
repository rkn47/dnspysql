// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
#include "schema.hpp"

#include <algorithm>

#include <nlohmann/json.hpp>

namespace dnspysql {

namespace {

using json = nlohmann::json;

xsql::ColumnType column_type(const std::string& t) {
    if (t == "int") return xsql::ColumnType::Integer;
    if (t == "real") return xsql::ColumnType::Real;
    if (t == "blob") return xsql::ColumnType::Blob;
    return xsql::ColumnType::Text;
}

void set_result(xsql::FunctionContext& ctx, const Cell& c) {
    switch (c.tag) {
        case Cell::Int: ctx.result_int64(c.i); break;
        case Cell::Real: ctx.result_double(c.d); break;
        // libxsql's result_text ends the value at the first NUL: text that holds one goes back as its bytes, a blob,
        // so nothing after it is lost (a decrypted string can contain NUL)
        case Cell::Text:
            if (c.s.find('\0') != std::string::npos) ctx.result_blob(c.s.data(), c.s.size());
            else ctx.result_text(c.s);
            break;
        case Cell::Blob: ctx.result_blob(c.s.data(), c.s.size()); break;
        default: ctx.result_null(); break;
    }
}

Cell from_arg(const xsql::FunctionArg& a) {
    if (a.is_null()) return Cell::null();
    switch (a.type()) {
        case 1: return Cell::integer(a.as_int64());   // SQLITE_INTEGER
        case 2: return Cell::real(a.as_double());     // SQLITE_FLOAT
        case 4:                                       // SQLITE_BLOB
            return Cell::blob(std::string(static_cast<const char*>(a.as_blob()), static_cast<size_t>(a.bytes())));
        default:  // text, read with its byte count: as_text() would stop at a NUL
            return Cell::text(std::string(static_cast<const char*>(a.as_blob()), static_cast<size_t>(a.bytes())));
    }
}

// An engine scan cursor, read in batches that grow from small (a LIMIT or an
// EXISTS needs only the first rows) to large (a full scan pays the bridge per
// batch, not per row). Errors end the scan and are reported through libxsql.
class Scan {
public:
    Scan(Engine& eng, const std::string& table, uint64_t used, const std::vector<Engine::Constraint>& cons) : eng_(eng) {
        try {
            id_ = eng_.scan_open(table, used, cons, batch_, rows_);
            pending_ = true;
            if (rows_.size() < batch_) done_ = true;  // the engine closed the cursor
            batch_ = std::min(batch_ * 4, kMaxBatch);
        } catch (const std::exception& e) {
            xsql::set_vtab_error(e.what());
            done_ = true;
        }
    }
    ~Scan() {
        if (done_) return;
        try {
            eng_.scan_close(id_);
        } catch (...) {
        }
    }
    Scan(const Scan&) = delete;
    Scan& operator=(const Scan&) = delete;

    // Moves onto the next row; false at the end.
    bool advance() {
        if (pending_) {  // the first batch came with scan_open
            pending_ = false;
            pos_ = 0;
            if (!rows_.empty()) return true;
            return false;
        }
        if (++pos_ < rows_.size()) return true;
        if (done_) return false;
        try {
            rows_ = eng_.scan_next(id_, batch_);
        } catch (const std::exception& e) {
            xsql::set_vtab_error(e.what());
            rows_.clear();
            done_ = true;  // the engine closed the cursor
            return false;
        }
        if (rows_.size() < batch_) done_ = true;
        batch_ = std::min(batch_ * 4, kMaxBatch);
        pos_ = 0;
        return !rows_.empty();
    }
    const NRow& row() const { return rows_[pos_]; }

private:
    static constexpr size_t kMaxBatch = 16384;
    Engine& eng_;
    int64_t id_ = 0;
    bool done_ = false;
    bool pending_ = false;
    std::vector<NRow> rows_;
    size_t pos_ = static_cast<size_t>(-1);
    size_t batch_ = 64;
};

// A scan (full, or with the constraints SQLite pushed down) as a libxsql generator.
class ScanGenerator : public xsql::Generator<NRow> {
public:
    ScanGenerator(Engine& eng, const std::string& table, uint64_t used, const std::vector<Engine::Constraint>& cons = {})
        : scan_(eng, table, used, cons) {}

    bool next() override { return scan_.advance(); }
    const NRow& current() const override { return scan_.row(); }
    int64_t rowid() const override { return scan_.row().key; }

private:
    Scan scan_;
};

int sqlite_op(xsql::ConstraintOp op) {
    switch (op) {
        case xsql::ConstraintOp::Gt: return 4;
        case xsql::ConstraintOp::Le: return 8;
        case xsql::ConstraintOp::Lt: return 16;
        case xsql::ConstraintOp::Ge: return 32;
        default: return 2;  // Eq
    }
}

}  // namespace

Schema Schema::parse(const std::string& text) {
    Schema s;
    auto j = json::parse(text);
    auto str = [](const json& o, const char* k) {
        auto it = o.find(k);
        return it != o.end() && it->is_string() ? it->get<std::string>() : std::string();
    };
    for (const auto& t : j.at("tables")) {
        TableInfo ti;
        ti.name = t.at("name");
        ti.doc = str(t, "doc");
        ti.domain = str(t, "domain");
        ti.required_hint = str(t, "required_hint");
        ti.insertable = t.value("insertable", false);
        ti.deletable = t.value("deletable", false);
        ti.estimated_rows = t.value("estimated_rows", 10000.0);
        ti.cost_per_row = t.value("cost_per_row", 1.0);
        for (const auto& c : t.at("columns")) {
            ColumnInfo ci;
            ci.name = c.at("name");
            ci.type = c.at("type");
            ci.doc = str(c, "doc");
            ci.pushdown = c.value("pushdown", std::string("none"));
            ci.writable = c.value("writable", false);
            ci.hidden = c.value("hidden", false);
            ci.required = c.value("required", false);
            ci.argument = c.value("argument", false);
            ti.columns.push_back(std::move(ci));
        }
        s.tables.push_back(std::move(ti));
    }
    for (const auto& f : j.at("functions")) {
        s.functions.push_back({f.at("name"), str(f, "signature"), str(f, "doc"), str(f, "domain"),
                               f.value("args", 0), f.value("mutates", false)});
    }
    for (const auto& v : j.value("views", json::array())) s.views.push_back({v.at("name"), v.at("sql")});
    return s;
}

void Registry::install(xsql::Database& db) {
    for (const auto& t : schema_.tables) add_table(db, t);
    for (const auto& f : schema_.functions) add_function(db, f);
    for (const auto& v : schema_.views) {
        if (db.exec(v.sql) != xsql::Status::ok) throw std::runtime_error("cannot create view " + v.name + ": " + db.last_error());
        // The engine's catalog tables (dnspysql_columns) list view columns too.
        json cols = json::array();
        auto st = db.prepare_statement("PRAGMA table_info(\"" + v.name + "\")");
        while (st.valid() && st.step() == xsql::StepResult::row) cols.push_back({st.text(1), st.text(2)});
        engine_.view_columns(v.name, cols.dump());
    }
}

void Registry::add_table(xsql::Database& db, const TableInfo& t) {
    Engine& eng = engine_;
    const std::string name = t.name;
    bool has_required = false;
    for (const auto& c : t.columns) has_required = has_required || c.required;

    // A libxsql generator table whose scans compute only the columns the query
    // reads: SQLite's colUsed goes to the engine, which builds each cell in .NET
    // and ships it over the bridge, so unused columns are the cost to avoid.
    auto b = xsql::generator_table<NRow>(name.c_str());
    // A table that needs a filter must never be planned as a full scan while another plan exists.
    const double full_rows = has_required ? 1e12 : std::max(1.0, t.estimated_rows);
    b.estimate_rows([full_rows] { return static_cast<size_t>(full_rows); });
    if (!has_required) {
        // A bare COUNT(*) is answered without building or shipping any rows.
        b.row_count([&eng, name]() -> size_t {
            try {
                return eng.count(name);
            } catch (const std::exception& e) {
                xsql::set_vtab_error(e.what());
                return 0;
            }
        });
    }
    b.projection_generator([&eng, name](uint64_t used) -> std::unique_ptr<xsql::Generator<NRow>> {
        return std::make_unique<ScanGenerator>(eng, name, used);
    });
    b.generator([&eng, name]() -> std::unique_ptr<xsql::Generator<NRow>> {
        return std::make_unique<ScanGenerator>(eng, name, ~uint64_t{0});
    });

    for (size_t i = 0; i < t.columns.size(); i++) {
        const auto& c = t.columns[i];
        auto getter = [i](xsql::FunctionContext& ctx, const NRow& r) {
            if (i < r.vals.size()) set_result(ctx, r.vals[i]);
            else ctx.result_null();
        };
        if (c.writable) {
            const std::string col = c.name;
            b.column_rw(c.name.c_str(), column_type(c.type), getter,
                [&eng, name, col, i](NRow& r, xsql::FunctionArg v) {
                    try {
                        Cell cell = from_arg(v);
                        eng.update(name, r.key, col, cell);
                        if (i < r.vals.size()) r.vals[i] = std::move(cell);
                        return true;
                    } catch (const std::exception& e) {
                        xsql::set_vtab_error(e.what());
                        return false;
                    }
                });
        } else {
            b.column(c.name.c_str(), column_type(c.type), getter);
        }
    }

    // UPDATE and DELETE find their row by key (the SQLite rowid).
    b.row_lookup([&eng, name](NRow& out, int64_t key) {
        try {
            auto r = eng.get(name, key);
            if (!r) return false;
            out = std::move(*r);
            return true;
        } catch (const std::exception& e) {
            xsql::set_vtab_error(e.what());
            return false;
        }
    });
    if (t.deletable) {
        b.deletable([&eng, name](NRow& r) {
            try {
                eng.remove(name, r.key);
                return true;
            } catch (const std::exception& e) {
                xsql::set_vtab_error(e.what());
                return false;
            }
        });
    }
    if (t.insertable) {
        b.insertable([&eng, name](int argc, xsql::FunctionArg* argv) {
            try {
                std::vector<Cell> values;
                values.reserve(static_cast<size_t>(argc));
                for (int k = 0; k < argc; k++) values.push_back(from_arg(argv[k]));
                eng.insert(name, values);
                return true;
            } catch (const std::exception& e) {
                xsql::set_vtab_error(e.what());
                return false;
            }
        });
    }
    if (has_required) b.full_scan_error("table '" + name + "' needs a filter: " + t.required_hint);

    auto def = std::make_unique<xsql::GeneratorTableDef<NRow>>(b.build());
    for (size_t i = 0; i < t.columns.size(); i++)
        if (t.columns[i].hidden) def->hidden_columns.insert(static_cast<int>(i));

    // Pushed-down filters. Every filter lists all filterable columns, so whatever a query constrains reaches the
    // engine together (table arguments in particular); one column per filter is required, which sets its cost:
    // a unique key finds one row, an equality about 1%, a range a quarter of the table.
    std::vector<xsql::GeneratorConstraintSpec> all;
    for (size_t i = 0; i < t.columns.size(); i++) {
        const auto& c = t.columns[i];
        if (c.pushdown == "none") continue;
        const int col = static_cast<int>(i);
        all.push_back({col, xsql::ConstraintOp::Eq, false, {}});
        if (c.pushdown == "range")
            for (auto op : {xsql::ConstraintOp::Gt, xsql::ConstraintOp::Ge, xsql::ConstraintOp::Lt, xsql::ConstraintOp::Le})
                all.push_back({col, op, false, {}});
    }
    auto factory = [&eng, name](const std::vector<xsql::GeneratorConstraintArg>& args, uint64_t used)
        -> std::unique_ptr<xsql::Generator<NRow>> {
        std::vector<Engine::Constraint> cons;
        cons.reserve(args.size());
        for (const auto& a : args) cons.push_back({a.column_index, sqlite_op(a.op), from_arg(a.value)});
        return std::make_unique<ScanGenerator>(eng, name, used, cons);
    };
    const double rows = std::max(1.0, t.estimated_rows);
    for (size_t s = 0; s < all.size(); s++) {
        const auto& lead = all[s];
        const auto& c = t.columns[static_cast<size_t>(lead.column_index)];
        // With required columns, only a filter led by one of them can satisfy the table.
        if (has_required && !c.required) continue;
        const bool eq = lead.op == xsql::ConstraintOp::Eq;
        const double est = !eq ? rows / 4 : c.pushdown == "unique" ? 1 : std::max(1.0, rows / 100);
        xsql::ConstraintFilterDef<NRow> cf;
        cf.specs = all;
        cf.specs[s].required = true;
        cf.filter_id = xsql::CONSTRAINT_FILTER_BASE + static_cast<int>(def->constraint_filters.size());
        cf.estimated_cost = est * t.cost_per_row + 1;
        cf.estimated_rows = est;
        cf.create_with_col_used = factory;
        def->constraint_filters.push_back(std::move(cf));
    }
    // Two equalities narrow more than either: a filter per pair, priced as both, so a lookup that pins a row by two
    // columns (il's method and idx, a self-join on the next instruction) is not planned as a scan of one of them.
    auto narrow = [rows](const ColumnInfo& c) { return c.pushdown == "unique" ? 1.0 : std::max(1.0, rows / 100); };
    for (size_t s = 0; s < all.size(); s++) {
        if (all[s].op != xsql::ConstraintOp::Eq) continue;
        for (size_t u = s + 1; u < all.size(); u++) {
            if (all[u].op != xsql::ConstraintOp::Eq) continue;
            const auto& c1 = t.columns[static_cast<size_t>(all[s].column_index)];
            const auto& c2 = t.columns[static_cast<size_t>(all[u].column_index)];
            if (has_required && !c1.required && !c2.required) continue;
            const double est = std::max(1.0, narrow(c1) * narrow(c2) / rows);
            xsql::ConstraintFilterDef<NRow> cf;
            cf.specs = all;
            cf.specs[s].required = true;
            cf.specs[u].required = true;
            cf.filter_id = xsql::CONSTRAINT_FILTER_BASE + static_cast<int>(def->constraint_filters.size());
            cf.estimated_cost = est * t.cost_per_row + 1;
            cf.estimated_rows = est;
            cf.create_with_col_used = factory;
            def->constraint_filters.push_back(std::move(cf));
        }
    }

    defs_.push_back(std::move(def));
    db.register_and_create_generator_table(*defs_.back());
}

void Registry::add_function(xsql::Database& db, const FunctionInfo& f) {
    Engine& eng = engine_;
    const std::string name = f.name;
    db.register_function(name.c_str(), f.args,
        [&eng, name](xsql::FunctionContext& ctx, int n, xsql::FunctionArg* argv) {
            std::vector<Cell> args;
            args.reserve(static_cast<size_t>(n));
            for (int k = 0; k < n; k++) args.push_back(from_arg(argv[k]));
            try {
                Cell r = eng.invoke(name, args);
                set_result(ctx, r);
            } catch (const std::exception& e) {
                ctx.result_error(name + ": " + e.what());
            }
        });
}

}  // namespace dnspysql
