// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;

namespace DnSpySql.Tables;

/// <summary>Plain SQL views over the virtual tables (pushdown flows through simple views).</summary>
public static class Views
{
    public static readonly (string name, string doc, string sql)[] All =
    {
        ("callees", "What a method calls: WHERE method = <handle> (external callees have callee = 0)",
            "SELECT src AS method, dst AS callee, dst_name AS callee_name, dst_assembly, call_site, kind, is_external FROM call_edges"),
        ("external_calls", "Calls leaving the loaded modules, grouped by target (imports-like view)",
            "SELECT dst_assembly, dst_name, count(*) AS call_count, count(DISTINCT src) AS caller_count FROM call_edges WHERE is_external GROUP BY dst_assembly, dst_name"),
        ("method_metrics", "Per-method size/complexity/fan-in/fan-out/string counts for triage (hotness_score ranking)",
            @"WITH co AS (SELECT src AS m, count(*) AS n FROM call_edges GROUP BY src),
                   ci AS (SELECT dst AS m, count(*) AS n FROM call_edges WHERE dst <> 0 GROUP BY dst),
                   st AS (SELECT from_method AS m, count(*) AS n FROM xrefs WHERE kind = 'string' GROUP BY from_method)
              SELECT m.handle AS method, m.full_name AS name, m.module, m.instr_count, m.code_size, m.eh_count,
                     coalesce(co.n, 0) AS call_out, coalesce(ci.n, 0) AS call_in, coalesce(st.n, 0) AS string_count,
                     coalesce(ci.n, 0) * 3 + coalesce(co.n, 0) * 2 + coalesce(st.n, 0) + coalesce(m.instr_count, 0) / 20 AS hotness_score
              FROM methods m LEFT JOIN co ON co.m = m.handle LEFT JOIN ci ON ci.m = m.handle LEFT JOIN st ON st.m = m.handle"),
        ("entry_points", "Managed entry points and module initializers (<Module>..cctor) of every module",
            @"SELECT module, handle AS method, full_name, 'entry_point' AS kind FROM methods WHERE is_entry_point
              UNION ALL SELECT m.module, m.handle, m.full_name, 'module_initializer' FROM methods m JOIN types t ON t.handle = m.type WHERE t.is_global AND m.is_cctor
              UNION ALL SELECT module, handle, full_name, 'static_constructor' FROM methods WHERE is_cctor AND type_name <> '<Module>'"),
        ("type_hierarchy", "Direct base type and interfaces of every type",
            @"SELECT handle AS type, full_name, base_type, base_type_name AS parent_name, 'base' AS relation FROM types WHERE base_type_name IS NOT NULL
              UNION ALL SELECT type, type_name, interface, interface_name, 'interface' FROM interfaces"),
        ("native_imports", "P/Invoke imports grouped by DLL",
            "SELECT dll, entry, count(*) AS method_count, group_concat(method_name, '; ') AS methods FROM pinvokes GROUP BY dll, entry"),
    };

    public const string Domain = "xrefs";

    public static void Register(Session s)
    {
        // The host creates the views and reports their columns back (Session.ViewColumns) for the catalog.
        foreach (var (name, _, sql) in All) s.Db.Exec($"CREATE VIEW \"{name}\" AS {sql}");
    }
}
