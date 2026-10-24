// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Tables;
using DnSpySql.Functions;

namespace DnSpySql;

/// <summary>Registers every table and function of the DnSpySql schema.</summary>
public static class Registry
{
    public static void RegisterAll(Session s)
    {
        MetaTables.Register(s);
        MemberTables.Register(s);
        RefTables.Register(s);
        CodeTables.Register(s);
        XrefTables.Register(s);
        PeTables.Register(s);
        PdbTables.Register(s);
        ResourceTables.Register(s);
        DecompilerTables.Register(s);
        SearchTables.Register(s);
        AnnotationTables.Register(s);
        BreakpointTables.Register(s);
        Views.Register(s);
        Legacy.Register(s);
        BundleTables.Register(s);
        DnSpyTables.Register(s);
        HexTables.Register(s);
        ImageTables.Register(s);
        ApiDocTables.Register(s);
        ProtectionTables.Register(s);
        TriageTables.Register(s);
        GuideTables.Register(s);

        CoreFunctions.Register(s);
        EditFunctions.Register(s);
        CompileFunctions.Register(s);
        DataFunctions.Register(s);
        DnSpyFunctions.Register(s);
        TriageFunctions.Register(s);

        foreach (var t in s.Db.Tables) t.Sink = s.Ws;

        // A read-only session (--readonly, or set_setting('read_only', 1)) refuses what changes the model, replays the
        // journal, records annotations or writes files beside the sample, not only the edits of the model: the annotation
        // tables already refuse their INSERTs, and these are the same writes as functions. Decompiling, export_project and
        // opening more modules stay allowed.
        s.Db.MarkMutating("undo", "redo", "save", "save_raw", "save_project", "set_comment", "tag", "dnspy_sync", "bp_set", "bp_trace",
            "bp_set_line", "bp_set_decompiled", "bp_toggle", "bp_enable", "bp_clear", "bp_module", "break_on_exception", "bp_export",
            "bp_import", "export_dnspy_breakpoints", "import_dnspy_breakpoints");

        // Handle-valued filter columns accept bare tokens and '0x..' text (0 stays 0: "external" in call_edges/xrefs). A column
        // declared with Table.Handle() is one already; the names below mark the older ones.
        s.Db.NormalizeHandle = v => v == 0 ? 0 : s.Ws.Normalize(v);
        foreach (var c in s.Db.Tables.SelectMany(t => t.Columns))
            if (c.Type == DnSpySql.Sql.SqlType.Integer && c.Pushdown != DnSpySql.Sql.Pushdown.None && HandleColumns.Contains(c.Name))
                c.IsHandle = true;
    }

    static readonly HashSet<string> HandleColumns = new()
    {
        "handle", "method", "type", "declaring_type", "owner", "referrer", "from_method", "to_def", "src", "dst", "target",
    };
}
