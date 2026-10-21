// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Xml.Linq;
using DnSpySql.Sql;
using dnlib.DotNet;
using static DnSpySql.Tables.AnnotationTables;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>
/// dnSpy's own state in its settings file (dnSpy.xml, runtime setting dnspy_xml): debugger settings, Watch-window
/// expressions, the files it opens at startup and the tabs it last showed. What DnSpySql sets here is kept in the
/// project file and merged into dnSpy.xml like breakpoints (DnSpySettings.Export, after every changing statement).
/// </summary>
public static class DnSpyTables
{
    sealed record DbgSetting(int Index, string Name, bool Default, string Doc);

    // dnSpyEx DebuggerSettingsBase (Extensions/dnSpy.Debugger/dnSpy.Debugger/Settings/DebuggerSettingsImpl.cs): property
    // names (the attribute names in dnSpy.xml) and field initializers (the defaults).
    static readonly DbgSetting[] Debugger = new (string name, bool def, string doc)[]
    {
        ("UseHexadecimal", true, "show numbers in hex"),
        ("UseDigitSeparators", false, ""),
        ("SyntaxHighlight", true, ""),
        ("AutoOpenLocalsWindow", true, ""),
        ("UseMemoryModules", false, "debug modules as loaded in memory (unpacked/decrypted bodies) instead of the files"),
        ("PropertyEvalAndFunctionCalls", true, "evaluate properties and call functions in Locals/Watch (runs code of the debuggee)"),
        ("UseStringConversionFunction", true, "call ToString() for display (runs code of the debuggee)"),
        ("PreventManagedDebuggerDetection", true, "anti-anti-debug: Debugger.IsAttached / IsLogging report no debugger"),
        ("AntiIsDebuggerPresent", true, "anti-anti-debug: kernel32!IsDebuggerPresent returns false"),
        ("AntiCheckRemoteDebuggerPresent", true, "anti-anti-debug: kernel32!CheckRemoteDebuggerPresent reports no debugger"),
        ("AntiNtRaiseHardError", false, "anti-anti-debug: block ntdll!NtRaiseHardError (BSOD tricks)"),
        ("AntiCloseHandle", true, "anti-anti-debug: CloseHandle on an invalid handle does not raise"),
        ("IgnoreBreakInstructions", false, "ignore Debugger.Break() and int3: when on, bp_patch breakpoints never stop"),
        ("BreakAllProcesses", true, ""),
        ("EnableManagedDebuggingAssistants", true, ""),
        ("EnableJustMyCodeDebugging", false, ""),
        ("StepOverCodeInSystemModules", false, ""),
        ("OnlyStepIntoCodeInPrimaryModule", false, ""),
        ("HighlightChangedVariables", true, ""),
        ("ShowRawStructureOfObjects", false, ""),
        ("SortParameters", false, ""),
        ("SortLocals", false, ""),
        ("GroupParametersAndLocalsTogether", false, ""),
        ("ShowCompilerGeneratedVariables", false, ""),
        ("ShowDecompilerGeneratedVariables", true, ""),
        ("HideCompilerGeneratedMembers", true, ""),
        ("RespectHideMemberAttributes", true, ""),
        ("HideDeprecatedError", false, ""),
        ("SuppressJITOptimization_SystemModules", true, ""),
        ("SuppressJITOptimization_ProgramModules", true, "keep the debuggee's code unoptimized so locals stay visible"),
        ("FocusActiveProcess", true, ""),
        ("FocusDebuggerWhenProcessBreaks", true, ""),
        ("ShowReturnValues", true, ""),
        ("RedirectGuiConsoleOutput", true, ""),
        ("ShowOnlyPublicMembers", false, ""),
        ("ShowRawLocals", false, ""),
        ("AsyncDebugging", true, ""),
        ("StepOverPropertiesAndOperators", true, ""),
        ("IgnoreUnhandledExceptions", false, "do not break on unhandled exceptions"),
        ("FullString", false, ""),
    }.Select((x, i) => new DbgSetting(i, x.name, x.def, x.doc)).ToArray();

    sealed record WatchRow(long Key, WatchRec? Rec, int Window, string Expression, bool InDnSpy);
    sealed record DocRow(long Key, DocumentRec? Rec, string List, string Path, bool IsCurrent, bool InDnSpy);
    sealed record TabRow(string Window, int Group, int Index, string Path, string? Node, string? File, string? Content);

    public static void Register(Session s)
    {
        var db = s.Db;
        var st = () => s.Store;
        XElement? Section(Guid g) => DnSpySettings.ReadSection(s.DnSpy.SettingsPath(), g);
        static IEnumerable<XElement> Sub(XElement? e, string name) => e == null ? [] : DnSpySettings.Sections(e, name);
        static string? A(XElement e, string n) => DnSpySettings.A(e, n);

        // ---- debugger settings ----
        bool? FileValue(DbgSetting d) => Section(DnSpySettings.DebuggerSettingsGuid) is { } sec && A(sec, d.Name) is string v && bool.TryParse(v, out var b) ? b : null;
        void SetOverride(DbgSetting d, bool? v)
        {
            bool? old = st().DebuggerSettings.TryGetValue(d.Name, out var o) ? o : null;
            void Apply(bool? x) { if (x is bool b) st().DebuggerSettings[d.Name] = b; else st().DebuggerSettings.Remove(d.Name); st().Changed(); }
            Apply(v);
            s.Ws.Record("dnspy_debugger_settings", $"dnSpy debugger setting {d.Name}", () => Apply(old), () => Apply(v));
        }
        // SetOverride journals the override itself (the generic UPDATE journal would replay the effective value as an override)
        db.Register(new Table<DbgSetting>("dnspy_debugger_settings",
                "dnSpy's debugger settings (Options > Debugger), including its anti-anti-debug protections. UPDATE value to have DnSpySql " +
                "set one in dnSpy.xml (NULL returns it to dnSpy's own value)") { Domain = "dnspy", JournalUpdates = false }
            .Source(_ => Debugger)
            .Keyed(d => d.Index, i => i >= 0 && i < Debugger.Length ? Debugger[i] : null)
            .Text("name", d => d.Name, pushdown: Pushdown.Eq)
            .Int("value", d => (st().DebuggerSettings.TryGetValue(d.Name, out var o) ? o : FileValue(d) ?? d.Default) ? 1L : 0L,
                (d, v) => SetOverride(d, v == null ? null : Values.ToBool(v)), doc: "what dnSpy will use: DnSpySql's value, else dnSpy.xml's, else the default")
            .Int("dnspysql_value", d => st().DebuggerSettings.TryGetValue(d.Name, out var o) ? (o ? 1L : 0L) : null, doc: "value DnSpySql sets (NULL = not set)")
            .Int("dnspy_value", d => FileValue(d) is bool b ? (b ? 1L : 0L) : null, doc: "value in dnSpy.xml (NULL = dnSpy's default)")
            .Bool("default_value", d => d.Default)
            .Text("description", d => d.Doc)
            .Estimate(40));

        // ---- Watch windows ----
        List<WatchRow> WatchRows()
        {
            var file = Sub(Section(DnSpySettings.WatchGuid), "Watch")
                .SelectMany(w => Sub(w, "Expression").Select(e => (window: int.TryParse(A(w, "Index"), out var i) ? i : -1, expr: A(e, "Value") ?? "")))
                .ToList();
            var rows = st().Watch.OrderBy(x => x.Id)
                .Select(x => new WatchRow(x.Id, x, x.Window, x.Expression, file.Contains((x.Window, x.Expression)))).ToList();
            rows.AddRange(file.Where(f => !st().Watch.Any(x => x.Window == f.window && x.Expression == f.expr))
                .Select((f, i) => new WatchRow(-(i + 1), null, f.window, f.expr, true)));
            return rows;
        }
        db.Register(new Table<WatchRow>("dnspy_watch",
                "Expressions in dnSpy's Watch windows (0-3 = Watch 1-4). INSERT adds one for the analyst's next debugging session; " +
                "rows dnSpy already has are listed with dnspysql = 0") { Domain = "dnspy" }
            .Source(_ => WatchRows())
            .Keyed(r => r.Key, k => WatchRows().FirstOrDefault(r => r.Key == k))
            .Int("window", r => r.Window, (r, v) => { if (r.Rec == null) throw new SqlException("only rows DnSpySql added can be changed"); r.Rec.Window = Window(v); st().Changed(); })
            .Text("expression", r => r.Expression, (r, v) => { if (r.Rec == null) throw new SqlException("only rows DnSpySql added can be changed"); r.Rec.Expression = Str(v, "expression"); st().Changed(); })
            .Bool("dnspysql", r => r.Rec != null, doc: "added by DnSpySql (1) or already in dnSpy.xml (0)")
            .Bool("in_dnspy", r => r.InDnSpy, doc: "present in dnSpy.xml")
            .OnInsert(v =>
            {
                var rec = new WatchRec { Id = st().NewId(), Window = v.GetValueOrDefault("window") is { } w ? Window(w) : 0, Expression = Str(v.GetValueOrDefault("expression"), "expression") };
                st().Watch.Add(rec); st().Changed();
                ListUndo(s, "dnspy_watch", st().Watch, rec, true);
                return (rec.Id, null, null);
            })
            .OnDelete(r =>
            {
                if (r.Rec == null) throw new SqlException("this expression is dnSpy's own; remove it in dnSpy's Watch window");
                st().Watch.Remove(r.Rec); st().Changed(); ListUndo(s, "dnspy_watch", st().Watch, r.Rec, false);
                return (null, null);
            })
            .Estimate(10));

        // ---- the files dnSpy opens at startup ----
        List<DocRow> DocRows()
        {
            var lists = Sub(Section(DnSpySettings.DocumentTabsGuid), "FileLists").FirstOrDefault();
            var current = lists == null ? null : A(lists, "name");
            var file = Sub(lists, "FileList").SelectMany(l => Sub(l, "File").Select(f => (list: A(l, "name") ?? "", path: A(f, "name") ?? ""))).ToList();
            var currentList = current ?? file.Select(f => f.list).FirstOrDefault() ?? DnSpySettings.DefaultDocumentList;
            var rows = st().Documents.OrderBy(d => d.Id).Select(d => new DocRow(d.Id, d, currentList, d.Path, true,
                file.Any(f => f.list == currentList && string.Equals(f.path, d.Path, StringComparison.OrdinalIgnoreCase)))).ToList();
            rows.AddRange(file.Where(f => !st().Documents.Any(d => f.list == currentList && string.Equals(f.path, d.Path, StringComparison.OrdinalIgnoreCase)))
                .Select((f, i) => new DocRow(-(i + 1), null, f.list, f.path, f.list == currentList, true)));
            return rows;
        }
        db.Register(new Table<DocRow>("dnspy_documents",
                "The assemblies dnSpy opens at startup (its document lists). save() adds the annotated copy; INSERT (path) adds a file; " +
                "rows dnSpy already has show what the analyst had open") { Domain = "dnspy" }
            .Source(_ => DocRows())
            .Keyed(r => r.Key, k => DocRows().FirstOrDefault(r => r.Key == k))
            .Text("list", r => r.List, doc: "document list name; DnSpySql adds to the current one")
            .Text("path", r => r.Path)
            .Bool("is_current_list", r => r.IsCurrent, doc: "in the list dnSpy opens at startup")
            .Bool("dnspysql", r => r.Rec != null, doc: "added by DnSpySql (1) or already in dnSpy.xml (0)")
            .Bool("in_dnspy", r => r.InDnSpy, doc: "present in dnSpy.xml")
            .Bool("file_exists", r => File.Exists(r.Path))
            .Int("module", r => s.Ws.Modules.FirstOrDefault(m => string.Equals(m.Path, r.Path, StringComparison.OrdinalIgnoreCase))?.Id, doc: "loaded module with this path, if any")
            .OnInsert(v =>
            {
                var rec = new DocumentRec { Id = st().NewId(), Path = Path.GetFullPath(Str(v.GetValueOrDefault("path"), "path")) };
                st().Documents.Add(rec); st().Changed();
                ListUndo(s, "dnspy_documents", st().Documents, rec, true);
                return (rec.Id, null, null);
            })
            .OnDelete(r =>
            {
                if (r.Rec == null) throw new SqlException("this file is in dnSpy's own list; close it in dnSpy");
                st().Documents.Remove(r.Rec); st().Changed(); ListUndo(s, "dnspy_documents", st().Documents, r.Rec, false);
                return (null, null);
            })
            .Estimate(10));

        // ---- the tabs dnSpy showed when it last exited ----
        IEnumerable<TabRow> TabRows()
        {
            foreach (var tgw in Sub(Section(DnSpySettings.DocumentTabsGuid), "TabGroupWindow"))
                foreach (var tg in Sub(tgw, "TabGroup"))
                    foreach (var tab in Sub(tg, "Tab"))
                    {
                        var names = Sub(Sub(tab, "Path").FirstOrDefault(), "Name").Select(n => A(n, "name")).Where(n => !string.IsNullOrEmpty(n)).ToList();
                        yield return new TabRow(A(tgw, "name") ?? "Main", int.TryParse(A(tg, "index"), out var g) ? g : 0, int.TryParse(A(tab, "index"), out var i) ? i : 0,
                            string.Join(" > ", names), names.LastOrDefault(), Sub(tab, "File").Select(f => A(f, "name")).FirstOrDefault(),
                            Sub(tab, "Content").Select(c => A(c, "_g_")).FirstOrDefault());
                    }
        }
        db.Register(new Table<TabRow>("dnspy_tabs",
                "The tabs dnSpy showed when it last exited (dnSpy writes dnSpy.xml on exit): the Assembly Explorer path of each and, " +
                "when it is a member of a loaded module, its handle") { Domain = "dnspy" }
            .Source(_ => TabRows())
            .Text("window", r => r.Window)
            .Int("tab_group", r => r.Group)
            .Int("tab_index", r => r.Index)
            .Text("path", r => r.Path, doc: "Assembly Explorer nodes, outermost first")
            .Text("node", r => r.Node, doc: "the node the tab shows (a member's full name, a type as namespace.name)")
            .Int("target", r => r.Node is { } n ? FindNode(s, n) : null, doc: "handle of that type or member when it is in a loaded module")
            .Text("file", r => r.File, doc: "file dnSpy loads for the tab")
            .Text("content", r => r.Content, doc: "dnSpy content-provider id (decompiler, hex, ...)")
            .Estimate(10));
    }

    static int Window(object? v) => (int)(Values.ToLong(v) is long w and >= 0 and <= 3 ? w : throw new SqlException("window must be 0-3 (dnSpy's Watch 1-4)"));

    // A tab's last path name: dnSpy names member nodes by their full name and type nodes "namespace.name".
    static long? FindNode(Session s, string name)
    {
        foreach (var lm in s.Ws.Modules)
            foreach (var t in lm.Module.GetTypes())
            {
                if (t.Namespace + "." + t.Name == name) return lm.H(t);
                foreach (var m in t.Methods) if (m.FullName == name) return lm.H(m);
                foreach (var f in t.Fields) if (f.FullName == name) return lm.H(f);
                foreach (var p in t.Properties) if (p.FullName == name) return lm.H(p);
                foreach (var e in t.Events) if (e.FullName == name) return lm.H(e);
            }
        return null;
    }
}
