// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Functions;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using static DnSpySql.Tables.TableKit;
using static DnSpySql.Tables.AnnotationTables;

namespace DnSpySql.Tables;

/// <summary>
/// Breakpoint configuration, dnSpy style: code breakpoints/tracepoints, module breakpoints and exception settings.
/// Nothing is executed here; the configuration is stored in the project file and can be exported to (or imported from)
/// dnSpy's settings file so dnSpy picks it up.
/// </summary>
public static class BreakpointTables
{
    static readonly string[] ConditionKinds = { "IsTrue", "WhenChanged" };
    static readonly string[] HitCountKinds = { "Equals", "MultipleOf", "GreaterThanOrEquals" };

    public static void Register(Session s)
    {
        var db = s.Db;
        var ws = s.Ws;
        Func<ProjectStore> st = () => s.Store;

        // ================= code breakpoints / tracepoints =================
        var bps = new Table<BreakpointRec>("breakpoints",
            "Code breakpoints and tracepoints (dnSpy Breakpoints window): method + IL offset with condition, hit count, filter, " +
            "trace message and labels. Set with INSERT or bp_set/bp_set_line/bp_set_decompiled; export with export_dnspy_breakpoints()") { Domain = "breakpoints" };
        bps.Source(_ => st().Breakpoints.OrderBy(b => b.Id))
            .Keyed(x => x.Id, id => st().Breakpoints.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Int("method", x => HandleOf(s, x.At), doc: "method handle (NULL when its module is not loaded)")
            .Text("method_name", x => NameOf(s, x.At) ?? x.MethodName)
            .Int("module", x => HandleOf(s, x.At) is long h ? Handle.Module(h) : null)
            .Int("offset", x => x.At.Offset, Set<BreakpointRec>(s, (x, v) => x.At.Offset = (int)CheckOffset(s, x.At, Lng(v, "offset"))), doc: "IL offset (must be an instruction boundary)")
            .Int("idx", x => Instr(s, x) is var (md, i) && md != null ? md.Body.Instructions.IndexOf(i!) : null, doc: "instruction index (il.idx)")
            .Text("instruction", x => Instr(s, x) is var (md, i) && i != null ? $"IL_{i.Offset:X4}: {i.OpCode.Name} {BodyKit.OperandText(i, md!.Body)}".TrimEnd() : null)
            .Text("document", x => SeqPoint(s, x)?.Document?.Url)
            .Int("line", x => SeqPoint(s, x) is { } sp && sp.StartLine != 0xFEEFEE ? sp.StartLine : null, doc: "source line from the PDB")
            .Bool("enabled", x => x.Enabled, Set<BreakpointRec>(s, (x, v) => x.Enabled = Values.ToBool(v)))
            .Text("condition", x => x.Condition, Set<BreakpointRec>(s, (x, v) => x.Condition = Values.ToText(v) is { Length: > 0 } c ? c : null), doc: "C# expression evaluated by the debugger")
            .Text("condition_kind", x => x.ConditionKind, Set<BreakpointRec>(s, (x, v) => x.ConditionKind = Pick(ConditionKinds, v, "condition_kind")), doc: "IsTrue | WhenChanged")
            .Text("hit_count_kind", x => x.HitCountKind, Set<BreakpointRec>(s, (x, v) => x.HitCountKind = v == null ? null : Pick(HitCountKinds, v, "hit_count_kind")),
                doc: "NULL | Equals | MultipleOf | GreaterThanOrEquals")
            .Int("hit_count", x => x.HitCountKind == null ? null : x.HitCount, Set<BreakpointRec>(s, (x, v) => { x.HitCount = (int)Lng(v, "hit_count"); x.HitCountKind ??= "Equals"; }))
            .Text("filter", x => x.Filter, Set<BreakpointRec>(s, (x, v) => x.Filter = Values.ToText(v) is { Length: > 0 } f ? f : null),
                doc: "e.g. ProcessName == \"app.exe\" && ThreadName == \"worker\"")
            .Text("message", x => x.Message, Set<BreakpointRec>(s, (x, v) => x.Message = Values.ToText(v) is { Length: > 0 } m ? m : null),
                doc: "tracepoint message: $FUNCTION $CALLER $CALLSTACK $TID $TNAME $PID $PNAME $ADDRESS {expression}")
            .Bool("continue", x => x.Continue, Set<BreakpointRec>(s, (x, v) => x.Continue = Values.ToBool(v)), doc: "tracepoint keeps running (1) or also breaks (0)")
            .Bool("is_tracepoint", x => x.Message != null)
            .Text("labels", x => x.Labels, Set<BreakpointRec>(s, (x, v) => x.Labels = NormalizeLabels(Values.ToText(v))))
            .Text("status", x => Status(s, x), doc: "ok | module not loaded | method not found | method changed | not an instruction boundary")
            .Text("dnspy_module", x => x.DnSpyModule ?? ModuleOfBp(s, x)?.Path, Set<BreakpointRec>(s, (x, v) => x.DnSpyModule = Values.ToText(v) is { Length: > 0 } p ? p : null),
                doc: "module path written for dnSpy, which matches modules by full path: set it when dnSpy opens the file elsewhere (or pass module_dir to bp_export)");
        bps.OnInsert(v =>
        {
            var h = ws.HandleArg(v.GetValueOrDefault("method")) ?? throw new SqlException("method is required");
            var rec = SetBreakpoint(s, h, Values.ToLong(v.GetValueOrDefault("offset")), out var existed);
            if (!existed)
            {
                if (v.TryGetValue("enabled", out var en)) rec.Enabled = Values.ToBool(en);
                rec.Condition = Values.ToText(v.GetValueOrDefault("condition"));
                if (v.GetValueOrDefault("condition_kind") is { } ck) rec.ConditionKind = Pick(ConditionKinds, ck, "condition_kind");
                if (v.GetValueOrDefault("hit_count") is { } hc) { rec.HitCount = (int)Lng(hc, "hit_count"); rec.HitCountKind = "Equals"; }
                if (v.GetValueOrDefault("hit_count_kind") is { } hk) rec.HitCountKind = Pick(HitCountKinds, hk, "hit_count_kind");
                rec.Filter = Values.ToText(v.GetValueOrDefault("filter"));
                rec.Message = Values.ToText(v.GetValueOrDefault("message"));
                if (v.TryGetValue("continue", out var co)) rec.Continue = Values.ToBool(co);
                rec.Labels = NormalizeLabels(Values.ToText(v.GetValueOrDefault("labels")));
                st().Changed();
            }
            return (rec.Id, null, null);
        }).OnDelete(x => { st().Breakpoints.Remove(x); st().Changed(); ListUndo(s, "breakpoints", st().Breakpoints, x, false); return (null, null); });
        db.Register(bps);

        // ================= module breakpoints =================
        var mbps = new Table<ModuleBreakpointRec>("module_breakpoints",
            "dnSpy module breakpoints: break when a module matching module_name (wildcards) is loaded/unloaded") { Domain = "breakpoints" };
        mbps.Source(_ => st().ModuleBreakpoints.OrderBy(b => b.Id))
            .Keyed(x => x.Id, id => st().ModuleBreakpoints.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Bool("enabled", x => x.Enabled, Set<ModuleBreakpointRec>(s, (x, v) => x.Enabled = Values.ToBool(v)))
            .Text("module_name", x => x.ModuleName, Set<ModuleBreakpointRec>(s, (x, v) => x.ModuleName = Values.ToText(v)), doc: "file name or path pattern, * and ? wildcards")
            .Int("is_dynamic", x => B(x.IsDynamic), Set<ModuleBreakpointRec>(s, (x, v) => x.IsDynamic = NB(v)), doc: "NULL = any")
            .Int("is_in_memory", x => B(x.IsInMemory), Set<ModuleBreakpointRec>(s, (x, v) => x.IsInMemory = NB(v)), doc: "NULL = any")
            .Int("on_load", x => B(x.IsLoaded), Set<ModuleBreakpointRec>(s, (x, v) => x.IsLoaded = NB(v)), doc: "1 = when loaded, 0 = when unloaded, NULL = both")
            .Int("load_order", x => x.Order, Set<ModuleBreakpointRec>(s, (x, v) => x.Order = v == null ? null : (int)Lng(v, "load_order")))
            .Text("appdomain_name", x => x.AppDomainName, Set<ModuleBreakpointRec>(s, (x, v) => x.AppDomainName = Values.ToText(v)))
            .Text("process_name", x => x.ProcessName, Set<ModuleBreakpointRec>(s, (x, v) => x.ProcessName = Values.ToText(v)))
            .Text("matches_loaded", x => x.ModuleName == null ? null : string.Join(", ", ws.Modules.Where(m => Wildcard(x.ModuleName, m.Path) || Wildcard(x.ModuleName, Path.GetFileName(m.Path))).Select(m => m.Id)),
                doc: "ids of loaded modules whose name matches the pattern");
        mbps.OnInsert(v =>
        {
            var rec = new ModuleBreakpointRec
            {
                Id = st().NewId(),
                Enabled = !v.TryGetValue("enabled", out var en) || Values.ToBool(en),
                ModuleName = Values.ToText(v.GetValueOrDefault("module_name")),
                IsDynamic = NB(v.GetValueOrDefault("is_dynamic")), IsInMemory = NB(v.GetValueOrDefault("is_in_memory")),
                IsLoaded = v.TryGetValue("on_load", out var ol) ? NB(ol) : true,
                Order = Values.ToLong(v.GetValueOrDefault("load_order")) is long o ? (int)o : null,
                AppDomainName = Values.ToText(v.GetValueOrDefault("appdomain_name")), ProcessName = Values.ToText(v.GetValueOrDefault("process_name")),
            };
            st().ModuleBreakpoints.Add(rec); st().Changed();
            ListUndo(s, "module_breakpoints", st().ModuleBreakpoints, rec, true);
            return (rec.Id, null, null);
        }).OnDelete(x => { st().ModuleBreakpoints.Remove(x); st().Changed(); ListUndo(s, "module_breakpoints", st().ModuleBreakpoints, x, false); return (null, null); });
        db.Register(mbps);

        // ================= exception settings =================
        var exs = new Table<ExceptionSettingRec>("exception_settings",
            "dnSpy Exception Settings: break on first/second chance per exception type, optional module conditions") { Domain = "breakpoints" };
        exs.Source(_ => st().ExceptionSettings.OrderBy(b => b.Category).ThenBy(b => b.Name))
            .Keyed(x => x.Id, id => st().ExceptionSettings.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Text("category", x => x.Category, doc: "DotNet | MDA")
            .Text("name", x => x.Name, doc: "exception type full name ('' = category default)")
            .Bool("stop_first_chance", x => x.StopFirstChance, Set<ExceptionSettingRec>(s, (x, v) => x.StopFirstChance = Values.ToBool(v)), doc: "break when thrown")
            .Bool("stop_second_chance", x => x.StopSecondChance, Set<ExceptionSettingRec>(s, (x, v) => x.StopSecondChance = Values.ToBool(v)), doc: "break when unhandled")
            .Text("conditions", x => x.Conditions, Set<ExceptionSettingRec>(s, (x, v) => x.Conditions = ParseConditions(Values.ToText(v))),
                doc: "'ModuleNameEquals:pattern; ModuleNameNotEquals:pattern' (all must hold)")
            .Text("description", x => x.Description, Set<ExceptionSettingRec>(s, (x, v) => x.Description = Values.ToText(v) ?? ""))
            .Bool("is_custom", x => x.IsCustom, Set<ExceptionSettingRec>(s, (x, v) => x.IsCustom = Values.ToBool(v)),
                doc: "1 = new entry for dnSpy (exported as Add), 0 = override of a dnSpy built-in entry (Update)")
            .Int("defined_in", x => ExceptionType(s, x.Name) is { } t ? ws.Find(t.Module)?.H(t) : null, doc: "type handle when the exception is defined in a loaded module")
            .Int("throw_sites", x => x.Name.Length == 0 ? null : ThrowSites(s, null).Count(t => t.type == x.Name), doc: "number of throw sites in loaded modules");
        exs.OnInsert(v =>
        {
            var rec = AddException(s, Str(v.GetValueOrDefault("name"), "name"), Values.ToText(v.GetValueOrDefault("category")) ?? "DotNet");
            ChangeException(s, rec, () =>
            {
                if (v.TryGetValue("stop_first_chance", out var f)) rec.StopFirstChance = Values.ToBool(f);
                if (v.TryGetValue("stop_second_chance", out var sc)) rec.StopSecondChance = Values.ToBool(sc);
                if (v.GetValueOrDefault("conditions") is { } c) rec.Conditions = ParseConditions(Values.ToText(c));
                if (v.GetValueOrDefault("description") is { } d) rec.Description = Values.ToText(d) ?? "";
                if (v.TryGetValue("is_custom", out var ic)) rec.IsCustom = Values.ToBool(ic);
            });
            return (rec.Id, null, null);
        }).OnDelete(x => { st().ExceptionSettings.Remove(x); st().Changed(); ListUndo(s, "exception_settings", st().ExceptionSettings, x, false); return (null, null); });
        db.Register(exs);

        // ================= throw sites (helps choosing exception breakpoints) =================
        db.Register(new Table<(LoadedModule m, MethodDef md, Instruction ins, string type)>("throw_sites",
                "Every throw/rethrow in loaded code with the exception type when it is constructed just before (newobj ... throw)") { Domain = "breakpoints" }
            .Source(c => ThrowSites(s, c))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.m.H(r.md), pushdown: Pushdown.Eq)
            .Text("method_name", r => r.md.FullName)
            .Int("offset", r => r.ins.Offset)
            .Text("opcode", r => r.ins.OpCode.Name)
            .Text("exception_type", r => r.type));

        RegisterFunctions(s);
    }

    // ------------------------------------------------------------------------------------------------ functions

    static void RegisterFunctions(Session s)
    {
        var ws = s.Ws;
        s.Fn("bp_set", 1, 3, a =>
        {
            // bp_set(token, offset, module) is the older DnSpySql form: an integer third argument names the module.
            var h = a.Length > 2 && a[2] is long mod ? Handle.Make((int)mod, (uint)Lng(a[0], "method"))
                : ws.HandleArg(a[0]) ?? throw new SqlException("method is required");
            var rec = SetBreakpoint(s, h, Values.ToLong(a.Arg(1)), out var existed);
            if (!existed && a.Arg(2) is string { Length: > 0 } cond) { rec.Condition = cond; s.Store.Changed(); }
            return rec.Id;
        }, "bp_set(method [, il_offset [, condition | module]])", "set a breakpoint (default: first instruction); returns its id (existing id when one is already there)", "breakpoints");

        s.Fn("bp_trace", 3, 4, a =>
        {
            var rec = SetBreakpoint(s, ws.HandleArg(a[0]) ?? throw new SqlException("method is required"), Values.ToLong(a[1]), out _);
            var (message, cont) = (Str(a[2], "message"), a.Length < 4 || Values.ToBool(a[3]));
            var (oldMessage, oldCont) = (rec.Message, rec.Continue);
            void Apply(string? m, bool c) { rec.Message = m; rec.Continue = c; s.Store.Changed(); }
            Apply(message, cont);
            ws.Record("breakpoints", "bp_trace", () => Apply(oldMessage, oldCont), () => Apply(message, cont));
            return rec.Id;
        }, "bp_trace(method, il_offset, message [, continue])", "set a tracepoint ($FUNCTION, $TID, {expr} ...)", "breakpoints");

        s.Fn("bp_set_line", 2, 3, a =>
        {
            var (h, off) = FromSourceLine(s, Str(a[0], "file"), (int)Lng(a[1], "line"));
            var rec = SetBreakpoint(s, h, off, out var existed);
            if (!existed && Values.ToText(a.Arg(2)) is { Length: > 0 } cond) { rec.Condition = cond; s.Store.Changed(); }
            return rec.Id;
        }, "bp_set_line(source_file, line [, condition])", "set a breakpoint on a source line (PDB sequence points; file name or path suffix)", "breakpoints");

        s.Fn("bp_set_decompiled", 2, 3, a =>
        {
            var (h, off) = FromDecompiledLine(s, Lng(a[0], "handle"), (int)Lng(a[1], "line_num"));
            var rec = SetBreakpoint(s, h, off, out var existed);
            if (!existed && Values.ToText(a.Arg(2)) is { Length: > 0 } cond) { rec.Condition = cond; s.Store.Changed(); }
            return rec.Id;
        }, "bp_set_decompiled(handle, line_num [, condition])",
            "set a breakpoint on a line of the decompiled C# of handle (pseudocode_lines.line_num), like clicking in dnSpy's margin", "breakpoints");

        s.Fn("bp_toggle", 1, 2, a =>
        {
            var h = ws.Normalize(ws.HandleArg(a[0]) ?? throw new SqlException("method is required"));
            var md = ws.Resolve<MethodDef>(h, "method");
            var at = Loc(s, h, CheckOffset(s, Loc(s, h, null), Values.ToLong(a.Arg(1)) ?? FirstOffset(md)));
            var hit = s.Store.Breakpoints.FirstOrDefault(b => Same(b.At, at));
            if (hit != null)
            {
                s.Store.Breakpoints.Remove(hit); s.Store.Changed();
                ListUndo(s, "breakpoints", s.Store.Breakpoints, hit, false);
                return 0L;
            }
            SetBreakpoint(s, h, at.Offset, out _);
            return 1L;
        }, "bp_toggle(method [, il_offset])", "add the breakpoint if absent, remove it if present; returns 1 (set) or 0 (removed)", "breakpoints");

        s.Fn("bp_enable", 1, 2, a =>
        {
            bool on = Values.ToBool(a[0]);
            var label = Values.ToText(a.Arg(1));
            var those = s.Store.Breakpoints.Where(b => label == null || HasLabel(b, label)).Select(b => (b, was: b.Enabled)).ToList();
            void Apply(bool undo) { foreach (var (b, was) in those) b.Enabled = undo ? was : on; s.Store.Changed(); }
            Apply(false);
            ws.Record("breakpoints", $"bp_enable({(on ? 1 : 0)})", () => Apply(true), () => Apply(false));
            return (long)those.Count;
        }, "bp_enable(on [, label])", "enable/disable all breakpoints (or those with a label); returns the count", "breakpoints");

        s.Fn("bp_clear", 0, 1, a =>
        {
            // An integer argument is a module id (older DnSpySql form), text a label.
            var mod = a.Arg(0) is long id ? ws.Get((int)id) : null;
            var label = mod == null ? Values.ToText(a.Arg(0)) : null;
            var victims = s.Store.Breakpoints.Where(b => (label == null || HasLabel(b, label)) && (mod == null || ModuleOfBp(s, b) == mod)).ToList();
            foreach (var b in victims) { s.Store.Breakpoints.Remove(b); ListUndo(s, "breakpoints", s.Store.Breakpoints, b, false); }
            s.Store.Changed();
            return (long)victims.Count;
        }, "bp_clear([label | module])", "delete all breakpoints (or those with a label, or of a module)", "breakpoints");

        s.Fn("bp_module", 1, 2, a =>
        {
            var pattern = Str(a[0], "module_name");
            bool? onLoad = a.Length > 1 ? NB(a[1]) : true;
            var hit = s.Store.ModuleBreakpoints.FirstOrDefault(b => string.Equals(b.ModuleName, pattern, StringComparison.OrdinalIgnoreCase) && b.IsLoaded == onLoad
                                                                    && b.IsDynamic == null && b.IsInMemory == null && b.Order == null && b.AppDomainName == null && b.ProcessName == null);
            if (hit != null) return hit.Id;
            var rec = new ModuleBreakpointRec { Id = s.Store.NewId(), ModuleName = pattern, IsLoaded = onLoad };
            s.Store.ModuleBreakpoints.Add(rec);
            s.Store.Changed();
            ListUndo(s, "module_breakpoints", s.Store.ModuleBreakpoints, rec, true);
            return rec.Id;
        }, "bp_module(module_name [, on_load])",
            "add a dnSpy module breakpoint: break when a matching module is loaded (on_load = 1, default), unloaded (0) or either (NULL); * and ? wildcards", "breakpoints");

        s.Fn("bp_patch", 0, 1, a => (long)PatchBreakpoints(s, ws.ModuleArg(a.Arg(0))),
            "bp_patch([module])",
            "write each enabled breakpoint of the module into its IL as `if (Debugger.IsAttached) Debugger.Break();` (any debugger stops there; save() to keep) " +
            "and remove them from the table; returns the count. Conditions, hit counts, filters and tracepoints need a debugger, so they are refused",
            "breakpoints", mutates: true);

        s.Fn("break_on_exception", 1, 3, a =>
        {
            var rec = AddException(s, Str(a[0], "type"), "DotNet");
            ChangeException(s, rec, () =>
            {
                rec.StopFirstChance = a.Length < 2 || Values.ToBool(a[1]);
                if (a.Length > 2) rec.StopSecondChance = Values.ToBool(a[2]);
            });
            return rec.Id;
        }, "break_on_exception(type_full_name [, first_chance = 1 [, second_chance]])", "configure dnSpy to break when the exception is thrown", "breakpoints");

        s.Fn("bp_export", 1, 3, a =>
            (long)DnSpySettings.Export(s, Path.GetFullPath(Str(a[0], "path")), a.Arg(1) == null ? null : ws.ModuleArg(a[1]), Values.ToText(a.Arg(2))),
            "bp_export(path [, module [, module_dir]])",
            "write breakpoints and bookmarks (of one module, or all), module breakpoints and exception settings in dnSpy's layout. An existing file such as dnSpy.xml is " +
            "merged into: entries at the same location as ours are replaced, everything else (including breakpoints and bookmarks set in dnSpy) is kept; close dnSpy " +
            "first. A new file can be imported in dnSpy's Breakpoints and Bookmarks windows. A bookmark's category becomes its dnSpy labels and its comment " +
            "follows the name after ' — '. module_dir is the directory dnSpy opens the modules from. Returns the count",
            "breakpoints");

        s.Fn("bp_import", 1, 1, a => (long)DnSpySettings.Import(s, Path.GetFullPath(Str(a[0], "path"))),
            "bp_import(path)", "read breakpoints and bookmarks (of loaded modules), module breakpoints and exception settings from dnSpy.xml or a dnSpy breakpoint/bookmark file", "breakpoints");

        s.Fn("export_dnspy_breakpoints", 1, 2, a =>
            (long)DnSpySettings.Export(s, Path.GetFullPath(Str(a[0], "path")), null, Values.ToText(a.Arg(1))),
            "export_dnspy_breakpoints(dnspy_xml_path [, module_dir])",
            "write breakpoints, bookmarks, module breakpoints and exception settings into dnSpy's settings file (dnSpy.xml; merged keeping dnSpy's own entries, close dnSpy first). " +
            "module_dir replaces the directory of module paths (where dnSpy will open the files). Returns the number of entries written", "breakpoints");

        s.Fn("import_dnspy_breakpoints", 1, 1, a => (long)DnSpySettings.Import(s, Path.GetFullPath(Str(a[0], "path"))),
            "import_dnspy_breakpoints(dnspy_xml_path)", "read breakpoints and bookmarks (for loaded modules), module breakpoints and exception settings from dnSpy.xml", "breakpoints");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    public static BreakpointRec SetBreakpoint(Session s, long handle, long? offset, out bool existed)
    {
        handle = s.Ws.Normalize(handle);
        var md = s.Ws.Resolve<MethodDef>(handle, "method");
        if (!md.HasBody) throw new SqlException($"{md.FullName} has no IL body; breakpoints need IL");
        var at = Loc(s, handle, null);
        at.Offset = (int)CheckOffset(s, at, offset ?? FirstOffset(md));
        var hit = s.Store.Breakpoints.FirstOrDefault(b => Same(b.At, at));
        existed = hit != null;
        if (hit != null) return hit;
        var rec = new BreakpointRec { Id = s.Store.NewId(), At = at, MethodName = md.FullName };
        s.Store.Breakpoints.Add(rec);
        s.Store.Changed();
        ListUndo(s, "breakpoints", s.Store.Breakpoints, rec, true);
        return rec;
    }

    /// <summary>The loaded module a breakpoint belongs to, or null.</summary>
    public static LoadedModule? ModuleOfBp(Session s, BreakpointRec b) => s.Ws.Modules.FirstOrDefault(m => ModuleKey(m) == b.At.Mvid);

    // bp_patch: `if (Debugger.IsAttached) Debugger.Break();` in front of each enabled breakpoint's instruction. Jumps and
    // exception-handler boundaries that pointed at that instruction move to the check, so the patched method runs as
    // before, but any debugger (dnSpy, Visual Studio, Rider, VS Code) stops there. A bare Break() would kill the
    // process when no debugger is attached. The breakpoints leave the table: their offsets shift once the IL grows.
    static int PatchBreakpoints(Session s, LoadedModule lm)
    {
        var bps = s.Store.Breakpoints.Where(b => b.Enabled && ModuleOfBp(s, b) == lm).ToList();
        var withSettings = bps.Where(b => b.Condition != null || b.HitCountKind != null || b.Filter != null || b.Message != null).Select(b => b.Id).ToList();
        if (withSettings.Count > 0)
            throw new SqlException($"breakpoints {string.Join(", ", withSettings)} have a condition, hit count, filter or trace message that only a " +
                                   "debugger can evaluate; export them with bp_export() or clear those columns first");

        // Resolve every location before inserting anything: offsets are relative to the bodies as they are now.
        var targets = new List<(BreakpointRec bp, MethodDef md, Instruction at)>();
        foreach (var b in bps)
        {
            var (md, ins) = Instr(s, b);
            if (md == null || ins == null) throw new SqlException($"breakpoint {b.Id}: {Status(s, b)}");
            targets.Add((b, md, ins));
        }
        var methods = targets.Select(t => t.md).Distinct().ToList();
        var before = methods.Select(m => new BodySnapshot(m)).ToList();

        var mod = lm.Module;
        var debugger = new TypeRefUser(mod, "System.Diagnostics", "Debugger", mod.CorLibTypes.AssemblyRef);
        var isAttached = new MemberRefUser(mod, "get_IsAttached", MethodSig.CreateStatic(mod.CorLibTypes.Boolean), debugger);
        var brk = new MemberRefUser(mod, "Break", MethodSig.CreateStatic(mod.CorLibTypes.Void), debugger);
        foreach (var (_, md, at) in targets)
        {
            var check = Instruction.Create(OpCodes.Call, isAttached);
            IlEdit.InsertBefore(md.Body, at, check); // redirects jumps and handler boundaries from `at` to `check`
            int i = md.Body.Instructions.IndexOf(check);
            md.Body.Instructions.Insert(i + 1, Instruction.Create(OpCodes.Brfalse_S, at));
            md.Body.Instructions.Insert(i + 2, Instruction.Create(OpCodes.Call, brk));
        }
        foreach (var md in methods)
        {
            md.Body.UpdateInstructionOffsets();
            md.Body.OptimizeBranches();
        }
        var after = methods.Select(m => new BodySnapshot(m)).ToList();
        foreach (var (b, _, _) in targets) s.Store.Breakpoints.Remove(b);
        s.Store.Changed();
        var removed = targets.Select(t => t.bp).ToList();
        if (targets.Count > 0)
        {
            s.Ws.Touch(lm);
            s.Ws.Record("breakpoints", $"bp_patch {targets.Count} breakpoint(s)",
                () => { foreach (var x in before) x.Restore(); s.Store.Breakpoints.AddRange(removed); s.Store.Changed(); s.Ws.Touch(lm); },
                () => { foreach (var x in after) x.Restore(); foreach (var b in removed) s.Store.Breakpoints.Remove(b); s.Store.Changed(); s.Ws.Touch(lm); });
        }
        return targets.Count;
    }

    static uint FirstOffset(MethodDef md) => md.Body.Instructions.Count > 0 ? md.Body.Instructions[0].Offset : 0;

    static long CheckOffset(Session s, AnnLocation at, long offset)
    {
        if (HandleOf(s, at) is not long h || s.Ws.Resolve(h).item is not MethodDef { HasBody: true } md)
            throw new SqlException("breakpoint method is not loaded");
        if (!md.Body.Instructions.Any(i => i.Offset == offset))
            throw new SqlException($"IL offset 0x{offset:X} is not an instruction boundary of {md.FullName} (see il.offset)");
        return offset;
    }

    static bool Same(AnnLocation a, AnnLocation b) => a.Mvid == b.Mvid && a.Token == b.Token && a.Offset == b.Offset;

    static (MethodDef? md, Instruction? ins) Instr(Session s, BreakpointRec b)
    {
        if (HandleOf(s, b.At) is not long h) return (null, null);
        try
        {
            if (s.Ws.Resolve(h).item is MethodDef { HasBody: true } md)
                return (md, md.Body.Instructions.FirstOrDefault(i => i.Offset == b.At.Offset));
        }
        catch (SqlException) { }
        return (null, null);
    }

    static dnlib.DotNet.Pdb.SequencePoint? SeqPoint(Session s, BreakpointRec b)
    {
        var (md, ins) = Instr(s, b);
        if (md == null || ins == null) return null;
        var idx = md.Body.Instructions.IndexOf(ins);
        for (int i = idx; i >= 0; i--) if (md.Body.Instructions[i].SequencePoint is { } sp) return sp;
        return null;
    }

    static string Status(Session s, BreakpointRec b)
    {
        if (!s.Ws.Modules.Any(m => ModuleKey(m) == b.At.Mvid)) return "module not loaded";
        var (md, ins) = Instr(s, b);
        if (md == null) return "method not found";
        if (b.MethodName != null && md.FullName != b.MethodName) return $"method changed (was {b.MethodName})";
        if (ins == null) return "not an instruction boundary";
        return "ok";
    }

    static string Pick(string[] allowed, object? v, string what)
    {
        var t = Values.ToText(v)?.Replace("_", "") ?? "";
        return allowed.FirstOrDefault(a => a.Equals(t, StringComparison.OrdinalIgnoreCase))
               ?? throw new SqlException($"{what} must be one of {string.Join(", ", allowed)}");
    }

    static string NormalizeLabels(string? s) =>
        string.Join(", ", (s ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct());

    static bool HasLabel(BreakpointRec b, string label) =>
        b.Labels.Split(',', StringSplitOptions.TrimEntries).Contains(label, StringComparer.OrdinalIgnoreCase);

    static long? B(bool? b) => b == null ? null : b.Value ? 1 : 0;
    static bool? NB(object? v) => v == null ? null : Values.ToBool(v);

    public static bool Wildcard(string pattern, string text)
    {
        var re = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(text, re, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    public static string ParseConditions(string? text)
    {
        var parts = new List<string>();
        foreach (var p in (text ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kv = p.Split(':', 2, StringSplitOptions.TrimEntries);
            if (kv.Length != 2 || kv[1].Length == 0) throw new SqlException($"bad condition '{p}' (use ModuleNameEquals:pattern or ModuleNameNotEquals:pattern)");
            var kind = kv[0].Replace("_", "").ToLowerInvariant() switch
            {
                "modulenameequals" or "module" or "=" => "ModuleNameEquals",
                "modulenamenotequals" or "notmodule" or "!=" => "ModuleNameNotEquals",
                _ => throw new SqlException($"unknown condition type '{kv[0]}' (ModuleNameEquals | ModuleNameNotEquals)"),
            };
            parts.Add($"{kind}:{kv[1]}");
        }
        return string.Join("; ", parts);
    }

    // Changes an exception setting and journals the change (a new one is journaled as an insert by AddException; its
    // undo removes the record, so this entry only matters for one that already existed).
    static void ChangeException(Session s, ExceptionSettingRec rec, Action change)
    {
        static (bool, bool, string, string, bool) Get(ExceptionSettingRec r) => (r.StopFirstChance, r.StopSecondChance, r.Conditions, r.Description, r.IsCustom);
        void Set((bool first, bool second, string conditions, string description, bool custom) v)
        {
            (rec.StopFirstChance, rec.StopSecondChance, rec.Conditions, rec.Description, rec.IsCustom) = v;
            s.Store.Changed();
        }
        var before = Get(rec);
        change();
        var after = Get(rec);
        s.Store.Changed();
        if (after != before) s.Ws.Record("exception_settings", $"exception setting {rec.Name}", () => Set(before), () => Set(after));
    }

    static ExceptionSettingRec AddException(Session s, string name, string category)
    {
        if (category is not ("DotNet" or "MDA")) throw new SqlException("category must be DotNet or MDA");
        var rec = s.Store.ExceptionSettings.FirstOrDefault(x => x.Category == category && x.Name == name);
        if (rec != null) return rec;
        var t = ExceptionType(s, name);
        rec = new ExceptionSettingRec
        {
            Id = s.Store.NewId(), Category = category, Name = name,
            // Types defined in the analysed (non-framework) modules are not in dnSpy's built-in list.
            IsCustom = t != null && !IsFramework(t.Module),
        };
        s.Store.ExceptionSettings.Add(rec);
        s.Store.Changed();
        ListUndo(s, "exception_settings", s.Store.ExceptionSettings, rec, true);
        return rec;
    }

    static bool IsFramework(ModuleDef m) =>
        m.Assembly?.PublicKeyToken?.ToString() is "b77a5c561934e089" or "b03f5f7f11d50a3a" or "31bf3856ad364e35" or "cc7b13ffcd2ddd51" or "7cec85d7bea7798e";

    static TypeDef? ExceptionType(Session s, string name)
    {
        if (name.Length == 0) return null;
        foreach (var m in s.Ws.Modules)
            if (m.Module.Find(name, false) is TypeDef t) return t;
        return null;
    }

    static IEnumerable<(LoadedModule m, MethodDef md, Instruction ins, string type)> ThrowSites(Session s, Constraints? c)
    {
        IEnumerable<Row<MethodDef>> methods = c != null ? MemberTables.MethodScope(s.Ws, c) : s.Ws.Modules.SelectMany(m => m.Module.GetTypes().SelectMany(t => t.Methods).Select(x => new Row<MethodDef>(m, x)));
        foreach (var r in methods)
        {
            if (!r.Item.HasBody) continue;
            var il = r.Item.Body.Instructions;
            for (int i = 0; i < il.Count; i++)
            {
                if (il[i].OpCode.Code == Code.Rethrow) { yield return (r.M, r.Item, il[i], "(rethrow)"); continue; }
                if (il[i].OpCode.Code != Code.Throw) continue;
                string type = "(unknown)";
                for (int k = i - 1; k >= Math.Max(0, i - 3); k--)
                    // a MemberRef with a broken parent (obfuscators) has no declaring type
                    if (il[k].OpCode.Code == Code.Newobj && il[k].Operand is IMethod ctor) { type = ctor.DeclaringType?.FullName ?? type; break; }
                yield return (r.M, r.Item, il[i], type);
            }
        }
    }

    /// <summary>Source line → (method, IL offset) using PDB sequence points.</summary>
    static (long handle, long offset) FromSourceLine(Session s, string file, int line)
    {
        var want = file.Replace('\\', '/');
        (long h, long off, int dist)? best = null;
        foreach (var m in s.Ws.Modules.Where(m => m.Module.PdbState != null))
            foreach (var md in m.Module.GetTypes().SelectMany(t => t.Methods).Where(x => x.HasBody))
                foreach (var ins in md.Body.Instructions)
                {
                    var sp = ins.SequencePoint;
                    if (sp == null || sp.StartLine == 0xFEEFEE || sp.Document == null) continue;
                    var url = sp.Document.Url.Replace('\\', '/');
                    if (!url.EndsWith(want, StringComparison.OrdinalIgnoreCase) || url.Length > want.Length && url[url.Length - want.Length - 1] != '/') continue;
                    int dist = line >= sp.StartLine && line <= sp.EndLine ? 0 : sp.StartLine > line ? sp.StartLine - line : int.MaxValue;
                    if (dist == int.MaxValue) continue;
                    if (best == null || dist < best.Value.dist) best = (m.H(md), ins.Offset, dist);
                }
        if (best == null) throw new SqlException($"no code at {file}:{line} (needs a PDB with sequence points; see pdb_documents)");
        return (best.Value.h, best.Value.off);
    }

    /// <summary>Decompiled C# line → (method, IL offset), using the statement on that line or the next one.</summary>
    static (long handle, long offset) FromDecompiledLine(Session s, long handle, int lineNum)
    {
        var r = s.Decompiler.Decompile(s.Ws.Normalize(handle), "csharp");
        foreach (var l in r.Lines.Where(l => l.Line >= lineNum).OrderBy(l => l.Line))
            if (l.ILOffset is int off && l.Method is long mh) return (mh, off);
        throw new SqlException($"no statement at or after decompiled line {lineNum} (see pseudocode_lines.il_offset)");
    }
}
