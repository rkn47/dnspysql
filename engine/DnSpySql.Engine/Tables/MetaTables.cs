// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.PE;
using ComImageFlags = dnlib.DotNet.MD.ComImageFlags;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>Session, catalog and assembly/module-level tables.</summary>
public static class MetaTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        // ---- binary: canonical key/value summary shared with idasql/ghidrasql ----
        db.Register(new Table<KeyValuePair<string, (object? value, string type)>>("binary",
                "Key/value summary of the session's primary module (canonical keys)") { Domain = "meta" }
            .Source(c => BinaryRows(s))
            .Text("key", r => r.Key, pushdown: Pushdown.Eq)
            .Col("value", SqlType.Any, r => r.Value.value)
            .Text("type", r => r.Value.type));

        // ---- modules ----
        var modules = new Table<LoadedModule>("modules", "Loaded modules (one row per assembly/netmodule file)") { Domain = "meta" };
        modules.Source(c => c.Long("id") is long id ? ws.Modules.Where(m => m.Id == id) : ws.Modules)
            .Keyed(m => m.Id, id => ws.Modules.FirstOrDefault(m => m.Id == id))
            .Int("id", m => m.Id, pushdown: Pushdown.Unique)
            .Text("path", m => m.Path)
            .Text("file_name", m => Path.GetFileName(m.Path))
            .Text("name", m => m.Module.Name.String, s.Setter<LoadedModule>((m, v) => m.Module.Name = Str(v, "name")), doc: "module name (ModuleDef.Name)")
            .Text("assembly", m => m.Module.Assembly?.Name.String)
            .Text("assembly_version", m => m.Module.Assembly?.Version.ToString())
            .Text("assembly_full_name", m => m.Module.Assembly?.FullName)
            .Text("mvid", m => m.Module.Mvid?.ToString(), s.Setter<LoadedModule>((m, v) => m.Module.Mvid = v == null ? null : Guid.Parse(Str(v, "mvid"))))
            .Text("kind", m => m.Module.Kind.ToString().ToLowerInvariant(), s.Setter<LoadedModule>((m, v) => SetKind(m.Module, Str(v, "kind"))),
                doc: "console | windows | dll | netmodule")
            .Text("runtime_version", m => m.Module.RuntimeVersion, s.Setter<LoadedModule>((m, v) => m.Module.RuntimeVersion = Str(v, "runtime_version")))
            .Text("target_framework", m => TargetFramework(m.Module))
            .Text("platform", m => Platform(m.Module))
            .Text("machine", m => m.Module.Machine.ToString(), s.Setter<LoadedModule>((m, v) => m.Module.Machine = Enum.Parse<Machine>(Str(v, "machine"), true)))
            .Int("bits", m => m.Module.Machine is Machine.AMD64 or Machine.IA64 or Machine.ARM64 ? 64 : m.Module.Is32BitRequired ? 32 : (m.Module.Machine == Machine.I386 && !m.Module.Is32BitRequired && !m.Module.Is32BitPreferred ? 0 : 32),
                doc: "0 = AnyCPU")
            .Bool("is_il_only", m => m.Module.IsILOnly)
            .Bool("is_mixed_mode", m => m.IsMixedMode, doc: "C++/CLI image with native code")
            .Bool("is_ready_to_run", m => m.IsReadyToRun, doc: "ReadyToRun (crossgen) image: IL + precompiled native code")
            .Bool("is_32bit_required", m => m.Module.Is32BitRequired)
            .Bool("is_32bit_preferred", m => m.Module.Is32BitPreferred)
            .Bool("is_strong_name_signed", m => m.Module.IsStrongNameSigned)
            .Int("cor20_flags", m => (long)m.Module.Cor20HeaderFlags, s.Setter<LoadedModule>((m, v) => m.Module.Cor20HeaderFlags = (ComImageFlags)Lng(v, "cor20_flags")))
            .Int("characteristics", m => (long)m.Module.Characteristics, s.Setter<LoadedModule>((m, v) => m.Module.Characteristics = (Characteristics)Lng(v, "characteristics")))
            .Int("dll_characteristics", m => (long)m.Module.DllCharacteristics, s.Setter<LoadedModule>((m, v) => m.Module.DllCharacteristics = (DllCharacteristics)Lng(v, "dll_characteristics")))
            .Int("entry_point", m => m.Module.ManagedEntryPoint is IMDTokenProvider ep ? m.H(ep) : null,
                s.Setter<LoadedModule>((m, v) => SetEntryPoint(ws, m, v)), doc: "handle of the managed entry point (UPDATE to change, NULL clears)")
            .Text("entry_point_name", m => (m.Module.ManagedEntryPoint as IFullName)?.FullName)
            .Int("native_entry_rva", m => (long)(uint)m.Module.NativeEntryPoint)
            .Bool("has_pdb", m => m.Module.PdbState != null)
            .Int("timestamp", m => (long)m.Module.Metadata.PEImage.ImageNTHeaders.FileHeader.TimeDateStamp)
            .Int("image_base", m => (long)m.Module.Metadata.PEImage.ImageNTHeaders.OptionalHeader.ImageBase)
            .Int("file_size", m => m.DiskBytes.Length)
            .Text("md5", m => m.Md5)
            .Text("sha256", m => m.Sha256)
            .Int("type_count", m => m.Module.GetTypes().Count())
            .Int("method_count", m => m.Module.Metadata.TablesStream.MethodTable.Rows)
            .Bool("is_current", m => m.Id == ws.CurrentModuleId)
            .Bool("dirty", m => m.Dirty)
            .Int("revision", m => m.Revision)
            .Int("raw_patch_count", m => m.RawPatches.Count)
            .Text("dnspy_target", m => DnSpySettings.DnSpyTarget(s, m),
                doc: "file path dnSpy exports name for this module (the last save() of it, else where it was loaded from); dnSpy binds breakpoints by this path")
            .Text("dnspy_assembly_full_name", m => m.Module.Assembly?.FullName ?? "",
                doc: "assembly name dnSpy matches breakpoints and bookmarks against (with dnspy_target)")
            .Text("origin", m => m.Origin, doc: "file | bundle (an entry of a single-file app) | bytes (open_bytes)")
            .Int("derived_from", m => m.DerivedFrom,
                doc: "the module this one came out of: one whose file holds these bytes as they are, or the parent given to open_bytes(); " +
                     "NULL otherwise. It may name a module closed since");
        db.Register(modules);

        // ---- assemblies ----
        db.Register(s.DefTable<AssemblyDef>("assemblies", "meta", "AssemblyDef rows (identity of each loaded assembly)",
                m => m.Module.Assembly is { } a ? new[] { a } : Array.Empty<AssemblyDef>())
            .Text("name", r => r.Item.Name.String, s.Setter<Row<AssemblyDef>>((r, v) => RenameAssembly(r.M, Str(v, "name"))))
            .Text("version", r => r.Item.Version.ToString(), s.Setter<Row<AssemblyDef>>((r, v) => r.Item.Version = Version.Parse(Str(v, "version"))))
            .Text("culture", r => r.Item.Culture.String, s.Setter<Row<AssemblyDef>>((r, v) => r.Item.Culture = Values.ToText(v) ?? ""))
            .Text("full_name", r => r.Item.FullName)
            .Text("public_key", r => r.Item.PublicKey.IsNullOrEmpty ? null : Convert.ToHexString(r.Item.PublicKey.Data),
                s.Setter<Row<AssemblyDef>>((r, v) => r.Item.PublicKey = v == null ? new PublicKey() : new PublicKey(Convert.FromHexString(Str(v, "public_key")))))
            .Text("public_key_token", r => r.Item.PublicKey.IsNullOrEmpty ? null : r.Item.PublicKey.Token.ToString())
            .Text("hash_alg", r => r.Item.HashAlgorithm.ToString(), s.Setter<Row<AssemblyDef>>((r, v) => r.Item.HashAlgorithm = Enum.Parse<AssemblyHashAlgorithm>(Str(v, "hash_alg"), true)))
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<AssemblyDef>>((r, v) => r.Item.Attributes = (AssemblyAttributes)Lng(v, "flags")))
            .Text("flags_text", r => r.Item.Attributes.ToString())
            .Text("processor_arch", r => ((int)r.Item.Attributes & 0x70) switch
            {
                0x10 => "PA_MSIL", 0x20 => "PA_x86", 0x30 => "PA_IA64", 0x40 => "PA_AMD64", 0x50 => "PA_ARM", 0x60 => "PA_ARM64",
                0x70 => "PA_NoPlatform", _ => "PA_None",
            })
            .Bool("is_retargetable", r => r.Item.IsRetargetable)
            .Bool("is_winrt", r => r.Item.IsContentTypeWindowsRuntime)
            .Int("module_count", r => r.Item.Modules.Count));

        // ---- asmrefs / modrefs / files / exported types ----
        db.Register(s.DefTable<AssemblyRef>("asmrefs", "meta", "AssemblyRef rows: assemblies this module references",
                m => m.Module.GetAssemblyRefs())
            .Text("name", r => r.Item.Name.String, s.Setter<Row<AssemblyRef>>((r, v) => r.Item.Name = Str(v, "name")))
            .Text("version", r => r.Item.Version.ToString(), s.Setter<Row<AssemblyRef>>((r, v) => r.Item.Version = Version.Parse(Str(v, "version"))))
            .Text("culture", r => r.Item.Culture.String)
            .Text("public_key_token", r => r.Item.PublicKeyOrToken?.Token.ToString())
            .Text("full_name", r => r.Item.FullName)
            .Int("flags", r => (long)r.Item.Attributes)
            .Int("resolved_module", r => ws.Modules.FirstOrDefault(m => m.Module.Assembly != null && AssemblyNameComparer.NameAndPublicKeyTokenOnly.Equals(m.Module.Assembly, r.Item))?.Id,
                doc: "id of the loaded module that satisfies the reference, if any")
            .Text("resolved_path", r => Try(() => ws.Resolver.Resolve(r.Item, r.M.Module)?.ManifestModule?.Location)));

        db.Register(s.DefTable<ModuleRef>("modrefs", "meta", "ModuleRef rows (native DLLs and netmodules referenced)",
                m => m.Module.GetModuleRefs())
            .Text("name", r => r.Item.Name.String, s.Setter<Row<ModuleRef>>((r, v) => r.Item.Name = Str(v, "name"))));

        db.Register(s.DefTable<FileDef>("files", "meta", "File table rows (multi-file assembly members)",
                m => Enumerable.Range(1, (int)m.Module.Metadata.TablesStream.FileTable.Rows).Select(i => m.Module.ResolveFile((uint)i)).OfType<FileDef>())
            .Text("name", r => r.Item.Name.String)
            .Int("flags", r => (long)r.Item.Flags)
            .Bool("contains_metadata", r => r.Item.ContainsMetadata)
            .Text("hash", r => r.Item.HashValue == null ? null : Convert.ToHexString(r.Item.HashValue)));

        db.Register(s.DefTable<ExportedType>("exported_types", "meta", "ExportedType rows (type forwarders and multi-module exports)",
                m => m.Module.ExportedTypes)
            .Text("namespace", r => r.Item.TypeNamespace.String)
            .Text("name", r => r.Item.TypeName.String)
            .Text("full_name", r => r.Item.FullName)
            .Bool("is_forwarder", r => r.Item.MovedToAnotherAssembly)
            .Text("implementation", r => r.Item.Implementation?.FullName)
            .Int("flags", r => (long)r.Item.Attributes));

        db.Register(new Table<Row<(string ns, int count)>>("namespaces", "Namespaces per module with top-level type counts") { Domain = "meta" }
            .Source(c => ws.Modules(c).SelectMany(m => m.Module.Types.GroupBy(t => t.Namespace.String)
                .Select(g => new Row<(string, int)>(m, (g.Key, g.Count())))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("name", r => r.Item.ns)
            .Int("type_count", r => r.Item.count));

        // ---- runtime settings ----
        var settings = new Table<Session.RuntimeSetting>("runtime_settings", "Session settings; UPDATE value on settable rows") { Domain = "meta" };
        settings.Source(_ => s.Settings.Values)
            .Keyed(r => KeyId(r.Key), id => s.Settings.Values.FirstOrDefault(x => KeyId(x.Key) == id))
            .Text("key", r => r.Key, pushdown: Pushdown.Eq)
            .Text("value", r => r.Key == "current_module" ? ws.CurrentModuleId.ToString() : r.Value, (r, v) => s.SetSetting(r.Key, Values.ToText(v)))
            .Text("type", r => r.Type)
            .Bool("settable", r => r.Settable)
            .Text("description", r => r.Doc);
        db.Register(settings);

        // ---- capabilities ----
        db.Register(new Table<(string feature, string state, string detail)>("sql_capabilities", "Feature matrix of this build") { Domain = "meta" }
            .Source(_ => Capabilities(s))
            .Text("feature", r => r.feature, pushdown: Pushdown.Eq)
            .Text("state", r => r.state)
            .Text("detail", r => r.detail));

        // ---- transactions (undo/redo journal) ----
        db.Register(new Table<(string kind, int pos, JournalEntry e)>("transactions", "Undo/redo journal of SQL writes. undo()/redo() replay it") { Domain = "meta" }
            .Source(_ => ws.UndoStack.AsEnumerable().Reverse().Select((e, i) => ("undo", i + 1, e))
                .Concat(ws.RedoStack.AsEnumerable().Reverse().Select((e, i) => ("redo", i + 1, e))))
            .Text("kind", r => r.kind)
            .Int("position", r => r.pos)
            .Int("seq", r => r.e.Seq)
            .Int("group_id", r => r.e.Group)
            .Text("table_name", r => r.e.Table)
            .Text("description", r => r.e.Description)
            .Text("time", r => r.e.Time.ToString("O")));

        // ---- catalog ----
        // Virtual tables plus the plain SQL views (Views.All); a view row has t = null.
        IEnumerable<(string name, VirtualTable? t, string doc)> Entries() =>
            db.Tables.Select(t => (t.Name, (VirtualTable?)t, t.Doc)).Concat(Views.All.Select(v => (v.name, (VirtualTable?)null, v.doc)));

        db.Register(new Table<(string name, VirtualTable? t, string doc)>("dnspysql_tables", "Catalog of DnSpySql tables and views") { Domain = "meta" }
            .Source(_ => Entries())
            .Text("table_name", r => r.name, pushdown: Pushdown.Eq)
            .Text("domain", r => r.t?.Domain ?? Views.Domain)
            .Text("description", r => r.doc)
            .Bool("can_update", r => r.t?.CanUpdate ?? false)
            .Bool("can_insert", r => r.t?.CanInsert ?? false)
            .Bool("can_delete", r => r.t?.CanDelete ?? false)
            .Text("required_filter", r => r.t is { } t && t.Columns.Any(c => c.Required) ? t.RequiredHint() : null)
            .Text("pushdown_columns", r => r.t is { } t ? string.Join(",", t.Columns.Where(c => c.Pushdown != Pushdown.None).Select(c => c.Name)) : "")
            .Text("kind", r => r.t == null ? "view" : "table"));

        db.Register(new Table<(string table, ColumnInfo? c, string viewType, string name, int i)>("dnspysql_columns", "Catalog of DnSpySql columns (tables and views)") { Domain = "meta" }
            .Source(c => Entries().Where(e => c.Text("table_name") is not string n || string.Equals(e.name, n, StringComparison.OrdinalIgnoreCase))
                .SelectMany(e => e.t != null
                    ? e.t.Columns.Select((col, i) => (e.name, (ColumnInfo?)col, "", col.Name, i))
                    : s.ViewColumns.GetValueOrDefault(e.name, new()).Select((vc, i) => (e.name, (ColumnInfo?)null, vc.type, vc.name, i))))
            .Text("table_name", r => r.table, pushdown: Pushdown.Eq)
            .Int("ordinal", r => r.i)
            .Text("column_name", r => r.name)
            .Text("type", r => r.c?.Type.ToString().ToUpperInvariant() ?? (r.viewType.Length > 0 ? r.viewType.ToUpperInvariant() : "ANY"))
            .Bool("hidden", r => r.c?.Hidden ?? false)
            .Bool("writable", r => r.c?.Writable ?? false)
            .Text("pushdown", r => r.c?.Pushdown.ToString().ToLowerInvariant() ?? "none")
            .Bool("required", r => r.c?.Required ?? false)
            .Bool("is_argument", r => r.c?.IsArgument ?? false)
            .Text("description", r => r.c?.Doc));

        // SQLite registers a function once per argument count; the catalog lists each function once
        db.Register(new Table<(FunctionInfo F, int Min, int Max)>("dnspysql_functions", "Catalog of DnSpySql SQL functions") { Domain = "meta" }
            .Source(_ => db.Functions.GroupBy(f => f.Name).Select(g => (g.First(), g.Min(f => f.Args), g.Max(f => f.Args)))
                .OrderBy(x => x.Item1.Domain).ThenBy(x => x.Item1.Name))
            .Text("name", x => x.F.Name, pushdown: Pushdown.Eq)
            .Text("domain", x => x.F.Domain)
            .Int("arg_count", x => x.Min, doc: "fewest arguments (min_args); max_args is the most")
            .Int("min_args", x => x.Min)
            .Int("max_args", x => x.Max)
            .Text("signature", x => x.F.Signature)
            .Bool("mutates", x => x.F.Mutates)
            .Text("description", x => x.F.Doc));
    }

    static long KeyId(string key) => (long)(uint)StringComparer.OrdinalIgnoreCase.GetHashCode(key);

    static T? Try<T>(Func<T?> f) { try { return f(); } catch { return default; } }

    public static string? TargetFramework(ModuleDef m)
    {
        var ca = m.Assembly?.CustomAttributes.Find("System.Runtime.Versioning.TargetFrameworkAttribute");
        if (ca != null && ca.ConstructorArguments.Count > 0) return (ca.ConstructorArguments[0].Value as UTF8String)?.String;
        return m.RuntimeVersion;
    }

    static void SetKind(ModuleDef m, string kind)
    {
        m.Kind = Enum.Parse<ModuleKind>(kind, true);
        if (m.Kind is ModuleKind.Dll or ModuleKind.NetModule) m.Characteristics |= Characteristics.Dll;
        else m.Characteristics &= ~Characteristics.Dll;
    }

    static void SetEntryPoint(Workspace ws, LoadedModule m, object? v)
    {
        if (v == null) { m.Module.ManagedEntryPoint = null; return; }
        var md = ws.Resolve<MethodDef>(v, "method");
        if (md.Module != m.Module) throw new SqlException("entry point must be a method of the same module");
        m.Module.EntryPoint = md;
    }

    /// <summary>Renames an assembly and fixes AssemblyRefs to it inside its own module (dnSpy behaviour).</summary>
    static void RenameAssembly(LoadedModule m, string name)
    {
        var asm = m.Module.Assembly!;
        var old = asm.Name;
        foreach (var r in m.Module.GetAssemblyRefs().Where(r => r.Name == old)) r.Name = name;
        asm.Name = name;
    }

    static IEnumerable<KeyValuePair<string, (object?, string)>> BinaryRows(Session s)
    {
        var ws = s.Ws;
        var list = new List<KeyValuePair<string, (object?, string)>>();
        void Add(string k, object? v, string type) { if (v != null) list.Add(new(k, (v, type))); }
        var lm = ws.Modules.FirstOrDefault(m => m.Id == ws.CurrentModuleId) ?? ws.Modules.FirstOrDefault();
        if (lm == null)
        {
            Add("summary", "no module loaded (use open('path'))", "string");
            Add("tool_name", Session.ToolName, "string");
            Add("tool_version", Session.ToolVersion, "string");
            Add("tool_commit", Session.ToolCommit, "string");
            Memory();
            return list;
        }
        // what the session holds: close() modules when this grows (an MCP session keeps every module it opened otherwise)
        void Memory()
        {
            Add("session_memory_mb", (Environment.WorkingSet >> 20).ToString(), "int");
            Add("managed_heap_mb", (GC.GetTotalMemory(false) >> 20).ToString(), "int");
        }
        var md = lm.Module;
        var pe = md.Metadata.PEImage;
        bool is64 = md.Machine is Machine.AMD64 or Machine.IA64 or Machine.ARM64;
        var kind = md.Kind switch { ModuleKind.Dll => "dll", ModuleKind.NetModule => "netmodule", ModuleKind.Windows => "winexe", _ => "exe" };
        Add("summary", $"{lm.Name} {md.Assembly?.Version} ({kind}, {TargetFramework(md)}, {md.Machine}{(lm.IsReadyToRun ? ", ReadyToRun" : lm.IsMixedMode ? ", mixed-mode" : "")}), {md.GetTypes().Count()} types, {md.Metadata.TablesStream.MethodTable.Rows} methods", "string");
        Add("tool_name", Session.ToolName, "string");
        Add("tool_version", Session.ToolVersion, "string");
        Add("tool_commit", Session.ToolCommit, "string");
        Add("processor", "CIL", "string");
        Add("machine", md.Machine.ToString(), "string");
        Add("platform", Platform(md), "string");
        Add("filetype", $"PE{(pe.ImageNTHeaders.OptionalHeader is ImageOptionalHeader64 ? "32+" : "32")} .NET {kind}", "string");
        Add("image_base", $"0x{pe.ImageNTHeaders.OptionalHeader.ImageBase:X}", "hex");
        if (md.ManagedEntryPoint is IMDTokenProvider ep) Add("entry_point", $"0x{lm.H(ep):X}", "hex");
        Add("is_64bit", is64 ? "1" : "0", "bool");
        Add("bits", is64 ? "64" : "32", "int");
        Add("endianness", "little", "string");
        Add("filename", lm.Path, "string");
        Add("md5", lm.Md5, "string");
        Add("sha256", lm.Sha256, "string");
        Add("module_id", lm.Id.ToString(), "int");
        Add("module_count", ws.Modules.Count.ToString(), "int");
        Memory();
        Add("assembly", md.Assembly?.FullName, "string");
        Add("mvid", md.Mvid?.ToString(), "string");
        Add("runtime_version", md.RuntimeVersion, "string");
        Add("target_framework", TargetFramework(md), "string");
        Add("is_il_only", md.IsILOnly ? "1" : "0", "bool");
        Add("is_ready_to_run", lm.IsReadyToRun ? "1" : "0", "bool");
        Add("is_mixed_mode", lm.IsMixedMode ? "1" : "0", "bool");
        Add("has_pdb", md.PdbState != null ? "1" : "0", "bool");
        Add("dirty", ws.Modules.Any(m => m.Dirty) ? "1" : "0", "bool");
        Add("revision", ws.Revision.ToString(), "int");
        Add("project_file", s.Store.Path, "string");
        Add("breakpoint_count", s.Store.Breakpoints.Count.ToString(), "int");
        Add("sqlite_version", Database.SqliteVersion, "string");
        var ov = Overlay.Analyze(lm.DiskBytes);
        Add("overlay_offset", ov == null ? null : $"0x{ov.Offset:X}", "hex");
        Add("overlay_size", (ov?.Size ?? 0).ToString(), "int");
        Add("overlay_entropy", ov?.Entropy.ToString("F3"), "string");
        Add("overlay_kind", ov?.Kind, "string");
        Add("overlay_pe_offset", ov?.EmbeddedPe is long epe ? $"0x{epe:X}" : null, "hex");
        Add("overlay_padding", ov?.Padding.ToString(), "int");
        var anomalies = PeTables.Anomalies(lm);
        Add("anomaly_count", anomalies.Count.ToString(), "int");
        Add("anomalies", string.Join("\n", anomalies), "string");
        return list;
    }

    public static string Platform(ModuleDef md) => md.Machine switch
    {
        Machine.I386 when md.Is32BitRequired => "x86",
        Machine.I386 when md.Is32BitPreferred => "AnyCPU (32-bit preferred)",
        Machine.I386 => "AnyCPU",
        Machine.AMD64 => "x64",
        Machine.ARM64 => "ARM64",
        Machine.ARMNT => "ARM",
        Machine.IA64 => "IA64",
        var m => m.ToString(),
    };

    static IEnumerable<(string, string, string)> Capabilities(Session s)
    {
        yield return ("feature.metadata", "yes", "dnlib metadata model: types, members, refs, attributes, signatures");
        yield return ("feature.metadata_write", s.Db.ReadOnly ? "readonly" : "yes", "UPDATE/INSERT/DELETE on metadata tables, journaled (undo/redo)");
        yield return ("feature.il", "yes", "il/locals/exception_handlers/blocks/cfg_edges tables; IL edit via il table + il_* functions");
        yield return ("feature.xrefs", "yes", "xrefs/call_edges/callers/callees/string_refs built from IL");
        yield return ("feature.analyzer", "yes", "analyze(): dnSpy analyzer relations (uses, used_by, read_by, assigned_by, ...)");
        yield return ("feature.decompiler", "yes", "dnSpyEx decompiler (dnlib-backed ILSpy fork, vendored): csharp, vb, il; BAML to XAML");
        yield return ("feature.compile", "yes", "Roslyn: compile_method / add_members / add_type (dnSpy Edit Method / Add Class Members / Add Class (C#))");
        yield return ("feature.pe", "yes", "pe_* headers, sections, data directories, metadata streams/tables/heaps");
        yield return ("feature.pdb", "yes", "sequence_points, pdb_locals, pdb_documents when a PDB is present");
        yield return ("feature.resources", "yes", "resources / resource_elements (.resources), read and write");
        yield return ("feature.raw_patch", "yes", "file_bytes UPDATE / patch_bytes() + save_raw() (hex editor)");
        yield return ("feature.search", "yes", "search(), jump_entities, byte_search");
        yield return ("feature.annotations", s.Store.Path != null ? "yes" : "memory", "comments, bookmarks, tags, kv, breakpoints (project file)");
        yield return ("feature.breakpoints", "yes", "breakpoints, module_breakpoints, exception_settings (dnSpy breakpoint configuration by IL offset, source line or decompiled line; exportable to dnSpy)");
        yield return ("feature.process_debugging", "no", "by design: DnSpySql configures breakpoints, it does not run or attach to processes");
        yield return ("feature.runtime_settings", "yes", "runtime_settings table");
        yield return ("feature.undo", "yes", "transactions table, undo(n)/redo(n)");
    }
}
