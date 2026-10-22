// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Tables;
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql.Functions;

public static class FnKit
{
    /// <summary>Registers a function accepting between min and max arguments.</summary>
    public static void Fn(this Session s, string name, int min, int max, Func<object?[], object?> impl, string signature, string doc,
        string domain, bool mutates = false, bool deterministic = false)
    {
        for (int n = min; n <= max; n++)
        {
            s.Db.Function(name, n, impl, signature, doc, deterministic, mutates, domain);
        }
    }

    public static object? Arg(this object?[] a, int i) => i < a.Length ? a[i] : null;
}

/// <summary>Navigation, formatting, lifecycle, decompiler, raw-byte and live-target functions.</summary>
public static class CoreFunctions
{
    public static void Register(Session s)
    {
        var ws = s.Ws;

        // ---- handles & names ----
        s.Fn("handle", 1, 2, a => a.Length == 1 ? ws.Normalize(Values.ToLong(a[0]) ?? 0) : Handle.Make((int)(Values.ToLong(a[0]) ?? 0), (uint)(Values.ToLong(a[1]) ?? 0)),
            "handle(token) | handle(module, token)", "build a universal handle (module<<32 | token)", "core", deterministic: true);
        s.Fn("token_of", 1, 1, a => (long)Handle.Token(Values.ToLong(a[0]) ?? 0), "token_of(handle)", "metadata token part of a handle", "core", deterministic: true);
        s.Fn("module_of", 1, 1, a => (long)Handle.Module(ws.Normalize(Values.ToLong(a[0]) ?? 0)), "module_of(handle)", "module id part of a handle", "core");
        s.Fn("hx", 1, 1, a => Values.ToLong(a[0]) is long v ? $"0x{v:X}" : null, "hx(int)", "format an integer as 0x hex", "core", deterministic: true);
        s.Fn("tok", 1, 1, a => Values.ToLong(a[0]) is long v ? Handle.Hex(v) : null, "tok(handle)", "format a handle as 0xM_TTTTTTTT (or 0xTTTTTTTT); that text is accepted back wherever a handle is", "core", deterministic: true);
        s.Fn("kind_of", 1, 1, a => Values.ToLong(a[0]) is long v ? Handle.KindOf(Handle.Token(v)) : null, "kind_of(handle)", "entity kind from the token table", "core", deterministic: true);
        s.Fn("name_of", 1, 1, a =>
        {
            if (ws.HandleArg(a[0]) is not long h) return null;
            try { var (_, it) = ws.Resolve(h); return (it as IFullName)?.FullName ?? it.ToString(); } catch { return null; }
        }, "name_of(handle)", "full name of any entity", "core");
        s.Fn("resolve", 1, 3, a => Resolve(s, Str(a[0], "name"), Values.ToText(a.Arg(1)), a.Arg(2) == null ? null : ws.ModuleArg(a.Arg(2))),
            "resolve(name [, kind [, module]])", "find a handle by full name: 'Ns.Type', 'Ns.Outer/Nested', 'Ns.Type::Method', 'Ns.Type::Method(System.String,System.Int32)' " +
            "(an overload by its parameter types), 'Ns.Type::field', 'Ns.Type::.ctor'. First match, with a note when a method name has several " +
            "overloads; NULL when nothing matches. kind = type|method|field|property|event (NULL: any). Searches the given module, else the " +
            "current one (use_module) first, then the others, with a note when the name is in more than one", "core");
        s.Fn("def_of", 1, 1, a =>
        {
            if (ws.HandleArg(a[0]) is not long h) return null;
            var (_, it) = ws.Resolve(h);
            return MemberTables.DefHandle(ws, it as IMemberRef);
        }, "def_of(handle)", "resolve a TypeRef/MemberRef/MethodSpec handle to its definition handle (if loaded)", "core");

        // ---- session / lifecycle ----
        s.Fn("open", 1, 1, a => (long)s.Open(Str(a[0], "path")).Id, "open(path)", "load another assembly/module into the session; returns its module id", "session");
        // The next stage of a loader is usually a blob the SQL data helpers can already decode (decrypt, decompress,
        // base64_decode, xor): this loads it as a module of its own, so it can be queried, decompiled and saved.
        s.Fn("open_bytes", 1, 4, a =>
        {
            if (a[0] == null) return null; // the decode step before it failed (decompress, decrypt, ... return NULL)
            var parent = a.Arg(3) == null ? null : ws.ModuleArg(a[3]);
            var data = a[0] as byte[] ?? throw new SqlException("open_bytes(data): data must be a blob (decode it first: decompress, decrypt, base64_decode, ...)");
            var name = Values.ToText(a.Arg(1)) ?? $"memory-{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data))[..12].ToLowerInvariant()}.dll";
            // the same name again is the same module only if it is the same bytes (a payload decrypted again with another key is not)
            // a native PE (a payload's next stage written in C, a dropped DLL) has no tables here: NULL and a note, so a
            // query opening every payload of a sample goes on to the next one
            if (Values.ToLong(a.Arg(2)) != 1 && Workspace.NotDotNet(data) is { } why && why.Contains(": native ", StringComparison.Ordinal))
            {
                s.Notices.Add($"open_bytes: {name}: {why}; not opened (NULL)");
                return null;
            }
            if (ws.Modules.FirstOrDefault(m => string.Equals(m.Path, name, StringComparison.OrdinalIgnoreCase)) is { } open && !open.OriginalBytes.AsSpan().SequenceEqual(data))
                throw new SqlException($"a module named '{name}' is already open with other bytes (module {open.Id}); give this one another name, " +
                                       "or leave the name out to get one from its hash");
            // the same bytes under another name would be a second copy of every row, and every name in it ambiguous; an
            // edited module is not those bytes any more, so a pristine copy of it can still be opened
            if (ws.Modules.FirstOrDefault(m => !m.Dirty && m.OriginalBytes.Length == data.Length && m.OriginalBytes.AsSpan().SequenceEqual(data)) is { } same)
            {
                if (!string.Equals(same.Path, name, StringComparison.OrdinalIgnoreCase))
                    s.Notices.Add($"open_bytes: {name}: the same bytes are open as module {same.Id} ({same.Path}); returned it");
                if (parent != null && same.DerivedFrom == null && same.Origin == "bytes" && parent != same) same.DerivedFrom = parent.Id;
                return (long)same.Id;
            }
            return (long)s.OpenBytes(data, name, Values.ToLong(a.Arg(2)) == 1, parent: parent).Id;
        }, "open_bytes(data [, name [, memory_layout [, parent]]])",
            "load a module from a blob, such as a payload decrypted or decompressed with SQL; it is only parsed, never run. " +
            "The name defaults to memory-<sha256 prefix>.dll, unique per payload; bytes already open return that module, with a note. " +
            "memory_layout = 1 for an image dumped from memory. modules.derived_from names the module it came out of: found for a PE that " +
            "embedded_pes carves (or one in a module's file as it is); pass parent for a payload decoded by hand. Returns its module id " +
            "(NULL for NULL data, and for a native PE, with a note)", "session");
        // A sample is rarely one module (untamper()'s copy, the stages it carries): closing one closes what came out of it,
        // so a long MCP session can go sample by sample without holding every module it ever opened.
        s.Fn("close", 1, 2, a =>
        {
            var ids = s.Close(ws.ModuleArg(a[0]), Values.ToLong(a.Arg(1)) is not 0);
            return System.Text.Json.JsonSerializer.Serialize(ids);
        }, "close(module [, with_derived])",
            "take a module out of the session when you are done with it, with every module that came out of it (modules.derived_from: " +
            "untamper()'s copy, stages opened with open_bytes), and free their memory; with_derived = 0 closes that module alone. It " +
            "happens when the statement ends, with a note of the memory freed; ids are never reused, so a handle of a closed module stays an " +
            "error. Refused for a module with unsaved edits (save() first: undoing them still leaves it marked as edited) and for the one " +
            "holding the project file; a module edited later in the same statement stays open, with a note. Returns the " +
            "ids closed, as a JSON array", "session");
        s.Fn("close_all", 0, 1, a => System.Text.Json.JsonSerializer.Serialize(s.CloseAll(Values.ToLong(a.Arg(0)) is 1)),
            "close_all([keep_first])",
            "close() every module: all but the one holding the project file (all of them with --no-project), and with keep_first = 1 " +
            "all but the first one open. For bulk work: open a batch, analyze it, close_all(), the next batch. Returns the ids closed", "session");
        // Anti-tamper keeps method bodies encrypted in the file until a startup routine decrypts them in memory:
        // interpreting that routine over a copy of the image (Emulator.Untamper) gives the decrypted file.
        s.Fn("untamper", 0, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(0));
            dnlib.DotNet.MethodDef init;
            if (Values.ToLong(a.Arg(2)) is long ih)
                init = lm.Module.ResolveToken(Handle.Token(ws.Normalize(ih))) as dnlib.DotNet.MethodDef ?? throw new SqlException("initializer is not a method");
            else if (lm.Origin == "untamper") // its routine already ran: again, it would decrypt the decrypted bodies
                throw new SqlException($"module {lm.Id} is untamper()'s decrypted copy of module {lm.DerivedFrom}; untamper that one " +
                                       "(pass another initializer for the bodies still encrypted), or pass the initializer to run one here anyway");
            else if (Tables.HexTables.Undecodable(lm).Count == 0) // found by shape only: nothing encrypted means nothing to look for
                throw new SqlException("every method body already decodes as IL: nothing to untamper (pass the initializer to run it anyway)");
            else
                init = AntiTamperInitializer(s, lm)
                       ?? throw new SqlException("no anti-tamper initializer (a static method calling Marshal.GetHINSTANCE and VirtualProtect)");
            byte[] image;
            try { image = new Emulator(s, () => s.Db.Cancellation).Untamper(init); }
            catch (Emulator.Failed e) { throw new SqlException(e.Message); }
            var name = Values.ToText(a.Arg(1)) ?? Path.GetFileNameWithoutExtension(lm.Path) + ".untampered" + Path.GetExtension(lm.Path);
            var opened = s.OpenBytes(image, name, false, lm, init.MDToken.Raw);
            // the routine may decrypt only part of the image (or with a key that came out wrong): say so, the module is still useful
            int left = Tables.HexTables.Undecodable(opened).Count, total = Tables.HexTables.Bodies(opened).Count;
            if (left > 0) s.Notices.Add($"untamper: {left} of {total} method bodies of module {opened.Id} still do not decode as IL (see method_bodies)");
            return (long)opened.Id;
        }, "untamper([module [, name [, initializer]]])",
            "decrypt the method bodies of an anti-tampered module by interpreting the routine that decrypts them at startup (found: a " +
            "static method using Marshal.GetHINSTANCE and VirtualProtect; or the initializer given) over a copy of the image, and open " +
            "the result as a new module; the sample never runs. Returns the new module's id", "session");
        s.Fn("use_module", 1, 1,a => { s.SetSetting("current_module", Values.ToText(a[0])); return (long)ws.CurrentModuleId; },
            "use_module(id)", "module used for bare tokens", "session");
        s.Fn("save", 1, 2, a =>
        {
            var (lm, path) = a.Length == 1 ? (ws.Get(ws.CurrentModuleId), Str(a[0], "path")) : (ws.ModuleArg(a[0]), Str(a[1], "path"));
            return Sidecars(lm, ws.Save(lm, path, s.Settings["save_preserve_tokens"].AsBool));
        }, "save([module,] path)", "write the (edited) module with dnlib, preserving tokens (dnSpy Save Module); also writes a PDB if one was loaded. " +
           "With save_sidecars (default on) it also writes <file>.xml, the comments and tags as XML documentation that dnSpyEx shows as /// " +
           "comments, and <file>.dnspysql.json with the annotations, and later dnSpy exports name the saved file", "session");
        s.Fn("save_raw", 1, 2, a =>
        {
            var (lm, path) = a.Length == 1 ? (ws.Get(ws.CurrentModuleId), Str(a[0], "path")) : (ws.ModuleArg(a[0]), Str(a[1], "path"));
            return Sidecars(lm, ws.SaveRaw(lm, path));
        }, "save_raw([module,] path)", "write the original file bytes plus raw byte patches (hex editor save); sidecar files as save()", "session");
        string Sidecars(LoadedModule lm, string path)
        {
            if (s.Settings["save_sidecars"].AsBool && AnnotatedSave.After(s, lm, path) is { Length: > 0 } note) s.Notices.Add(note);
            return path;
        }
        s.Fn("dnspy_sync", 0, 0, _ => { s.Notices.Add(s.DnSpy.Sync(out var n)); return (long)n; }, "dnspy_sync()",
            "merge breakpoints, bookmarks, module breakpoints and exception settings into dnSpy's settings file now (runtime setting " +
            "dnspy_xml; this also happens after every statement that changes them). Run it after closing dnSpy, which overwrites the file " +
            "on exit. Returns the number of entries", "breakpoints");
        s.Fn("save_project", 0, 1, a => { s.Store.Save(Values.ToText(a.Arg(0))); return s.Store.Path; },
            "save_project([path])", "persist annotations (comments, bookmarks, tags, kv, breakpoints)", "session");
        s.Fn("is_dirty", 0, 1, a => a.Length == 0 ? ws.Modules.Any(m => m.Dirty || m.RawPatches.Count > 0) : (object)(ws.ModuleArg(a[0]) is var m && (m.Dirty || m.RawPatches.Count > 0)),
            "is_dirty([module])", "unsaved model edits or raw patches", "session");
        s.Fn("undo", 0, 1, a => (long)ws.Undo((int)(Values.ToLong(a.Arg(0)) ?? 1)), "undo([n])", "undo the last n statements' writes", "session");
        s.Fn("redo", 0, 1, a => (long)ws.Redo((int)(Values.ToLong(a.Arg(0)) ?? 1)), "redo([n])", "redo n undone statements", "session");
        s.Fn("set_setting", 2, 2, a => { s.SetSetting(Str(a[0], "key"), Values.ToText(a[1])); return 1L; }, "set_setting(key, value)", "same as UPDATE runtime_settings", "session");

        // ---- decompiler ----
        // decompile(handle [, lang]) or, in the older form, decompile(token [, module [, lang]]): an integer second
        // argument is a module id.
        long Target(object?[] a) => a.Length > 1 && a[1] is long mod ? Handle.Make(ws.ModuleArg(mod).Id, (uint)Lng(a[0], "token")) : Lng(a[0], "handle");
        string? Lang(object?[] a) => a.Length == 3 || a.Length > 1 && a[1] is long ? Values.ToText(a.Arg(2)) : Values.ToText(a.Arg(1));
        // NULL in, NULL out: decompile((SELECT handle ... LIMIT 1)) on a module where nothing matches
        s.Fn("decompile", 1, 3, a => a[0] == null ? null : s.Decompiler.Decompile(Target(a), Lang(a)).Text,
            "decompile(handle [, 'csharp'|'vb'|'il'])  or  decompile(token [, module [, lang]])",
            "decompile a type/method/field/property/event with dnSpy's engine (reflects edits). A failure comes back as text starting /* dnspysql: so bulk queries never abort",
            "decompiler");
        s.Fn("il_text", 1, 2, a => a[0] == null ? null : s.Decompiler.Decompile(Target(a), "il").Text, "il_text(handle)  or  il_text(token [, module])", "ildasm-style disassembly", "decompiler");
        s.Fn("decompile_module", 0, 2, a => s.Decompiler.DecompileModule(ws.ModuleArg(a.Arg(0)), Values.ToText(a.Arg(1))),
            "decompile_module([module [, lang]])", "source for a whole module, assembled type by type (large!)", "decompiler");
        s.Fn("export_project", 1, 3, a =>
        {
            // export_project(dir [, module [, sdk]]) or export_project(module, dir); NULL module = all modules.
            if (a[0] is long mod) return s.Decompiler.ExportProject([ws.ModuleArg(mod)], Str(a.Arg(1), "dir"), Values.ToBool(a.Arg(2)));
            var modules = a.Arg(1) == null ? ws.Modules : new[] { ws.ModuleArg(a[1]) };
            return s.Decompiler.ExportProject(modules, Str(a[0], "dir"), Values.ToBool(a.Arg(2)));
        }, "export_project(dir [, module [, sdk]])  or  export_project(module, dir)",
            "dnSpy 'Export to Project' with its dialog's defaults: a solution with one C# project per module (all loaded modules when module is NULL), " +
            "resources unpacked to .resx; sdk = 1 for SDK-style projects. Returns the .sln path", "decompiler");

        // ---- raw bytes ----
        s.Fn("rva_to_offset", 1, 2, a => PeTables.RvaToOffset(ws.ModuleArg(a.Arg(1)), Lng(a[0], "rva")), "rva_to_offset(rva [, module])", "file offset of an RVA", "pe");
        s.Fn("offset_to_rva", 1, 2, a => PeTables.OffsetToRva(ws.ModuleArg(a.Arg(1)), Lng(a[0], "offset")), "offset_to_rva(offset [, module])", "RVA of a file offset", "pe");
        s.Fn("read_bytes", 2, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var off = Lng(a[0], "offset"); var n = (int)Lng(a[1], "size");
            if (off < 0 || off + n > lm.DiskBytes.Length) throw new SqlException("range outside the file");
            var b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = ws.RawByte(lm, off + i);
            return b;
        }, "read_bytes(offset, size [, module])", "bytes of the current file image (with patches)", "pe");
        s.Fn("patch_bytes", 2, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var data = a[1] is string hex ? PeTables.ParsePattern(hex).bytes : Values.ToBytes(a[1]) ?? throw new SqlException("data required");
            PeTables.PatchBytes(s, lm, Lng(a[0], "offset"), data);
            return (long)data.Length;
        }, "patch_bytes(offset, blob|'hex bytes' [, module])", "raw patch (hex editor); saved by save_raw()", "pe", mutates: true);
        s.Fn("method_bytes", 1, 1, a =>
        {
            var m = ws.Resolve<MethodDef>(a[0], "method");
            var lm = ws.ModuleOf(m);
            var rva = PeTables.FileRva(lm, m);
            if (rva == 0 || PeTables.RvaToOffset(lm, rva) is not long off) return null;
            var size = (int)(MemberTables.CodeSize(m) ?? 0) + 12;
            return Enumerable.Range(0, (int)Math.Min(size, lm.DiskBytes.Length - off)).Select(i => ws.RawByte(lm, off + i)).ToArray();
        }, "method_bytes(method)", "raw bytes of a method body in the file (header + IL, original layout)", "pe");

        // ---- annotations ----
        s.Fn("set_comment", 2, 3, a =>
        {
            var (h, off, text) = a.Length == 2 ? (a[0], (object?)null, a[1]) : (a[0], a[1], a[2]);
            var at = AnnotationTables.Loc(s, h, off);
            s.Store.Comments.RemoveAll(c => c.At.Mvid == at.Mvid && c.At.Token == at.Token && c.At.Offset == at.Offset);
            if (Values.ToText(text) is string t && t.Length > 0) s.Store.Comments.Add(new CommentRec { Id = s.Store.NewId(), At = at, Text = t });
            s.Store.Changed();
            return 1L;
        }, "set_comment(handle, [il_offset,] text)", "replace the comment at an entity / IL offset (NULL or '' removes)", "annotations");
        s.Fn("tag", 2, 2, a =>
        {
            var at = AnnotationTables.Loc(s, a[0], null);
            var t = Str(a[1], "tag");
            if (!s.Store.Tags.Any(x => x.Tag == t && x.At.Mvid == at.Mvid && x.At.Token == at.Token))
                s.Store.Tags.Add(new TagRec { Id = s.Store.NewId(), At = at, Tag = t });
            s.Store.Changed();
            return 1L;
        }, "tag(handle, tag)", "attach a tag (progress tracking)", "annotations");
    }

    static string Str(object? v, string what) => TableKit.Str(v, what);
    static long Lng(object? v, string what) => TableKit.Lng(v, what);

    public static long? Resolve(Session s, string name, string? kind, LoadedModule? only = null)
    {
        var ws = s.Ws;
        string typePart = name, member = "";
        var sep = name.IndexOf("::", StringComparison.Ordinal);
        if (sep >= 0) { typePart = name[..sep]; member = name[(sep + 2)..]; }
        var paren = member.IndexOf('(');
        var mname = paren >= 0 ? member[..paren] : member;
        string? overloadNote = null;

        long? In(LoadedModule lm)
        {
            var t = lm.Module.Find(typePart.Replace('+', '/'), false)
                    ?? lm.Module.GetTypes().FirstOrDefault(x => x.FullName == typePart || x.ReflectionFullName == typePart);
            if (t == null) return null;
            if (member.Length == 0) return kind is null or "type" ? lm.H(t) : null;
            if (kind is null or "method")
            {
                var overloads = t.Methods.Where(m => m.Name == mname && (paren < 0 || MemberTables.Signature(m).Contains(member[paren..]) || m.FullName.EndsWith(member))).ToList();
                // the first of several overloads is a guess: say so, since a patch or comment on the wrong one goes unnoticed
                if (overloads.Count > 1)
                    overloadNote ??= $"resolve: '{name}' matches {overloads.Count} methods; returned the first, {overloads[0].FullName} " +
                                     $"(name one with its parameter types: '{typePart}::{mname}({string.Join(",", overloads[1].MethodSig?.Params.Select(p => p.FullName) ?? [])})')";
                if (overloads.Count > 0) return lm.H(overloads[0]);
            }
            if (kind is null or "field" && t.Fields.FirstOrDefault(f => f.Name == mname) is { } fd) return lm.H(fd);
            if (kind is null or "property" && t.Properties.FirstOrDefault(p => p.Name == mname) is { } pd) return lm.H(pd);
            if (kind is null or "event" && t.Events.FirstOrDefault(e => e.Name == mname) is { } ed) return lm.H(ed);
            return null;
        }

        // the current module first (use_module), then the others in load order; a name in several modules (an untamper()
        // copy, a stage opened twice) gets a note, since following it into the wrong module goes unnoticed
        IEnumerable<LoadedModule> order = only != null ? [only] : ws.Modules.OrderBy(m => m.Id == ws.CurrentModuleId ? 0 : 1).ThenBy(m => m.Id);
        long? found = null;
        var others = new List<int>();
        foreach (var lm in order)
        {
            if (In(lm) is not long h) continue;
            if (found == null) { found = h; if (overloadNote != null) s.Notices.Add(overloadNote); }
            else others.Add(lm.Id);
        }
        // once per statement: resolve() over many rows of an untamper() copy would otherwise note every name
        const string several = "resolve: names in several modules";
        if (found is long f && others.Count > 0 && !s.Notices.Any(n => n.StartsWith(several, StringComparison.Ordinal)))
            s.Notices.Add($"{several}: '{name}' is in modules {Handle.Module(f)} and {string.Join(", ", others)}; returned module {Handle.Module(f)}'s " +
                          $"(the current module, else the first loaded; resolve(name, kind, module) picks one)");
        return found;
    }

    // A parameterless static method that takes the module's base address (Marshal.GetHINSTANCE) and makes it writable
    // (a VirtualProtect P/Invoke, called directly or through a wrapper): a self-decrypting startup routine. The module
    // initializer type (<Module>) is searched first, since its static constructor runs before anything else.
    internal static dnlib.DotNet.MethodDef? AntiTamperInitializer(Session s, LoadedModule lm)
    {
        bool CallsProtect(dnlib.DotNet.MethodDef m, int depth) => s.Index.From(lm.H(m)).Any(x => x.IsCall && x.Def is dnlib.DotNet.MethodDef d
            && (d.ImplMap?.Name.String == "VirtualProtect" || depth < 2 && d.HasBody && CallsProtect(d, depth + 1)));
        return lm.Module.GetTypes().OrderBy(t => t.IsGlobalModuleType ? 0 : 1).SelectMany(t => t.Methods)
            .FirstOrDefault(m => m.IsStatic && !m.IsStaticConstructor && m.HasBody && m.MethodSig?.Params.Count == 0
                                 && s.Index.From(lm.H(m)).Any(x => x.ToName.Contains("Marshal::GetHINSTANCE(", StringComparison.Ordinal))
                                 && CallsProtect(m, 0));
    }
}
