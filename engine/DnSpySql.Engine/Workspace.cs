// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Security.Cryptography;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using dnlib.PE;

namespace DnSpySql;

/// <summary>One loaded assembly/module in the session.</summary>
public sealed class LoadedModule
{
    public required int Id { get; init; }
    public required ModuleDefMD Module { get; set; }
    /// <summary>Path on disk, or a pseudo path such as memory://pid/0x7ff.. for modules read from a process.</summary>
    public required string Path { get; init; }
    public required byte[] OriginalBytes { get; init; }
    /// <summary>The bytes on disk when <see cref="OriginalBytes"/> had to be repaired to load (see <see cref="Repair"/>).</summary>
    public byte[]? FileBytes { get; init; }
    /// <summary>
    /// The file as it is on disk: what the raw views (file_bytes, pe_fields, byte_search, read_bytes) show and raw patches
    /// apply to. It differs from <see cref="OriginalBytes"/> only when the header had to be repaired (in place).
    /// </summary>
    public byte[] DiskBytes => FileBytes ?? OriginalBytes;
    /// <summary>What was repaired to load this module, or null.</summary>
    public string? Repair { get; init; }
    /// <summary>How the module was opened: file | bundle | bytes | untamper (see modules.origin).</summary>
    public string Origin { get; internal set; } = "file";
    /// <summary>The module this one came out of: the one untamper() decrypted, or the one whose file holds these bytes.</summary>
    public int? DerivedFrom { get; internal set; }
    /// <summary>For an untamper() result: the token of the startup routine already applied to these bytes.</summary>
    public uint? UntamperedBy { get; internal set; }
    public bool Dirty { get; set; }
    /// <summary>Bumped on every change (model edit, raw patch, undo/redo).</summary>
    public int Revision { get; set; }
    /// <summary>Raw file patches (hex editor style), applied by save_raw().</summary>
    public SortedDictionary<long, byte> RawPatches { get; } = new();
    public string Sha256 => _sha ??= Convert.ToHexString(SHA256.HashData(FileBytes ?? OriginalBytes)).ToLowerInvariant();
    string? _sha;
    public string Md5 => _md5 ??= Convert.ToHexString(MD5.HashData(FileBytes ?? OriginalBytes)).ToLowerInvariant();
    string? _md5;

    /// <summary>ReadyToRun image: IL plus precompiled native code (ILLibrary flag + ManagedNativeHeader), not C++/CLI.</summary>
    public bool IsReadyToRun =>
        (Module.Cor20HeaderFlags & dnlib.DotNet.MD.ComImageFlags.ILLibrary) != 0
        || Module.Metadata.ImageCor20Header.ManagedNativeHeader.VirtualAddress != 0;

    /// <summary>True C++/CLI mixed-mode image (native code that is not ReadyToRun).</summary>
    public bool IsMixedMode => !Module.IsILOnly && !IsReadyToRun;

    /// <summary>
    /// The metadata of the file as it was loaded, for the views of the file's own structures (pe_*, md_rows, method_bodies,
    /// heap_entries, file_map). It is the model's until a whole-module edit: Workspace.SnapshotEdit then works on a
    /// module re-read from a serialized image, whose offsets no longer describe the file.
    /// </summary>
    public dnlib.DotNet.MD.Metadata FileMetadata => _fileMetadata ?? Module.Metadata;
    internal dnlib.DotNet.MD.Metadata? _fileMetadata;

    /// <summary>Data appended after the PE image, from the bytes on disk (see Overlay).</summary>
    public OverlayInfo? Overlay => (_overlay ??= new(() => DnSpySql.Overlay.Analyze(FileBytes ?? OriginalBytes))).Value;
    Lazy<OverlayInfo?>? _overlay;

    internal Workspace? Ws { get; set; }
    /// <summary>The single-file bundle this module was taken from (see Bundle), and the host file's bytes.</summary>
    public BundleInfo? Bundle { get; internal set; }
    public byte[]? BundleHost { get; internal set; }
    /// <summary>The bundle's other app assemblies, registered with the resolver while this module is open.</summary>
    internal List<AssemblyDef> BundleDeps { get; set; } = [];
    /// <summary>Where annotations and project files belong: the bundle on disk, or the module's own path.</summary>
    public string DiskPath => Bundle?.HostPath ?? Path;
    /// <summary>Marks the module edited (dirty, new revision); same as Workspace.Touch.</summary>
    public void Touch() => Ws?.Touch(this);

    public long H(IMDTokenProvider? p) => p == null ? 0 : Handle.Make(Id, p.MDToken.Raw);
    public long H(uint token) => Handle.Make(Id, token);
    public string Name => Module.Assembly?.Name.String ?? Module.Name.String;
}

public sealed class JournalEntry
{
    public long Seq { get; init; }
    public long Group { get; init; }
    public required string Table { get; init; }
    public required string Description { get; init; }
    public required Action Undo { get; init; }
    public required Action Redo { get; init; }
    public DateTime Time { get; init; } = DateTime.UtcNow;
    /// <summary>A module its statement changed was closed since: replaying it would edit a disposed module.</summary>
    public int? ClosedModule { get; set; }
}

/// <summary>The analysis session: loaded modules, resolver, undo journal.</summary>
public sealed class Workspace : IWriteSink, IDisposable
{
    // Copy on write: a scan enumerates the array it started with, so a function in the same statement that opens a module
    // (open_bytes() over embedded_pes, untamper(), open()) or closes one cannot break the enumeration ("Collection was
    // modified" once the host asked for the scan's second batch). Reads stay allocation-free.
    LoadedModule[] _modules = [];
    public IReadOnlyList<LoadedModule> Modules => _modules;
    // Ids are never reused: a handle (module << 32 | token) kept from a closed module must not address a later one.
    int _nextId;
    public ModuleContext Context { get; }
    public SafeAssemblyResolver Resolver { get; }
    public int CurrentModuleId { get; set; } = 1;
    /// <summary>Most modules open at once (runtime setting max_modules; 0 = no limit).</summary>
    public int MaxModules { get; set; }
    readonly MemoResolver _memo;
    public long Revision { get; private set; }
    public List<JournalEntry> UndoStack { get; } = new();
    public List<JournalEntry> RedoStack { get; } = new();
    long _seq;
    long _group;
    bool _replaying;

    /// <summary>Starts a new undo group; every write recorded until the next call is undone/redone together.</summary>
    public void BeginGroup() => _group++;

    public Workspace()
    {
        Resolver = new SafeAssemblyResolver { EnableFrameworkRedirect = false, FindExactMatch = false, EnableTypeDefCache = true };
        _memo = new MemoResolver(new Resolver(Resolver), () => Revision);
        Context = new ModuleContext(Resolver, _memo);
        Resolver.DefaultModuleContext = Context;
        // dnlib finds the .NET Framework GAC (and Mono) but not the .NET Core shared framework, so references to
        // System.Runtime, System.Private.CoreLib or netstandard would stay unresolved, and the decompiler would then
        // skip transforms that need framework types (async/await, for one). dnSpy adds the framework directories
        // itself; here the running runtime's shared frameworks are searched last. Their mscorlib and netstandard
        // facades also serve .NET Framework references when no GAC, Mono or reference pack is installed.
        foreach (var dir in SharedFrameworkDirs())
            if (!Resolver.PostSearchPaths.Contains(dir)) Resolver.PostSearchPaths.Add(dir);
    }

    // The newest installed version of each shared framework (Microsoft.NETCore.App, Microsoft.AspNetCore.App,
    // Microsoft.WindowsDesktop.App), starting with the one this process runs on.
    static IEnumerable<string> SharedFrameworkDirs()
    {
        var core = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory().TrimEnd('/', '\\');
        if (Directory.Exists(core)) yield return core;
        var shared = System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(core));
        if (shared is null || !Directory.Exists(shared)) yield break;
        foreach (var fx in Directory.GetDirectories(shared))
        {
            if (string.Equals(System.IO.Path.GetFileName(fx), "Microsoft.NETCore.App", StringComparison.OrdinalIgnoreCase)) continue;
            var newest = Directory.GetDirectories(fx)
                .Select(d => (d, v: System.Version.TryParse(System.IO.Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
                .Where(x => x.v != null).OrderByDescending(x => x.v).Select(x => x.d).FirstOrDefault();
            if (newest != null) yield return newest;
        }
    }

    public LoadedModule Open(string path)
    {
        path = System.IO.Path.GetFullPath(path);
        var bytes = File.ReadAllBytes(path);
        var dir = System.IO.Path.GetDirectoryName(path);
        if (dir != null && !Resolver.PreSearchPaths.Contains(dir)) Resolver.PreSearchPaths.Add(dir);
        if (Bundle.Read(path, bytes) is { } bundle) return OpenBundle(path, bytes, bundle);
        return Add(bytes, path, path);
    }

    /// <summary>
    /// A single-file app: its own assembly becomes the module (shown as host!/entry), and the bundle's other app
    /// assemblies are registered for resolution, so references into them decompile and analyze like files next to it.
    /// </summary>
    LoadedModule OpenBundle(string path, byte[] host, BundleInfo bundle)
    {
        var main = Bundle.MainAssembly(bundle) ?? throw new SqlException($"{path} is a single-file bundle without managed assemblies");
        var deps = new List<AssemblyDef>();
        foreach (var e in bundle.Entries.Where(e => e.Type == 1 && e != main && !Bundle.IsFramework(e)))
        {
            try
            {
                var dep = ModuleDefMD.Load(Bundle.Extract(host, e), new ModuleCreationOptions(Context) { TryToLoadPdbFromDisk = false });
                dep.Location = $"{path}!/{e.Path}";
                if (dep.Assembly != null) { Resolver.AddToCache(dep); deps.Add(dep.Assembly); }
            }
            catch (Exception ex) when (ex is BadImageFormatException or InvalidDataException or IOException) { }
        }
        var lm = OpenBundleEntry(path, host, bundle, main);
        lm.BundleDeps = deps;
        return lm;
    }

    public LoadedModule OpenBundleEntry(string path, byte[] host, BundleInfo bundle, BundleEntry entry)
    {
        if (entry.Type != 1) throw new SqlException($"{entry.Path} is a {entry.Kind} entry, not an assembly");
        var lm = Add(Bundle.Extract(host, entry), null, $"{path}!/{entry.Path}");
        lm.Origin = "bundle";
        lm.Bundle = bundle;
        lm.BundleHost = host;
        // another entry of a bundle already open resolves into the same app assemblies, so it keeps them registered too
        if (lm.BundleDeps.Count == 0 && _modules.FirstOrDefault(m => m != lm && m.Bundle?.HostPath == bundle.HostPath) is { } sibling) lm.BundleDeps = sibling.BundleDeps;
        return lm;
    }

    /// <summary>Explains why a file dnlib refused is not a .NET module (null when it looks like one).</summary>
    public static string? NotDotNet(byte[] b)
    {
        if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return "not a .NET assembly: not a PE file (no MZ header)";
        int pe = BitConverter.ToInt32(b, 0x3C);
        if (pe < 0 || pe > b.Length - 0x18 || b[pe] != 'P' || b[pe + 1] != 'E' || b[pe + 2] != 0 || b[pe + 3] != 0)
            return "not a .NET assembly: MZ file without a PE header (DOS executable?)";
        var machine = (Machine)BitConverter.ToUInt16(b, pe + 4);
        bool dll = (BitConverter.ToUInt16(b, pe + 0x16) & 0x2000) != 0;
        int opt = pe + 0x18;
        if (opt + 2 > b.Length) return null;
        ushort magic = BitConverter.ToUInt16(b, opt);
        int dirs = opt + (magic == 0x20B ? 0x70 : 0x60), clr = dirs + 14 * 8;
        if (clr + 8 > b.Length) return null;
        int count = BitConverter.ToInt32(b, dirs - 4);
        if (count > 14 && BitConverter.ToUInt32(b, clr) != 0) return null;
        return $"not a .NET assembly: native {(magic == 0x20B ? "PE32+" : "PE32")} {(dll ? "DLL" : "executable")} ({machine}) without a CLR header";
    }

    public LoadedModule OpenBytes(byte[] bytes, string pseudoPath, bool memoryLayout = false, LoadedModule? untamperedFrom = null, uint untamperedBy = 0,
        LoadedModule? parent = null)
    {
        int count = _modules.Length;
        var lm = OpenBytesCore(bytes, pseudoPath, memoryLayout);
        if (_modules.Length == count) return lm; // the module of that name, opened before
        if (untamperedFrom != null) (lm.Origin, lm.DerivedFrom, lm.UntamperedBy) = ("untamper", untamperedFrom.Id, untamperedBy);
        else
        {
            lm.Origin = "bytes";
            lm.DerivedFrom = parent?.Id ?? (memoryLayout || bytes.Length < 256 ? null : Carrier(lm, bytes));
        }
        return lm;
    }

    // The module a stage came out of: one embedded_pes carves it from (a resource, also compressed or in pieces, or its
    // file bytes), else one whose file holds it byte for byte (a resource read with SQL). A payload decoded by hand
    // (decrypted, xored) is in neither: open_bytes() takes its parent as an argument.
    int? Carrier(LoadedModule lm, byte[] bytes)
    {
        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        return _modules.FirstOrDefault(m => m != lm && Tables.ProtectionTables.CarvedHashes(m).Contains(hash))?.Id
               ?? _modules.FirstOrDefault(m => m != lm && Contains(m.DiskBytes, bytes))?.Id;
    }

    // Where the blob's first 64 bytes occur, the rest compared; a bounded number of places, since crafted data (the same
    // bytes over and over) would otherwise make this quadratic.
    static bool Contains(byte[] file, byte[] blob)
    {
        if (file.Length <= blob.Length) return false;
        var head = blob.AsSpan(0, 64);
        int from = 0;
        for (int tries = 0; tries < 64; tries++)
        {
            int at = file.AsSpan(from).IndexOf(head);
            if (at < 0) return false;
            at += from;
            if (at + blob.Length > file.Length) return false;
            if (file.AsSpan(at, blob.Length).SequenceEqual(blob)) return true;
            from = at + 1;
        }
        return false;
    }

    LoadedModule OpenBytesCore(byte[] bytes, string pseudoPath, bool memoryLayout)
    {
        if (memoryLayout)
        {
            var opts = new ModuleCreationOptions(Context) { TryToLoadPdbFromDisk = false };
            var mod = ModuleDefMD.Load(new PEImage(bytes, ImageLayout.Memory, verify: false), opts);
            // Normalize to file layout so it can be saved and re-read.
            using var ms = new MemoryStream();
            if (mod.IsILOnly) mod.Write(ms, new ModuleWriterOptions(mod) { MetadataOptions = { Flags = MetadataFlags.PreserveAll } });
            else mod.NativeWrite(ms, new NativeModuleWriterOptions(mod, false) { MetadataOptions = { Flags = MetadataFlags.PreserveAll } });
            bytes = ms.ToArray();
        }
        return Add(bytes, null, pseudoPath);
    }

    LoadedModule Add(byte[] bytes, string? filePath, string displayPath)
    {
        var existing = _modules.FirstOrDefault(m => string.Equals(m.Path, displayPath, StringComparison.OrdinalIgnoreCase));
        if (existing != null) return existing;
        // a long session that forgets to close samples gets this instead of running the machine out of memory
        if (MaxModules > 0 && _modules.Length >= MaxModules)
            throw new SqlException($"{_modules.Length} modules are open (the process holds {Environment.WorkingSet >> 20:N0} MB): close() the ones you are " +
                                   "done with, or raise the runtime setting max_modules");
        var opts = new ModuleCreationOptions(Context) { TryToLoadPdbFromDisk = false };
        if (filePath != null)
        {
            var pdb = System.IO.Path.ChangeExtension(filePath, ".pdb");
            if (File.Exists(pdb)) opts.PdbFileOrData = pdb;
        }
        ModuleDefMD module;
        byte[]? fileBytes = null;
        string? repair = null;
        try
        {
            try { module = ModuleDefMD.Load(bytes, opts); }
            catch when (opts.PdbFileOrData != null) { opts.PdbFileOrData = null; module = ModuleDefMD.Load(bytes, opts); }
        }
        catch (Exception) when (DnSpySql.Bundle.AppHostTarget(bytes) is { } app)
        {
            // the launcher of a framework-dependent app: no .NET code of its own, the app is the assembly beside it
            throw new SqlException("not a .NET assembly: the app host (launcher) of a framework-dependent .NET app, with no .NET code of its own; " +
                                   (app.Length > 0 ? $"it starts {app}, which sits beside it: open that file" : "it starts an assembly beside it (same name, .dll): open that file"));
        }
        catch (Exception e) when (NotDotNet(bytes) is string why)
        {
            // a native dropper may still carry a .NET payload: the raw search that needs no module
            var carve = filePath != null && why.Contains(": native ", StringComparison.Ordinal)
                ? $"; to look for PE files inside it: SELECT offset, size, is_dotnet FROM carve_file WHERE path = '{filePath.Replace("'", "''")}'" : "";
            throw new SqlException(why + $" ({e.Message}){carve}");
        }
        catch (BadImageFormatException) when (ClrHeaderRepair.TryRepair(bytes, out var note) is byte[] fixedBytes)
        {
            opts.PdbFileOrData = null;
            module = ModuleDefMD.Load(fixedBytes, opts);
            (fileBytes, bytes, repair) = (bytes, fixedBytes, note);
        }
        if (filePath != null) module.Location = filePath;
        // Else the PDB the debug directory names (or an embedded one). dnlib looks for it next to the module's location,
        // which a module read from bytes only has from here on: during the load it would look in the current directory.
        if (filePath != null && module.PdbState == null)
            try { module.LoadPdb(); } catch (Exception) { } // a broken PDB costs the symbols, not the module
        module.EnableTypeDefFindCache = true;
        var lm = new LoadedModule { Id = ++_nextId, Module = module, Path = displayPath, OriginalBytes = bytes, FileBytes = fileBytes, Repair = repair, Ws = this };
        _modules = [.. _modules, lm];
        if (RefPaths.UsesNetFramework(module)) EnsureFrameworkPaths();
        if (module.Assembly != null) Resolver.AddToCache(module);
        if (_modules.Length == 1) CurrentModuleId = lm.Id;
        Revision++;
        return lm;
    }

    /// <summary>Extra directories (setting reference_paths) searched for referenced assemblies.</summary>
    public List<string> UserReferencePaths { get; } = new();
    public List<string> FrameworkPaths { get; } = new();
    /// <summary>Bumped whenever reference search paths change (invalidates decompiler snapshots).</summary>
    public int RefsVersion { get; private set; }
    public bool HasFrameworkTargets => _modules.Any(m => RefPaths.UsesNetFramework(m.Module));

    /// <summary>Puts .NET Framework directories ahead of the .NET runtime so mscorlib-based targets resolve real Framework types.</summary>
    public void EnsureFrameworkPaths()
    {
        foreach (var d in FrameworkPaths) Resolver.PostSearchPaths.Remove(d);
        FrameworkPaths.Clear();
        FrameworkPaths.AddRange(RefPaths.NetFramework(UserReferencePaths));
        for (int i = FrameworkPaths.Count - 1; i >= 0; i--) Resolver.PostSearchPaths.Insert(0, FrameworkPaths[i]);
        Revision++;
        RefsVersion++;
    }

    public void SetUserReferencePaths(IEnumerable<string> dirs)
    {
        foreach (var d in UserReferencePaths) Resolver.PreSearchPaths.Remove(d);
        UserReferencePaths.Clear();
        UserReferencePaths.AddRange(dirs.Select(System.IO.Path.GetFullPath));
        foreach (var d in UserReferencePaths) if (!Resolver.PreSearchPaths.Contains(d)) Resolver.PreSearchPaths.Add(d);
        if (HasFrameworkTargets) EnsureFrameworkPaths();
        Revision++;
        RefsVersion++;
    }

    public LoadedModule Get(int id) => _modules.FirstOrDefault(m => m.Id == id)
        ?? throw new SqlException(id > 0 && id <= _nextId ? $"module {id} was closed (close())" : $"no module with id {id}");

    public LoadedModule? Find(ModuleDef? module) => module == null ? null : _modules.FirstOrDefault(m => ReferenceEquals(m.Module, module));

    public LoadedModule ModuleArg(object? arg)
    {
        if (arg == null) return Get(CurrentModuleId);
        if (Values.ToLong(arg) is long id && arg is not string) return Get((int)id);
        var s = Values.ToText(arg)!;
        if (Values.ParseLong(s) is long n) return Get((int)n);
        return _modules.FirstOrDefault(m => string.Equals(m.Name, s, StringComparison.OrdinalIgnoreCase)
                                            || string.Equals(System.IO.Path.GetFileName(m.Path), s, StringComparison.OrdinalIgnoreCase))
               ?? throw new SqlException($"no module named '{s}'");
    }

    /// <summary>Normalizes a handle or bare token to a full handle.</summary>
    public long Normalize(long value) => Handle.Module(value) == 0 ? Handle.Make(CurrentModuleId, (uint)value) : value;

    public long? HandleArg(object? arg)
    {
        var v = Values.ToLong(arg);
        return v.HasValue ? Normalize(v.Value) : null;
    }

    public (LoadedModule lm, IMDTokenProvider item) Resolve(long handle)
    {
        handle = Normalize(handle);
        var lm = Get(Handle.Module(handle));
        var item = lm.Module.ResolveToken(Handle.Token(handle)) ?? throw new SqlException($"cannot resolve {Handle.Hex(handle)}");
        return (lm, item);
    }

    public T Resolve<T>(object? arg, string what) where T : class
    {
        var h = HandleArg(arg) ?? throw new SqlException($"{what}: a handle or token is required");
        var (_, item) = Resolve(h);
        return item as T ?? throw new SqlException($"{Handle.Hex(h)} is a {Handle.KindOf(Handle.Token(h))}, not a {what}");
    }

    public LoadedModule ModuleOf(IMemberDef? def) => Find(def?.Module) ?? throw new SqlException("member does not belong to a loaded module");

    /// <summary>Call after any mutation of a module's model.</summary>
    public void Touch(LoadedModule lm) { NoteEdit(lm); lm.Dirty = true; lm.Revision++; Revision++; lm.Module.ResetTypeDefFindCache(); DnSpyDecompiler.ForgetTimeouts(); }
    public void Touch(ModuleDef? m) { var lm = Find(m); if (lm != null) Touch(lm); }

    // The modules each undo group (statement) changed, so closing one can take the groups that would replay into it out
    // of the journal. Replays (undo/redo) touch modules too, but belong to the group they replay.
    readonly Dictionary<long, HashSet<int>> _groupModules = new();

    /// <summary>Records that the current statement changed this module (Touch does; raw patches, which leave the model alone, call it).</summary>
    public void NoteEdit(LoadedModule lm)
    {
        if (_replaying) return;
        if (!_groupModules.TryGetValue(_group, out var ids)) _groupModules[_group] = ids = new();
        ids.Add(lm.Id);
    }

    /// <summary>
    /// Takes modules out of the session (close()): the module list, the resolver's cache, and the journal, whose entries
    /// for them are marked so undo()/redo() say so instead of editing a disposed module. Their ids are not used again.
    /// </summary>
    public void Close(IReadOnlyCollection<int> ids)
    {
        var gone = _modules.Where(m => ids.Contains(m.Id)).ToList();
        if (gone.Count == 0) return;
        _modules = _modules.Where(m => !ids.Contains(m.Id)).ToArray();
        // the closed modules, and what their references loaded from disk (framework and side-by-side assemblies, each a
        // whole module): the resolver loads one again when an open module asks for it
        var keep = _modules.SelectMany(m => m.BundleDeps.Append(m.Module.Assembly)).OfType<AssemblyDef>().ToHashSet();
        Resolver.Forget(gone.Select(m => (ModuleDef)m.Module).ToList(), keep);
        foreach (var m in gone) m.Module.Dispose();
        // an open module with the same identity as a closed one (an untamper() copy, a second copy of a file) shared its
        // cache entry: registered again
        foreach (var m in _modules) if (m.Module.Assembly != null) Resolver.AddToCache(m.Module);
        _memo.Clear(); // references of the other modules resolved into these
        // a group that changed one of them cannot be replayed, and its closures hold the module (whole ModuleDefs, for a
        // whole-module edit): one light placeholder per group stays, so undo()/redo() can say what happened
        var affected = new Dictionary<long, int>();
        foreach (var (group, touched) in _groupModules)
            if (touched.FirstOrDefault(ids.Contains) is var id and > 0) affected[group] = id;
        Tombstone(UndoStack, affected);
        Tombstone(RedoStack, affected);
        if (_modules.Length > 0 && !_modules.Any(m => m.Id == CurrentModuleId)) CurrentModuleId = _modules.Min(m => m.Id);
        Revision++;
        RefsVersion++; // what references resolved to may have been in them
    }

    // ---- undo journal (IWriteSink) ----
    // Tables that live in the project file, not the model: writing them changes no IL, name or reference, so it does not
    // bump Revision (which would rebuild the whole CodeIndex on the next xref query, once per set_comment in a loop).
    static readonly HashSet<string> AnnotationTables = new(StringComparer.Ordinal)
    {
        "comments", "tags", "bookmarks", "kv", "breakpoints", "module_breakpoints", "exception_settings",
        "dnspy_debugger_settings", "dnspy_watch", "dnspy_documents", "dnspy_tabs",
    };

    public void Record(string table, string description, Action undo, Action redo)
    {
        if (_replaying) return;
        UndoStack.Add(new JournalEntry { Seq = ++_seq, Group = _group, Table = table, Description = description, Undo = undo, Redo = redo });
        RedoStack.Clear();
        if (!AnnotationTables.Contains(table)) Revision++;
    }

    public void Record(string description, Action undo, Action redo) => Record("function", description, undo, redo);

    /// <summary>Undoes the last <paramref name="count"/> groups (one group = one SQL statement or function call).</summary>
    public int Undo(int count = 1)
    {
        int n = 0;
        while (n < count && UndoStack.Count > 0)
        {
            var g = UndoStack[^1].Group;
            if (Dropped(UndoStack, g, "undo", n)) break;
            while (UndoStack.Count > 0 && UndoStack[^1].Group == g)
            {
                var e = UndoStack[^1];
                UndoStack.RemoveAt(UndoStack.Count - 1);
                _replaying = true;
                try { e.Undo(); } finally { _replaying = false; }
                RedoStack.Add(e);
            }
            n++;
        }
        if (n > 0) TouchAllDirty();
        return n;
    }

    public int Redo(int count = 1)
    {
        int n = 0;
        while (n < count && RedoStack.Count > 0)
        {
            var g = RedoStack[^1].Group;
            if (Dropped(RedoStack, g, "redo", n)) break;
            while (RedoStack.Count > 0 && RedoStack[^1].Group == g)
            {
                var e = RedoStack[^1];
                RedoStack.RemoveAt(RedoStack.Count - 1);
                _replaying = true;
                try { e.Redo(); } finally { _replaying = false; }
                UndoStack.Add(e);
            }
            n++;
        }
        if (n > 0) TouchAllDirty();
        return n;
    }

    static readonly Action Nothing = () => { };

    static void Tombstone(List<JournalEntry> stack, Dictionary<long, int> affected)
    {
        for (int i = stack.Count - 1; i >= 0; i--)
        {
            var e = stack[i];
            if (!affected.TryGetValue(e.Group, out var id)) continue;
            if (i + 1 < stack.Count && stack[i + 1].Group == e.Group) { stack.RemoveAt(i); continue; } // one per group
            stack[i] = new JournalEntry { Seq = e.Seq, Group = e.Group, Table = e.Table, Description = e.Description, Time = e.Time,
                                          Undo = Nothing, Redo = Nothing, ClosedModule = id };
        }
    }

    // A group that changed a module closed since is taken out of the history (it cannot be replayed): undo()/redo() stop
    // there, and when it is the first group they reach they say so; called again, they go on to the group before it.
    static bool Dropped(List<JournalEntry> stack, long group, string what, int done)
    {
        if (stack.LastOrDefault(e => e.Group == group && e.ClosedModule != null)?.ClosedModule is not int closed) return false;
        stack.RemoveAll(e => e.Group == group);
        if (done > 0) return true;
        throw new SqlException($"the last change was to module {closed}, which close() removed; it is dropped from the {what} history, " +
                               $"and {what}() again goes on to the change before it");
    }

    void TouchAllDirty() { Revision++; foreach (var m in _modules.Where(m => m.Dirty)) { m.Revision++; m.Module.ResetTypeDefFindCache(); } }

    // ---- saving ----
    /// <summary>When true, edited ReadyToRun images are written IL-only (setting save_strip_ready_to_run).</summary>
    public bool StripReadyToRun { get; set; } = true;

    public ModuleWriterOptionsBase WriterOptions(LoadedModule lm, bool preserveTokens = true, bool writePdb = true)
    {
        var module = lm.Module;
        bool ilOnly = module.IsILOnly || lm.IsReadyToRun && StripReadyToRun;
        ModuleWriterOptionsBase o = ilOnly
            ? new ModuleWriterOptions(module)
            : new NativeModuleWriterOptions(module, optimizeImageSize: false);
        if (ilOnly && !module.IsILOnly)
        {
            // Drop the precompiled code: the runtime would otherwise keep using it and ignore IL edits.
            o.Cor20HeaderOptions.Flags = (module.Cor20HeaderFlags | dnlib.DotNet.MD.ComImageFlags.ILOnly) & ~dnlib.DotNet.MD.ComImageFlags.ILLibrary;
        }
        if (preserveTokens) o.MetadataOptions.Flags |= MetadataFlags.PreserveAll | MetadataFlags.KeepOldMaxStack;
        if (writePdb && module.PdbState != null) o.WritePdb = true;
        o.Logger = DummyLogger.NoThrowInstance;
        return o;
    }

    public byte[] Serialize(LoadedModule lm, bool preserveTokens = true)
    {
        using var ms = new MemoryStream();
        var o = WriterOptions(lm, preserveTokens, writePdb: false);
        if (o is NativeModuleWriterOptions n) lm.Module.NativeWrite(ms, n); else lm.Module.Write(ms, (ModuleWriterOptions)o);
        return ms.ToArray();
    }

    public string Save(LoadedModule lm, string path, bool preserveTokens = true)
    {
        path = System.IO.Path.GetFullPath(path);
        if (lm.RawPatches.Count > 0 && !lm.Dirty) return SaveRaw(lm, path);
        if (lm.RawPatches.Count > 0) throw new SqlException("module has both raw byte patches and model edits; use save_raw() or revert one of them");
        var o = WriterOptions(lm, preserveTokens);
        if (o.WritePdb) o.PdbFileName = System.IO.Path.ChangeExtension(path, ".pdb");
        var tmp = path + ".tmp";
        if (o is NativeModuleWriterOptions n) lm.Module.NativeWrite(tmp, n); else lm.Module.Write(tmp, (ModuleWriterOptions)o);
        File.Move(tmp, path, overwrite: true);
        lm.Dirty = false;
        return path;
    }

    public string SaveRaw(LoadedModule lm, string path)
    {
        var bytes = (byte[])lm.DiskBytes.Clone();
        foreach (var (off, b) in lm.RawPatches) if (off < bytes.Length) bytes[off] = b;
        path = System.IO.Path.GetFullPath(path);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>
    /// Runs an edit that restructures the module (type splicing) and journals it as one step. The edit runs on a copy
    /// (serialized with all tokens preserved, so handles stay valid) and the module instance from before is kept as it
    /// was: undo swaps it back, and the journal entries recorded before the edit, which hold its objects, work again.
    /// </summary>
    public T SnapshotEdit<T>(LoadedModule lm, string description, Func<T> edit)
    {
        var before = lm.Module;
        bool dirty = lm.Dirty;
        Swap(lm, Load(lm, Serialize(lm)));
        T result;
        try { result = edit(); }
        catch
        {
            // nothing changed: not dirty either (dnSpy exports skip dirty modules)
            Swap(lm, before);
            lm.Dirty = dirty;
            throw;
        }
        // re-read what the edit produced: members it added have no token until written (resolve() and handles would
        // see 0x06000000), and this gives them the ones save() writes
        Swap(lm, Load(lm, Serialize(lm)));
        var after = lm.Module;
        Record("module", description, () => Swap(lm, before), () => Swap(lm, after));
        return result;
    }

    ModuleDefMD Load(LoadedModule lm, byte[] image)
    {
        var module = ModuleDefMD.Load(image, new ModuleCreationOptions(Context) { TryToLoadPdbFromDisk = false });
        module.Location = lm.Module.Location;
        module.EnableTypeDefFindCache = true;
        return module;
    }

    void Swap(LoadedModule lm, ModuleDefMD module)
    {
        var old = lm.Module;
        Resolver.Remove(old);
        lm._fileMetadata ??= old.Metadata; // still the file's: the first module was read from OriginalBytes
        lm.Module = module;
        if (module.Assembly != null) Resolver.AddToCache(module);
        Touch(lm);
    }

    /// <summary>Current file image including raw patches (what the hex view shows).</summary>
    public byte RawByte(LoadedModule lm, long offset) => lm.RawPatches.TryGetValue(offset, out var b) ? b : lm.DiskBytes[offset];

    public void Dispose()
    {
        foreach (var m in _modules) m.Module.Dispose();
        _modules = [];
    }
}

/// <summary>
/// dnlib looks for a referenced assembly at Path.Combine(searchDir, name + ".dll"), and a sample chooses its references'
/// names: one named \\host\share\x would make the resolver probe that share (sending the analyst's NTLM credentials),
/// and C:\... or ..\.. would read files outside the search paths. A name that is not a plain file name resolves to nothing.
/// </summary>
public sealed class SafeAssemblyResolver : AssemblyResolver, IAssemblyResolver
{
    static bool Plain(IAssembly? a) => a?.Name?.String is { } n && n.IndexOfAny(['\\', '/', ':']) < 0 && n.Trim('.').Length > 0;

    // both: callers through IAssemblyResolver (dnlib, the decompiler) and through Workspace.Resolver
    AssemblyDef? IAssemblyResolver.Resolve(IAssembly assembly, ModuleDef sourceModule) => Plain(assembly) ? base.Resolve(assembly, sourceModule) : null;
    public new AssemblyDef? Resolve(IAssembly assembly, ModuleDef sourceModule) => Plain(assembly) ? base.Resolve(assembly, sourceModule) : null;

    // For the resolver's life dnlib keeps each module's search paths, keyed by the module, and every assembly it loaded,
    // under each name it was asked for (aliases too); its public Remove drops one name. Both caches are private.
    static readonly System.Reflection.FieldInfo? SearchPaths =
        typeof(AssemblyResolver).GetField("moduleSearchPaths", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
    static readonly System.Reflection.FieldInfo? Cached =
        typeof(AssemblyResolver).GetField("cachedAssemblies", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);

    /// <summary>Lets go of closed modules and of every cached assembly not in keep (close()); a dnlib that renames its caches gets the public calls.</summary>
    internal void Forget(IReadOnlyCollection<ModuleDef> closed, IReadOnlySet<AssemblyDef> keep)
    {
        if (SearchPaths?.GetValue(this) is System.Collections.IDictionary paths) foreach (var m in closed) paths.Remove(m);
        if (Cached?.GetValue(this) is System.Collections.IDictionary cached)
        {
            foreach (var key in cached.Keys.Cast<object>().ToList())
                if (cached[key] is not AssemblyDef a || !keep.Contains(a)) cached.Remove(key);
        }
        else
            foreach (var a in GetCachedAssemblies().Where(a => !keep.Contains(a)).ToList()) Remove(a);
    }
}

// dnlib resolves a TypeRef or MemberRef by searching the target assembly each time; the decompiler asks for the
// same references over and over (every call site of String.Concat, say), which doubled decompile time once the
// framework became resolvable. Results are kept per reference object until the workspace changes, since an edit
// (a rename, a deleted member) can change what a reference resolves to. The table is weak, so references the
// decompiler creates on the fly are not kept alive, and it is safe for export_project's parallel decompiles.
sealed class MemoResolver(IResolver inner, Func<long> version) : IResolver
{
    sealed record Entry(long Version, object? Value);
    readonly System.Runtime.CompilerServices.ConditionalWeakTable<object, Entry> memo = new();

    T? Get<T>(object key, Func<T?> resolve) where T : class
    {
        long v = version();
        if (memo.TryGetValue(key, out var hit) && hit.Version == v) return (T?)hit.Value;
        var r = resolve();
        memo.AddOrUpdate(key, new Entry(v, r));
        return r;
    }

    public TypeDef? Resolve(TypeRef typeRef, ModuleDef sourceModule) =>
        Get(typeRef, () => inner.Resolve(typeRef, sourceModule));

    public IMemberForwarded? Resolve(MemberRef memberRef) =>
        Get(memberRef, () => inner.Resolve(memberRef));

    public void Clear() => memo.Clear();
}

