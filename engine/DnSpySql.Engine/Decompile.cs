// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Text;
using dnSpy.Decompiler.ILSpy.Core.CSharp;
using dnSpy.Decompiler.ILSpy.Core.IL;
using dnSpy.Decompiler.ILSpy.Core.Settings;
using DnSpySql.Sql;
using ICSharpCode.Decompiler.Ast;

namespace DnSpySql;

public sealed class DecompiledLine
{
    public int Line;
    public string Text = "";
    public int? ILOffset;
    /// <summary>Exclusive end of the IL range attributed to this line (next statement start of the same method).</summary>
    public int? ILEnd;
    public long? Method;
}

/// <summary>A name in the decompiled text and what it refers to (dnSpy's click-to-definition data).</summary>
public sealed class DecompiledRef
{
    public int Line;
    /// <summary>1-based column of the first character on its line.</summary>
    public int Column;
    public int Length;
    public string Text = "";
    /// <summary>type | method | field | property | event | local | parameter | label | data | opcode | namespace | keyword | other</summary>
    public string Kind = "other";
    /// <summary>Handle of the definition when it lives in a loaded module.</summary>
    public long? Target;
    public string? TargetName;
    public bool IsDefinition, IsWrite, IsLocal, IsHidden;
}

public sealed class DecompileResult
{
    public string Text = "";
    public bool Completed = true;
    public string? Error;
    public List<DecompiledLine> Lines = new();
    /// <summary>
    /// The names in <see cref="Text"/> and what they refer to, worked out on first use: describing them resolves every
    /// member reference, which decompile() alone does not need.
    /// </summary>
    public List<DecompiledRef> Refs => _refs ??= MakeRefs?.Invoke() ?? new();
    internal Func<List<DecompiledRef>>? MakeRefs;
    List<DecompiledRef>? _refs;
}

/// <summary>
/// The session's decompiler: dnSpyEx's engine (Decompile below) over the live dnlib model, with results cached until the
/// module changes, and a line table built from the statement/IL mapping dnSpy's debugger uses.
/// </summary>
public sealed class DecompilerService
{
    readonly Session _s;
    readonly Dictionary<(long handle, string lang, long rev), DecompileResult> _cache = new();

    public DecompilerService(Session s) { _s = s; }

    public static string NormalizeLanguage(string? language) => (language ?? "csharp").Trim().ToLowerInvariant() switch
    {
        "" or "csharp" or "cs" or "c#" => "csharp",
        "il" or "cil" or "msil" => "il",
        var other => throw new SqlException($"unknown language '{other}' (csharp | il)"),
    };

    // Decompiling is the expensive call and a query often names the same result more than once (SQLite inlines
    // `select f(d), g(d) from (select decompile(token) d ...)` as two calls), so results are kept until the module
    // is next edited.
    public DecompileResult Decompile(long handle, string? language = null)
    {
        handle = _s.Ws.Normalize(handle);
        var lm = _s.Ws.Get(Handle.Module(handle));
        var lang = NormalizeLanguage(language ?? _s.Settings["decompiler_language"].Value);
        var key = (handle, lang, (long)lm.Revision * 1000 + _s.Ws.RefsVersion);
        if (_cache.TryGetValue(key, out var hit)) return hit;
        var token = Handle.Token(handle);
        var entity = lm.Module.ResolveToken(token) ?? throw new SqlException($"cannot resolve {Handle.Hex(handle)}");
        var r = new DecompileResult();
        var piece = DnSpyDecompiler.Entity(lm, entity, lang == "il" ? DnSpyDecompiler.Lang.Il : DnSpyDecompiler.Lang.CSharp);
        r.Text = piece.Text + (Note(lm, entity) is { } note ? (piece.Text.EndsWith('\n') ? "" : "\n") + note + "\n" : "");
        if (piece.Error != null) { r.Completed = false; r.Error = piece.Error; }
        r.Lines = Lines(lm, piece);
        r.MakeRefs = () => Refs(piece);
        if (_cache.Count > 2000) _cache.Clear();
        _cache[key] = r;
        return r;
    }

    // Bodies that do not decode as IL in the file (anti-tamper encrypts them until runtime) come out of the decompiler
    // as empty or garbage methods, which reads as real code. Say so, after the code, so dnSpy's line numbers stay.
    static string? Note(LoadedModule lm, IMDTokenProvider entity)
    {
        try { return Undecodable(lm, entity); }
        catch (Exception e) when (e is not OutOfMemoryException) { return null; } // a note must never cost the decompilation
    }

    static string? Undecodable(LoadedModule lm, IMDTokenProvider entity)
    {
        static IEnumerable<MethodDef> All(TypeDef t) => t.Methods.Concat(t.NestedTypes.SelectMany(All));
        var methods = entity switch
        {
            MethodDef md => [md],
            TypeDef td => All(td).ToList(),
            PropertyDef p => p.GetMethods.Concat(p.SetMethods).Concat(p.OtherMethods).ToList(),
            EventDef e => new[] { e.AddMethod, e.RemoveMethod, e.InvokeMethod }.OfType<MethodDef>().ToList(),
            _ => new List<MethodDef>(),
        };
        if (methods.Count == 0) return null;
        var bad = DnSpySql.Tables.HexTables.Undecodable(lm);
        var hit = methods.Where(m => bad.ContainsKey(m.MDToken.Raw)).ToList();
        if (hit.Count == 0) return null;
        const string why = "encrypted until runtime, as anti-tamper protectors do. method_bodies shows the details; dnSpy shows the real code " +
                           "once the process has decrypted it (debug it and open the module from memory)";
        return entity is MethodDef
            ? $"// dnspysql: this method's body does not decode as IL in the file ({bad[hit[0].MDToken.Raw]}): {why}."
            : $"// dnspysql: {hit.Count} of {methods.Count} method bodies here do not decode as IL in the file and show as empty or garbage: {why}.";
    }

    // One row per text line; a line where a statement starts gets that statement's IL offset (the first one when
    // several start on it) and the method the IL belongs to (MoveNext for async/iterator code).
    static List<DecompiledLine> Lines(LoadedModule lm, DnSpyDecompiler.Piece piece)
    {
        var text = piece.Text.TrimEnd('\n', '\r');
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++) if (text[i] == '\n') starts.Add(i + 1);
        var lines = new List<DecompiledLine>(starts.Count);
        for (int i = 0; i < starts.Count; i++)
        {
            int end = i + 1 < starts.Count ? starts[i + 1] - 1 : text.Length;
            lines.Add(new DecompiledLine { Line = i + 1, Text = text[starts[i]..end].TrimEnd('\r') });
        }
        foreach (var st in piece.Statements.OrderBy(x => x.TextStart).ThenBy(x => x.ILStart))
        {
            int idx = starts.BinarySearch(st.TextStart);
            if (idx < 0) idx = ~idx - 1;
            if (idx < 0 || idx >= lines.Count || lines[idx].ILOffset != null) continue;
            lines[idx].ILOffset = (int)st.ILStart;
            lines[idx].ILEnd = (int)st.ILEnd;
            lines[idx].Method = lm.H(st.Method);
        }
        return lines;
    }

    // The references dnSpy attaches to names in its output, with line/column and, where the target is a definition in a
    // loaded module, its handle.
    List<DecompiledRef> Refs(DnSpyDecompiler.Piece piece)
    {
        var text = piece.Text;
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++) if (text[i] == '\n') starts.Add(i + 1);
        var refs = new List<DecompiledRef>(piece.Refs.Count);
        foreach (var x in piece.Refs)
        {
            if (x.Start < 0 || x.Length <= 0 || x.Start + x.Length > text.Length) continue;
            int line = starts.BinarySearch(x.Start);
            if (line < 0) line = ~line - 1;
            var (kind, target, name) = Describe(x.Reference);
            refs.Add(new DecompiledRef
            {
                Line = line + 1, Column = x.Start - starts[line] + 1, Length = x.Length, Text = text.Substring(x.Start, x.Length),
                Kind = kind, Target = target, TargetName = name,
                IsDefinition = (x.Flags & DecompilerReferenceFlags.Definition) != 0, IsWrite = (x.Flags & DecompilerReferenceFlags.IsWrite) != 0,
                IsLocal = (x.Flags & DecompilerReferenceFlags.Local) != 0, IsHidden = (x.Flags & DecompilerReferenceFlags.Hidden) != 0,
            });
        }
        return refs;
    }

    // What a reference object points at: its kind, the handle of its definition when that is in a loaded module, a name.
    (string kind, long? target, string? name) Describe(object reference)
    {
        long? H(IMemberDef? d) => d?.Module is { } mod ? _s.Ws.Find(mod)?.H(d) : null;
        static T? Try<T>(Func<T?> f) where T : class { try { return f(); } catch (Exception) { return null; } }
        switch (reference)
        {
            case TypeDef t: return ("type", H(t), t.FullName);
            case MethodDef m: return ("method", H(m), m.FullName);
            case FieldDef f: return ("field", H(f), f.FullName);
            case PropertyDef p: return ("property", H(p), p.FullName);
            case EventDef e: return ("event", H(e), e.FullName);
            case ITypeDefOrRef tr: return ("type", H(Try(() => tr.ResolveTypeDef())), tr.FullName);
            case MethodSpec ms: return ("method", H(Try(() => ms.ResolveMethodDef())), ms.FullName);
            case MemberRef mr when mr.IsFieldRef: return ("field", H(Try(() => mr.ResolveFieldDef())), mr.FullName);
            case MemberRef mr: return ("method", H(Try(() => mr.ResolveMethodDef())), mr.FullName);
            case SourceParameter sp: return ("parameter", null, sp.Name);
            case SourceLocal sl: return ("local", null, sl.Name);
            case Parameter pa: return ("parameter", null, pa.Name);
            case Local lo: return ("local", null, lo.Name);
            case ICSharpCode.Decompiler.ILAst.ILVariable v: return (v.IsParameter ? "parameter" : "local", null, v.Name);
            case Tuple<FieldDef, RVA> data: return ("data", H(data.Item1), data.Item1.FullName);
            case OpCode op: return ("opcode", null, op.Name);
            case NamespaceReference ns: return ("namespace", null, ns.Namespace);
            case string s: return ("keyword", null, s);
            default: return (reference.GetType().Name.Contains("Label", StringComparison.Ordinal) ? "label" : "other", null, reference.ToString());
        }
    }

    public string Il(LoadedModule lm, uint token) => Decompile(lm.H(token), "il").Text;

    public string DecompileModule(LoadedModule lm, string? language = null) =>
        DnSpyDecompiler.Module(lm, NormalizeLanguage(language) == "il" ? DnSpyDecompiler.Lang.Il : DnSpyDecompiler.Lang.CSharp);

    /// <summary>dnSpy's BAML decompiler: a compiled WPF resource back to XAML.</summary>
    public string BamlToXaml(LoadedModule lm, byte[] baml) => Baml.ToXaml(lm.Module, baml, _s.Db.Cancellation);

    /// <summary>dnSpy's File > Export to Project for the given modules; returns the solution path.</summary>
    public string ExportProject(IReadOnlyList<LoadedModule> modules, string dir, bool sdkStyle) => Export.Project(modules, dir, sdkStyle);
}

// Decompilation runs on dnSpyEx's decompiler (a dnlib-backed fork of ILSpy),
// vendored under engine/vendor. It reads the *live* dnlib model this session
// already holds, so there is no second parse of the file and no re-serialization
// after an edit: renames, stubs and IL patches show up immediately. It also
// inherits dnlib's tolerance of the malformed metadata that protected
// assemblies carry, where a System.Reflection.Metadata reader gives up.
static class DnSpyDecompiler
{
    // A decompilation failure is reported as a comment *value* rather than a SQL
    // error, so `select decompile(token) from types` yields a row per type
    // instead of aborting on the first unreadable one. Find them with
    // `where decompile(token) like '/* dnspysql:%'`.
    public const string FailMarker = "/* dnspysql: ";

    // The ILSpy v2-era engine has pathological cases on obfuscated control flow
    // where one method never finishes. A method gets this budget, a whole type
    // this plus a second per method body; a method that exceeds it is dropped
    // from its type (see TypeText) instead of hanging the query.
    public static readonly TimeSpan Budget = TimeSpan.FromSeconds(20);

    // The statement's cancellation (interrupt or query timeout): unlike the budget, it stops the query instead of
    // being reported as a decompiler failure.
    internal static Func<CancellationToken> Outer = () => CancellationToken.None;
    static bool Interrupted => Outer().IsCancellationRequested;

    // Methods that ran out of the budget: decompiling one again would take the whole budget again (a type with one cost
    // 86 s: the whole-type attempt, the per-method pass, the re-run). Forgotten on any model edit (an analyst nops out the
    // flattening and decompiles again) and after export_project, whose parallel decompiles can time out from contention.
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<MethodDef, CilBody> _timedOut = new();

    internal static void ForgetTimeouts() => _timedOut.Clear();

    static bool TimedOut(MethodDef md) => _timedOut.TryGetValue(md, out var body) && md.Body is var b && ReferenceEquals(body, b);

    static Piece Method(IDecompiler dec, MethodDef md, TimeSpan? budget = null)
    {
        // only the C# decompiler's analysis can run long: the IL listing, which the timeout note points to, always works
        bool memo = dec is not ILDecompiler;
        if (memo && TimedOut(md)) throw new OperationCanceledException();
        try { return Run((o, c) => dec.Decompile(md, o, c), budget); }
        // remembered only when it had the full budget
        catch (OperationCanceledException) when (memo && !Interrupted && budget == null && md.Body is { } b) { _timedOut.AddOrUpdate(md, b); throw; }
    }

    // After a whole type ran out of its budget, each method gets this much to show it is not the slow one.
    static readonly TimeSpan ProbeBudget = TimeSpan.FromSeconds(5);

    static TimeSpan TypeBudget(TypeDef type) =>
        Budget + TimeSpan.FromSeconds(new[] { type }.Concat(type.GetTypes()).Sum(t => t.Methods.Count(m => m.HasBody)));

    static string Fail(string what, Exception e) =>
        $"{FailMarker}{what} failed: {Reason(e)} */";

    static string Reason(Exception e) => e is OperationCanceledException
        ? "exceeded the decompile time budget"
        : e.Message.ReplaceLineEndings(" ").Replace("*/", "* /").Trim();

    public enum Lang { CSharp, Il }

    // The decompilers are stateless with respect to the module (it is passed per
    // call), so one instance each is enough for the session.
    static readonly CSharpVBDecompilerSettings csharpSettings = new();
    static readonly Lazy<CSharpDecompiler> csharp = new(() => new CSharpDecompiler(csharpSettings, 0));
    static readonly Lazy<IDecompiler> il =
        new(() => new ILDecompiler(new ILDecompilerSettings()));

    static IDecompiler For(Lang lang) => lang switch
    {
        Lang.Il => il.Value,
        _ => csharp.Value,
    };

    static DecompilationContext Ctx(CancellationToken ct) => new()
    {
        CancellationToken = ct,
        // dnlib is the single source of truth here, so a body is "modified"
        // exactly when this session edited it.
        IsBodyModified = _ => false,
        // Statement -> IL spans, the mapping dnSpy's debugger uses (pseudocode_lines).
        CalculateILSpans = true,
    };

    static CancellationTokenSource Budgeted(TimeSpan budget)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(Outer());
        cts.CancelAfter(budget);
        return cts;
    }

    /// <summary>A statement of the output: where its text starts and the IL it covers.</summary>
    public readonly record struct Statement(int TextStart, uint ILStart, uint ILEnd, MethodDef Method);

    /// <summary>A reference the decompiler attached to a span of its output (what dnSpy makes clickable).</summary>
    public readonly record struct RefSpan(int Start, int Length, object Reference, DecompilerReferenceFlags Flags);

    /// <summary>Decompiled text, its statements and references, and the error when the entity could not be decompiled.</summary>
    public sealed record Piece(string Text, List<Statement> Statements, string? Error = null, List<RefSpan>? RefSpans = null)
    {
        public List<RefSpan> Refs => RefSpans ?? [];
        public Piece Shift(string prefix) =>
            new(prefix + Text, Statements.Select(s => s with { TextStart = s.TextStart + prefix.Length }).ToList(), Error,
                Refs.Select(r => r with { Start = r.Start + prefix.Length }).ToList());
    }

    // dnSpy's StringBuilderDecompilerOutput implements the custom-data members explicitly and ignores them;
    // re-implementing the interface here receives the debug info dnSpy emits for every decompiled method. The
    // reference overloads record what each name in the output refers to.
    sealed class DebugOutput : StringBuilderDecompilerOutput, IDecompilerOutput
    {
        public readonly List<Statement> Statements = new();
        public readonly List<RefSpan> Refs = new();
        bool IDecompilerOutput.UsesCustomData => true;
        void IDecompilerOutput.AddCustomData<TData>(string id, TData data)
        {
            if (id != PredefinedCustomDataIds.DebugInfo || data is not MethodDebugInfo info) return;
            foreach (var st in info.Statements)
                Statements.Add(new Statement(st.TextSpan.Start, st.ILSpan.Start, st.ILSpan.End, info.Method));
        }

        public override void Write(string text, object? reference, DecompilerReferenceFlags flags, object color)
        {
            if (reference != null && text.Length > 0) Refs.Add(new RefSpan(NextPosition, text.Length, reference, flags));
            base.Write(text, reference, flags, color);
        }

        public override void Write(string text, int index, int length, object? reference, DecompilerReferenceFlags flags, object color)
        {
            if (reference != null && length > 0) Refs.Add(new RefSpan(NextPosition, length, reference, flags));
            base.Write(text, index, length, reference, flags, color);
        }
    }

    // Runs one decompile under the budget and returns its text; throws
    // OperationCanceledException when the budget runs out.
    static Piece Run(Action<IDecompilerOutput, DecompilationContext> decompile, TimeSpan? budget = null)
    {
        using var cts = Budgeted(budget ?? Budget);
        var output = new DebugOutput();
        decompile(output, Ctx(cts.Token));
        return new Piece(output.ToString(), output.Statements, null, output.Refs);
    }

    public static Piece Entity(LoadedModule m, IMDTokenProvider entity, Lang lang)
    {
        XmlDocGuard.Check(m.Module);
        var dec = For(lang);
        try
        {
            return entity switch
            {
                TypeDef t => TypeText(dec, t, lang),
                MethodDef md => Method(dec, md),
                FieldDef f => Run((o, c) => dec.Decompile(f, o, c)),
                PropertyDef pd => Run((o, c) => dec.Decompile(pd, o, c)),
                EventDef ev => Run((o, c) => dec.Decompile(ev, o, c)),
                _ => throw new SqlException(
                    $"0x{entity.MDToken.Raw:X8} is a {Handle.KindOf(entity.MDToken.Raw)}, not a type/method/field/property/event definition"),
            };
        }
        catch (Exception e) when (e is not OutOfMemoryException and not SqlException && !Interrupted)
        {
            var fail = Fail($"decompile 0x{entity.MDToken.Raw:X8}", e);
            return new Piece(fail + IlFallback(lang, entity), new(), fail[FailMarker.Length..^3]);
        }
    }

    // On a C# failure the IL is still worth having, so it follows the marker.
    static string IlFallback(Lang lang, object entity)
    {
        if (lang != Lang.CSharp) return "";
        try
        {
            var text = entity switch
            {
                TypeDef t => Run((o, c) => il.Value.Decompile(t, o, c)).Text,
                MethodDef md => Run((o, c) => il.Value.Decompile(md, o, c)).Text,
                _ => null,
            };
            return text is null ? "" : "\n" + text;
        }
        catch (Exception e) when (e is not OutOfMemoryException && !Interrupted) { return ""; }
    }

    // A type is decompiled whole. If that fails or runs out of budget, the
    // methods that cause it are found one by one and the type is decompiled
    // again with their bodies left empty, so one bad method costs only itself.
    // (dnSpy already contains most per-method failures; what escapes are
    // timeouts and whole-tree transform crashes such as DeclareVariables'
    // "Cannot replace the root node".)
    static Piece TypeText(IDecompiler dec, TypeDef type, Lang lang)
    {
        var methods = new[] { type }.Concat(type.GetTypes()).SelectMany(t => t.Methods).Where(m => m.HasBody).ToList();
        var bad = new Dictionary<MethodDef, Exception>();
        // a method known to run out of the budget fails the whole type too: go straight to skipping it
        if (lang == Lang.CSharp && methods.Where(TimedOut).ToList() is { Count: > 0 } known)
        {
            foreach (var md in known) bad[md] = new OperationCanceledException();
            try { return Skipping(type, bad); }
            catch (Exception e) when (e is not OutOfMemoryException && !Interrupted) { bad.Clear(); }
        }

        Exception whole;
        try { return Run((o, c) => dec.Decompile(type, o, c), TypeBudget(type)); }
        catch (Exception e) when (lang == Lang.CSharp && e is not OutOfMemoryException && !Interrupted) { whole = e; }

        var probe = whole is OperationCanceledException ? ProbeBudget : (TimeSpan?)null;
        foreach (var md in methods)
        {
            try { Method(dec, md, probe); }
            catch (Exception e) when (e is not OutOfMemoryException && !Interrupted)
            {
                bad[md] = e;
                // the whole type ran out of its budget and this method of its probe: the slow one, remembered so the next
                // decompile of the type goes straight to skipping it (a type with one cost 71 s each time)
                if (e is OperationCanceledException && whole is OperationCanceledException && md.Body is { } b) _timedOut.AddOrUpdate(md, b);
            }
        }
        if (bad.Count == 0) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(whole);
        return Skipping(type, bad);
    }

    // The type with the given methods' bodies left empty, each named in a comment above it.
    static Piece Skipping(TypeDef type, Dictionary<MethodDef, Exception> bad)
    {
        var sb = new StringBuilder();
        foreach (var (md, e) in bad)
            sb.Append($"// dnspysql: {md.FullName} (0x{md.MDToken.Raw:X8}) ")
              .Append($"{(e is OperationCanceledException ? "" : "failed: ")}{Reason(e)}; ")
              .Append($"its body is left empty, see il_text(0x{md.MDToken.Raw:X8})\n");
        var rest = Run((o, c) => DecompileTypeSkipping(type, bad.Keys.ToHashSet(), o, c), TypeBudget(type));
        return rest.Shift(sb.ToString()) with { Error = $"{bad.Count} method(s) could not be decompiled" };
    }

    // CSharpDecompiler.Decompile(TypeDef) with a body-kind hook: the same
    // pipeline (builder pool, transforms, XML docs) dnSpy uses, but the skipped
    // methods get an empty body instead of a decompiled one.
    static void DecompileTypeSkipping(TypeDef type, HashSet<MethodDef> skip, IDecompilerOutput output, DecompilationContext ctx)
    {
        var settings = csharpSettings.Settings;
        var cache = ctx.GetOrCreate(() => new BuilderCache(settings.SettingsVersion));
        var state = new BuilderState(ctx, cache, CSharpMetadataTextColorProvider.Instance);
        try
        {
            var b = state.AstBuilder;
            b.Context.CurrentModule = type.Module;
            b.Context.CancellationToken = ctx.CancellationToken;
            b.Context.CurrentType = type;
            b.Context.Settings = settings;
            b.GetDecompiledBodyKind = (_, md) => skip.Contains(md) ? DecompiledBodyKind.Empty : DecompiledBodyKind.Full;
            b.AddType(type);
            b.RunTransformations();
            CSharpDecompiler.AddXmlDocumentation(ref state, settings, b);
            b.GenerateCode(output);
        }
        finally
        {
            state.Dispose();
        }
    }

    // The decompiler export_project hands to dnSpy's project exporter: dnSpy's C# decompiler, except that every
    // type file goes through TypeText (time budget, one bad method costs only itself) and every partial type
    // (WinForms designer and settings splits) gets the same per-type budget. Each file is decompiled into a buffer
    // first, so a failure becomes a comment instead of a truncated file.
    public static IDecompiler Exporter { get; } = new ExportDecompiler();

    // One context for a whole export. Method bodies are decompiled synchronously, as in dnSpy's exporter.
    public static DecompilationContext ExportContext()
    {
        var ctx = Ctx(CancellationToken.None);
        ctx.AsyncMethodBodyDecompilation = false;
        ctx.CalculateILSpans = false;
        return ctx;
    }

    sealed class ExportDecompiler : IDecompiler
    {
        static IDecompiler D => csharp.Value;

        public void Decompile(TypeDef type, IDecompilerOutput output, DecompilationContext ctx)
        {
            string text;
            try { text = TypeText(D, type, Lang.CSharp).Text; }
            catch (Exception e) when (e is not OutOfMemoryException && !Interrupted) { text = Fail($"decompile {type.FullName} (0x{type.MDToken.Raw:X8})", e) + "\n"; }
            output.Write(text, BoxedTextColor.Text);
        }

        public void Decompile(DecompilationType decompilationType, object data)
        {
            if (data is not DecompilePartialType p)
            {
                D.Decompile(decompilationType, data);
                return;
            }
            var buffer = new StringBuilderDecompilerOutput();
            try
            {
                using var cts = Budgeted(TypeBudget(p.Type));
                var q = new DecompilePartialType(buffer, Ctx(cts.Token), p.Type)
                {
                    AddPartialKeyword = p.AddPartialKeyword,
                    ShowDefinitions = p.ShowDefinitions,
                    UseUsingDeclarations = p.UseUsingDeclarations,
                };
                q.Definitions.UnionWith(p.Definitions);
                q.InterfacesToRemove.AddRange(p.InterfacesToRemove);
                D.Decompile(decompilationType, q);
                p.Output.Write(buffer.ToString(), BoxedTextColor.Text);
            }
            catch (Exception e) when (e is not OutOfMemoryException && !Interrupted)
            {
                p.Output.Write(Fail($"decompile {p.Type.FullName} (0x{p.Type.MDToken.Raw:X8})", e) + "\n", BoxedTextColor.Text);
            }
        }

        public DecompilerSettingsBase Settings => D.Settings;
        public MetadataTextColorProvider MetadataTextColorProvider => D.MetadataTextColorProvider;
        public string ContentTypeString => D.ContentTypeString;
        public string GenericNameUI => D.GenericNameUI;
        public string UniqueNameUI => D.UniqueNameUI;
        public double OrderUI => D.OrderUI;
        public Guid GenericGuid => D.GenericGuid;
        public Guid UniqueGuid => D.UniqueGuid;
        public string FileExtension => D.FileExtension;
        public string? ProjectFileExtension => D.ProjectFileExtension;
        public void WriteName(ITextColorWriter output, TypeDef type) => D.WriteName(output, type);
        public void WriteName(ITextColorWriter output, PropertyDef property, bool? isIndexer) => D.WriteName(output, property, isIndexer);
        public void WriteType(ITextColorWriter output, ITypeDefOrRef? type, bool includeNamespace, IHasCustomAttribute? customAttributeProvider = null) =>
            D.WriteType(output, type, includeNamespace, customAttributeProvider);
        public void Decompile(MethodDef method, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(method, output, ctx);
        public void Decompile(PropertyDef property, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(property, output, ctx);
        public void Decompile(FieldDef field, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(field, output, ctx);
        public void Decompile(EventDef ev, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(ev, output, ctx);
        public void DecompileNamespace(string @namespace, IEnumerable<TypeDef> types, IDecompilerOutput output, DecompilationContext ctx) =>
            D.DecompileNamespace(@namespace, types, output, ctx);
        public void Decompile(AssemblyDef asm, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(asm, output, ctx);
        public void Decompile(ModuleDef mod, IDecompilerOutput output, DecompilationContext ctx) => D.Decompile(mod, output, ctx);
        public void WriteToolTip(ITextColorWriter output, IMemberRef member, IHasCustomAttribute? typeAttributes) => D.WriteToolTip(output, member, typeAttributes);
        public void WriteToolTip(ITextColorWriter output, ISourceVariable variable) => D.WriteToolTip(output, variable);
        public void WriteNamespaceToolTip(ITextColorWriter output, string? @namespace) => D.WriteNamespaceToolTip(output, @namespace);
        public void Write(ITextColorWriter output, IMemberRef member, FormatterOptions flags) => D.Write(output, member, flags);
        public void WriteCommentBegin(IDecompilerOutput output, bool addSpace) => D.WriteCommentBegin(output, addSpace);
        public void WriteCommentEnd(IDecompilerOutput output, bool addSpace) => D.WriteCommentEnd(output, addSpace);
        public bool ShowMember(IMemberRef member) => D.ShowMember(member);
        public bool CanDecompile(DecompilationType decompilationType) => D.CanDecompile(decompilationType);
    }

    // Whole-module output is assembled type by type, so one unreadable type costs
    // only its own body: it is annotated in place and the rest still comes back.
    public static string Module(LoadedModule m, Lang lang)
    {
        XmlDocGuard.Check(m.Module);
        var dec = For(lang);
        var sb = new StringBuilder();
        int ok = 0, bad = 0;

        try { sb.Append(Run((o, c) => dec.Decompile(m.Module, o, c)).Text); }
        catch (Exception e) when (e is not OutOfMemoryException && !Interrupted) { sb.AppendLine(Fail("module header", e)); }

        foreach (var t in m.Module.GetTypes())
        {
            if (t.DeclaringType != null) continue; // nested types come with their parent
            Outer().ThrowIfCancellationRequested();
            sb.AppendLine();
            try
            {
                sb.AppendLine(TypeText(dec, t, lang).Text);
                ok++;
            }
            catch (Exception e) when (e is not OutOfMemoryException && !Interrupted)
            {
                sb.AppendLine(Fail($"decompile {t.FullName} (0x{t.MDToken.Raw:X8})", e));
                bad++;
            }
        }

        if (bad > 0)
            sb.AppendLine().Append(FailMarker).AppendLine($"{ok} type(s) decompiled, {bad} failed */");
        return sb.ToString();
    }
}

/// <summary>dnSpy's BAML decompiler (vendored without its WPF front end), as dnSpy's own IBamlDecompiler drives it.</summary>
static class Baml
{
    static XamlOutputOptions Output => new() { IndentChars = "\t", NewLineChars = "\n", NewLineOnAttributes = false };

    public static string ToXaml(ModuleDef module, byte[] baml, CancellationToken token)
    {
        var doc = dnSpy.BamlDecompiler.Baml.BamlReader.ReadDocument(new MemoryStream(baml), token);
        var xaml = dnSpy.BamlDecompiler.XamlDecompiler.Decompile(module, doc, token, BamlDecompilerOptions.CreateCSharp(), new List<string>());
        return new dnSpy.BamlDecompiler.XamlOutputCreator(Output).CreateText(xaml);
    }

    public static string TypeName(ModuleDef module, byte[] baml, CancellationToken token) =>
        dnSpy.BamlDecompiler.XamlDecompiler.DecompileTypeName(module, dnSpy.BamlDecompiler.Baml.BamlReader.ReadDocument(new MemoryStream(baml), token), token,
            BamlDecompilerOptions.CreateCSharp());

    public static IList<string> ToStream(ModuleDef module, byte[] baml, CancellationToken token, Stream output)
    {
        var doc = dnSpy.BamlDecompiler.Baml.BamlReader.ReadDocument(new MemoryStream(baml), token);
        var asmRefs = new List<string>();
        var xaml = dnSpy.BamlDecompiler.XamlDecompiler.Decompile(module, doc, token, BamlDecompilerOptions.CreateCSharp(), asmRefs);
        var bytes = System.Text.Encoding.UTF8.GetBytes(new dnSpy.BamlDecompiler.XamlOutputCreator(Output).CreateText(xaml));
        output.Write(bytes, 0, bytes.Length);
        return asmRefs;
    }
}

