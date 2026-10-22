// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;
using System.Text.RegularExpressions;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql.Tables;

/// <summary>
/// The questions of a malware triage that otherwise take a page of joins over il and xrefs: what a type's constructors
/// store in its fields (where configs live), what the code does (injection, persistence, download and execute, ...)
/// and at which call, and which URLs, addresses and tokens its literals hold. Every row points at the IL that holds
/// the evidence, so it can be decompiled or given to bp_set. Nothing here runs code.
/// </summary>
public static class TriageTables
{
    public sealed record FieldInit(LoadedModule M, IField Field, MethodDef SetIn, uint Offset, string Kind, object? Value, string Source = "literal");
    public sealed record Capability(LoadedModule M, string Kind, string Api, XRef Site, string Evidence);
    public sealed record Ioc(LoadedModule M, string Kind, string Value, MethodDef? Method, uint Offset, string Source, string? Resource = null, string? Fields = null);
    /// <summary>A settings field as a decoder leaves it (Field null: the decoder changed none, and Error says why).</summary>
    public sealed record Decoded(LoadedModule M, FieldDef? Field, TypeDef Settings, object? Initial, object? Value, MethodDef Decoder, uint Offset, string? Error);

    public static void Register(Session s)
    {
        RegisterTextTables(s);
        var ws = s.Ws;
        s.Db.Register(new Table<FieldInit>("field_inits",
                "Constants that constructors (.cctor and .ctor) store in fields: strings, numbers, byte arrays from field data, " +
                "string arrays. Malware settings classes (hosts, ports, keys, mutexes) are filled this way") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Inits(s, m)))
            .Int("module", f => f.M.Id, pushdown: Pushdown.Eq)
            .Int("field", f => f.Field is FieldDef fd ? f.M.H(fd) : null, doc: "the field (NULL for a field of another module)")
            .Text("field_name", f => f.Field.FullName)
            .Text("type_name", f => f.Field.DeclaringType?.FullName)
            .Int("set_in", f => f.M.H(f.SetIn), doc: "the constructor that stores it")
            .Int("offset", f => f.Offset, doc: "IL offset of the store")
            .Text("kind", f => f.Kind, doc: "string | int | real | bool | bytes | string[]")
            .Col("value", SqlType.Any, f => f.Value, doc: "the value; a JSON array for string[]")
            .Text("source", f => f.Source, doc: "literal | getter (a method returning a constant) | emulated (a decryptor called with literals, interpreted) | " +
                                                "cctor (what the static constructor leaves in the field, interpreted: Encoding.ASCII.GetBytes(\"...\"), say)")
            .Int("readers", f => f.Field is FieldDef fd ? s.Index.To(f.M.H(fd)).Count(x => x.Kind is "read" or "addr") : null,
                doc: "instructions that read the field")
            .Bool("is_default", f => f.Value is null or 0L or 0 or false or "" || f.Value is double d && d == 0,
                doc: "the store sets the field's default (0, false, empty string, null): what the compiler emits for an explicit initializer")
            .Estimate(200, 50));

        s.Db.Register(new Table<Capability>("capabilities",
                "What the code does, at the call or literal that shows it: process injection and hollowing, persistence, " +
                "download and execute, in-memory loading, keylogging, screen capture, webcam, audio capture, credential theft, defense tampering, " +
                "self-deletion, ... (APIs resolved by name through reflection or GetProcAddress included). bp_set(method, offset) " +
                "breaks there in dnSpy") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Capabilities(s, m)))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("kind", r => r.Kind)
            .Text("api", r => r.Api, doc: "the API, import or string that shows it")
            .Int("method", r => r.Site.FromHandle)
            .Text("method_name", r => r.Site.From.FullName)
            .Int("offset", r => r.Site.Offset, doc: "IL offset of the call or string")
            .Text("evidence", r => r.Evidence)
            .Bool("is_library", r => IsLibrary(r.Site.From), doc: "the method belongs to a well-known library namespace")
            .Estimate(100, 50));

        s.Db.Register(new Table<Ioc>("iocs",
                "Indicators in string literals, in base64 literals that decode to text, in what the decryptors return and in text " +
                "resources: URLs, Discord webhooks, Telegram bot tokens, IP addresses, domains, e-mail addresses, crypto wallets, " +
                "registry keys, mutex names") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Iocs(s, m)))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("kind", r => r.Kind, doc: "url | discord webhook | telegram bot | telegram token | ip | domain | host:port | email | btc wallet | eth wallet | " +
                                           "xmr wallet | registry | mutex")
            .Text("value", r => r.Value)
            .Int("method", r => r.Method == null ? null : r.M.H(r.Method))
            .Text("method_name", r => r.Method?.FullName)
            .Int("offset", r => r.Method == null ? null : r.Offset, doc: "IL offset of the ldstr, or of the decryptor call")
            .Text("source", r => r.Source, doc: "literal | base64 (the literal decoded) | decrypted (a decryptor's plaintext, interpreted) | " +
                "decoded (a settings field as its decoder leaves it, interpreted: decoded_fields) | computed (a value handed to an API) | " +
                "encrypted (a value handed to an API that is still ciphertext: its decoder could not be interpreted) | resource (text in a " +
                "resource, or a .resources string)")
            .Text("resource", r => r.Resource, doc: "the resource (resource/element for a .resources entry) the indicator is in")
            .Text("fields", r => r.Fields, doc: "the settings field(s) the value comes from (host:port names the host's field and the port's)")
            .Bool("is_library", r => r.Method != null && IsLibrary(r.Method), doc: "the method belongs to a well-known library namespace")
            .Estimate(100, 50));

        s.Db.Register(new Table<Decoded>("decoded_fields",
                "Settings as the program decodes them at startup: a type whose static constructor stores string literals (ciphertext, " +
                "usually) and a parameterless static method that reads those fields and writes them back through a call (Host = " +
                "Decrypt(Host), the key derived from another field). The decoder is interpreted after the static constructor, never " +
                "run; one row per field it changed") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => DecodedFields(s, m)))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("field", r => r.Field == null ? null : r.M.H(r.Field), doc: "NULL when the decoder changed no field: error says why")
            .Text("field_name", r => r.Field?.FullName)
            .Text("type_name", r => r.Settings.FullName)
            .Col("initial", SqlType.Any, r => r.Initial, doc: "what the static constructor stored")
            .Col("value", SqlType.Any, r => r.Value, doc: "what the decoder left")
            .Text("value_kind", r => ValueKind(r.Value), doc: "text | base64 text | ciphertext (still encrypted: another layer) | binary")
            .Int("decoded_by", r => r.M.H(r.Decoder), doc: "the decoder method")
            .Text("decoder_name", r => r.Decoder.FullName)
            .Int("offset", r => r.Field == null ? null : r.Offset, doc: "IL offset in the decoder where it stores the field")
            .Text("error", r => r.Error, doc: "why the decoder stopped, when it did (the fields it changed before that are still listed)")
            .Estimate(20, 50));
    }

    public sealed record TextIoc(string Kind, string Value, string Source);
    public sealed record Piece(long Index, string Value);

    static void RegisterTextTables(Session s)
    {
        s.Db.Register(new Table<TextIoc>("text_iocs",
                "The indicators iocs finds, in any text: WHERE text = <a decrypted config, a resource, a plaintext>. Base64 inside it is " +
                "decoded and searched too") { Domain = "triage" }
            .Source(c => c.Text("text") is { } text
                ? Find(text.Length > MaxLiteral ? text[..MaxLiteral] : text).Select(h => new TextIoc(h.Kind, h.Value, "text"))
                    .Concat(Base64Text(text) is { } decoded ? Find(decoded).Select(h => new TextIoc(h.Kind, h.Value, "base64")) : [])
                    .DistinctBy(h => (h.Kind, h.Value))
                : [])
            .Text("kind", r => r.Kind)
            .Text("value", r => r.Value)
            .Text("source", r => r.Source, doc: "text | base64 (decoded from the text)")
            .Arg("text", SqlType.Text, _ => null)
            .Estimate(10, 1));

        s.Db.Register(new Table<Piece>("split_text",
                "A text cut at a separator, one row per piece: WHERE text = ... AND separator = '|' (default ','). Configs are often " +
                "one delimited string") { Domain = "triage" }
            .Source(c => c.Text("text") is { } text
                ? text.Split(c.Text("separator") is { Length: > 0 } sep ? sep : ",").Select((p, i) => new Piece(i, p))
                : [])
            .Int("idx", r => r.Index)
            .Text("value", r => r.Value)
            .Arg("text", SqlType.Text, _ => null)
            .Arg("separator", SqlType.Text, _ => null, required: false)
            .Estimate(10, 1));
    }

    static readonly string[] LibraryNamespaces = ["System.", "Microsoft.", "Newtonsoft.", "Org.BouncyCastle", "Google.Protobuf", "MessagePack",
        "Costura", "ICSharpCode.", "Mono.", "NAudio", "AForge", "Ionic.", "SharpCompress", "Renci.", "ProtoBuf", "Dapper", "SQLite", "AsyncIO", "NetMQ"];

    internal static bool IsLibrary(MethodDef m)
    {
        var t = m.DeclaringType;
        while (t?.DeclaringType != null) t = t.DeclaringType;
        var ns = t?.Namespace.String ?? "";
        return LibraryNamespaces.Any(p => ns.StartsWith(p, StringComparison.Ordinal) || ns == p.TrimEnd('.'));
    }

    static bool TryBody(MethodDef m, out IList<Instruction> ins)
    {
        ins = Array.Empty<Instruction>();
        try
        {
            if (!m.HasBody || m.Body == null) return false;
            ins = m.Body.Instructions;
            return true;
        }
        catch (Exception) { return false; }
    }

    static int Prev(IList<Instruction> ins, int i)
    {
        for (i--; i >= 0 && ins[i].OpCode.Code == Code.Nop; i--) { }
        return i;
    }

    // ---- field_inits -------------------------------------------------------------------------------------------------

    internal static IEnumerable<FieldInit> Inits(Session s, LoadedModule m)
    {
        var fold = new ProtectionTables.Fold(s);
        foreach (var t in m.Module.GetTypes())
            foreach (var ctor in t.Methods.Where(x => x.IsConstructor))
            {
                if (!TryBody(ctor, out var ins)) continue;
                for (int i = 0; i < ins.Count; i++)
                    if (ins[i].OpCode.Code is Code.Stsfld or Code.Stfld && ins[i].Operand is IField f)
                    {
                        if (Stored(ins, i, f) is { Kind: { } kind } v) yield return new FieldInit(m, f, ctor, ins[i].Offset, kind, v.Value);
                        else if (Computed(s, fold, ins, i) is { } c) yield return new FieldInit(m, f, ctor, ins[i].Offset, c.Kind, c.Value, c.Source);
                        else if (ctor.IsStaticConstructor && ins[i].OpCode.Code == Code.Stsfld && FieldDefOf(f) is { } fd && fd.DeclaringType == t
                                 && ConfigLike(fd) && FrameworkCall(s, ins, i) && Emulator.StaticValue(s, fd) is { Value: { } value })
                            yield return new FieldInit(m, f, ctor, ins[i].Offset, KindOf(value), value, "cctor");
                    }
            }
    }

    static FieldDef? FieldDefOf(IField f)
    {
        try { return f.ResolveFieldDef(); } catch (Exception) { return null; } // a reference that does not resolve names no field here
    }

    // The kinds of field settings are kept in (strings, numbers, byte and string arrays): what a framework call computes
    // into one in a static constructor (Encoding.ASCII.GetBytes("salt")) is a setting too.
    static bool ConfigLike(FieldDef f) => f.FieldSig?.Type?.RemovePinnedAndModifiers() switch
    {
        SZArraySig a => a.Next?.ElementType is ElementType.U1 or ElementType.String,
        { ElementType: ElementType.String or ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.Boolean } => true,
        _ => false,
    };

    // The stored value is a framework call's result (not a method of an open module): what Stored and Computed leave out.
    static bool FrameworkCall(Session s, IList<Instruction> ins, int store)
    {
        int k = Prev(ins, store);
        if (k < 0 || ins[k].OpCode.Code is not (Code.Call or Code.Callvirt) || ins[k].Operand is not IMethod target) return false;
        try { return target.ResolveMethodDef() is not { } d || s.Ws.Find(d.Module) == null; }
        catch (Exception) { return true; }
    }

    // ---- decoded settings ----------------------------------------------------------------------------------------------

    // Per module, until the next edit: what its decoders leave, and every static field's value once the program started.
    sealed class Cache { public long Revision = -1; public List<Decoded>? Decoded; public Dictionary<FieldDef, (object? Value, string Source)>? Values; }
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, Cache> _caches = new();
    // set while those are worked out: their own interpretation folds field arguments (ProtectionTables.FieldConst), which
    // must not ask for them again
    [ThreadStatic] static int _busy;

    static Cache CacheOf(Session s, LoadedModule m)
    {
        var c = _caches.GetValue(m, _ => new Cache());
        lock (c) if (c.Revision != s.Ws.Revision) (c.Revision, c.Decoded, c.Values) = (s.Ws.Revision, null, null);
        return c;
    }

    const int MaxDecoders = 20;

    internal static List<Decoded> DecodedFields(Session s, LoadedModule m)
    {
        var c = CacheOf(s, m);
        lock (c)
        {
            if (c.Decoded != null) return c.Decoded;
            _busy++;
            try { return c.Decoded = FindDecoded(s, m).ToList(); }
            finally { _busy--; }
        }
    }

    // A settings type: its static constructor stores string literals into three or more of its static fields. Its decoders:
    // parameterless static methods (not the static constructor) that read two or more of its static fields and store two
    // or more back with a value a call returned. Nothing here is about one family; the shape is what settings code has.
    static IEnumerable<Decoded> FindDecoded(Session s, LoadedModule m)
    {
        int decoders = 0;
        foreach (var t in m.Module.GetTypes())
        {
            if (t.FindStaticConstructor() is not { } cctor || !TryBody(cctor, out var ins)) continue;
            var literal = new HashSet<FieldDef>();
            for (int i = 0; i < ins.Count; i++)
                if (ins[i].OpCode.Code == Code.Stsfld && ins[i].Operand is IField f && Prev(ins, i) is var k and >= 0 && ins[k].OpCode.Code == Code.Ldstr
                    && FieldDefOf(f) is { } fd && fd.DeclaringType == t)
                    literal.Add(fd);
            if (literal.Count < 3) continue;
            var reads = new Dictionary<MethodDef, HashSet<FieldDef>>();
            var writes = new Dictionary<MethodDef, Dictionary<FieldDef, uint>>();
            foreach (var f in t.Fields.Where(f => f.IsStatic))
                foreach (var x in s.Index.To(m.H(f)))
                {
                    if (x.From is not { IsStatic: true, IsStaticConstructor: false } from || from.MethodSig?.Params.Count != 0 || IsLibrary(from)) continue;
                    if (x.Kind == "read") (reads.TryGetValue(from, out var r) ? r : reads[from] = new()).Add(f);
                    else if (x.Kind == "write" && TryBody(from, out var body) && x.Index < body.Count && Prev(body, x.Index) is var p and >= 0
                             && body[p].OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
                        (writes.TryGetValue(from, out var w) ? w : writes[from] = new()).TryAdd(f, x.Offset);
                }
            foreach (var (decoder, stored) in writes.Where(w => w.Value.Count >= 2 && reads.GetValueOrDefault(w.Key)?.Count >= 2).OrderBy(w => w.Key.MDToken.Raw))
            {
                if (++decoders > MaxDecoders) yield break;
                var run = Emulator.Decode(s, decoder, t);
                foreach (var (f, before, after) in run.Changed)
                    yield return new Decoded(m, f, t, before, after, decoder, stored.GetValueOrDefault(f), run.Error);
                if (run.Changed.Count == 0)
                    yield return new Decoded(m, null, t, null, null, decoder, 0, run.Error ?? "the decoder left every field as the static constructor stored it");
            }
        }
    }

    /// <summary>Each field's value once the program has started: a decoder's over a computed one (a decryptor's result) over the stored literal.</summary>
    internal static Dictionary<FieldDef, (object? Value, string Source)> FieldValues(Session s, LoadedModule m)
    {
        var c = CacheOf(s, m);
        lock (c)
        {
            if (c.Values != null) return c.Values;
            _busy++;
            try
            {
                var values = new Dictionary<FieldDef, (object? Value, string Source)>();
                foreach (var init in Inits(s, m))
                    if (FieldDefOf(init.Field) is { } fd && (init.Source != "literal" || !values.ContainsKey(fd)))
                        values[fd] = (init.Value, init.Source);
                foreach (var d in DecodedFields(s, m))
                    if (d.Field != null && d.Value != null) values[d.Field] = (d.Value, "decoded");
                return c.Values = values;
            }
            finally { _busy--; }
        }
    }

    /// <summary>A static field's known value (FieldValues), for folding Decode(Settings.Host) to a call with that value; null while it is being worked out.</summary>
    internal static (object? Value, string Source)? KnownValue(Session s, FieldDef fd) =>
        _busy > 0 || s.Ws.Find(fd.Module) is not { } lm ? null : FieldValues(s, lm).TryGetValue(fd, out var v) && v.Value != null ? v : null;

    /// <summary>
    /// What a value looks like: text | base64 text (base64 of readable text) | ciphertext (base64 of 16 or more bytes, a
    /// multiple of 8, that are not text: another layer to decrypt) | binary.
    /// </summary>
    internal static string? ValueKind(object? v)
    {
        switch (v)
        {
            case null: return null;
            case byte[]: return "binary";
            case not string: return "text";
        }
        var s = (string)v;
        if (s.Length >= 8 && s.Length % 4 == 0 && s.TrimEnd('=') is var core && s.Length - core.Length <= 2
            && core.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '+' or '/'))
        {
            byte[] b;
            try { b = Convert.FromBase64String(s); } catch (FormatException) { return "text"; }
            if (Printable(b) >= 0.95) return "base64 text";
            if (b.Length >= 16 && b.Length % 8 == 0 && Printable(b) < 0.75) return "ciphertext";
            return "text";
        }
        return s.Count(ch => ch >= 0x20 && ch != 0x7F || ch is '\t' or '\r' or '\n') >= s.Length * 0.75 ? "text" : "binary";
    }

    // The share of bytes that are printable ASCII (or, for UTF-16 text, of its characters)
    static double Printable(byte[] b)
    {
        if (b.Length == 0) return 1;
        static bool P(byte x) => x is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\r' or (byte)'\n';
        if (b.Length >= 4 && b.Length % 2 == 0 && Enumerable.Range(0, b.Length / 2).All(i => b[2 * i + 1] == 0))
            return (double)Enumerable.Range(0, b.Length / 2).Count(i => P(b[2 * i])) / (b.Length / 2);
        return (double)b.Count(P) / b.Length;
    }

    // The constant on the stack when the field is stored, or (null, null).
    static (string? Kind, object? Value) Stored(IList<Instruction> ins, int store, IField f)
    {
        int k = Prev(ins, store);
        if (k < 0) return default;
        var p = ins[k];
        if (p.OpCode.Code == Code.Ldstr) return ("string", p.Operand as string ?? "");
        if (p.IsLdcI4())
            return f.FieldSig?.Type?.ElementType == ElementType.Boolean ? ("bool", p.GetLdcI4Value() != 0 ? 1L : 0L) : ("int", (long)p.GetLdcI4Value());
        if (p.OpCode.Code == Code.Ldc_I8 && p.Operand is long l) return ("int", l);
        if (p.OpCode.Code is Code.Ldc_R4 or Code.Ldc_R8) return ("real", Convert.ToDouble(p.Operand, System.Globalization.CultureInfo.InvariantCulture));
        // new T[] { ... } from field data: ldc n; newarr T; dup; ldtoken <data>; call RuntimeHelpers.InitializeArray
        if (p.OpCode.Code == Code.Call && p.Operand is IMethod im && (im.Name == "InitializeArray" || ForwardsTo(im, "InitializeArray"))
            && Prev(ins, k) is var t and >= 0 && ins[t].OpCode.Code == Code.Ldtoken && ins[t].Operand is FieldDef { InitialValue: { } data })
        {
            int newarr = Prev(ins, Prev(ins, t)), count = data.Length;
            if (newarr >= 0 && ins[newarr].OpCode.Code == Code.Newarr && Prev(ins, newarr) is var c and >= 0 && ins[c].IsLdcI4())
                count = ins[c].GetLdcI4Value() * ElementSize(ins[newarr].Operand as ITypeDefOrRef);
            return ("bytes", data[..Math.Clamp(count, 0, data.Length)]);
        }
        // new string[] { "a", "b" }: ldc n; newarr string; (dup; ldc i; ldstr s; stelem.ref)*
        if (p.OpCode.Code == Code.Stelem_Ref)
        {
            var items = new List<string?>();
            int j = k;
            while (j >= 3 && ins[j].OpCode.Code == Code.Stelem_Ref)
            {
                int str = Prev(ins, j), idx = Prev(ins, str), dup = Prev(ins, idx);
                if (str < 0 || idx < 0 || dup < 0 || ins[dup].OpCode.Code != Code.Dup || !ins[idx].IsLdcI4()
                    || ins[str].OpCode.Code is not (Code.Ldstr or Code.Ldnull)) return default;
                items.Add(ins[str].Operand as string);
                j = Prev(ins, dup);
            }
            if (j >= 0 && ins[j].OpCode.Code == Code.Newarr && (ins[j].Operand as ITypeDefOrRef)?.FullName == "System.String")
            {
                items.Reverse();
                return ("string[]", System.Text.Json.JsonSerializer.Serialize(items));
            }
        }
        return default;
    }

    // A value a call computes from literals: a getter's constant, or a decryptor's result, interpreted (Emulator).
    static (string Kind, object? Value, string Source)? Computed(Session s, ProtectionTables.Fold fold, IList<Instruction> ins, int store)
    {
        int k = Prev(ins, store);
        if (k < 0 || ins[k].OpCode.Code != Code.Call || ins[k].Operand is not IMethod target) return null;
        MethodDef? def;
        try { def = target.ResolveMethodDef(); } catch (Exception) { return null; }
        if (def is not { IsStatic: true } || s.Ws.Find(def.Module) == null || def.MethodSig?.RetType.ElementType == ElementType.Void) return null;
        int n = def.MethodSig?.Params.Count ?? 0;
        if (n == 0 && ProtectionTables.Getter(target, fold.Getters) is { } g) return (KindOf(g.Value), g.Value, "getter");
        if (n == 0 || ProtectionTables.ArgumentsAt(ins, k, n, fold) is not { } args) return null;
        var generic = (target as MethodSpec)?.GenericInstMethodSig?.GenericArguments;
        var (value, error) = Emulator.For(s).Cached(def, args.Select(a => a.Value).ToList(), generic);
        return error == null && value != null ? (KindOf(value), value, "emulated") : null;
    }

    static string KindOf(object? v) => v switch { string => "string", long => "int", double => "real", byte[] => "bytes", _ => "string" };

    // A sample method that only passes its arguments on to the named method (a proxy call).
    static bool ForwardsTo(IMethod m, string name)
    {
        try
        {
            if (m.ResolveMethodDef() is not { IsStatic: true } d || !TryBody(d, out var ins)) return false;
            var real = ins.Where(x => x.OpCode.Code != Code.Nop).ToList();
            return real.Count is >= 2 and <= 8 && real[^1].OpCode.Code == Code.Ret && real[^2].OpCode.Code == Code.Call
                   && real[^2].Operand is IMethod t && t.Name == name && real.Take(real.Count - 2).All(x => x.IsLdarg());
        }
        catch (Exception) { return false; }
    }

    static int ElementSize(ITypeDefOrRef? t) => t?.FullName switch
    {
        "System.Byte" or "System.SByte" or "System.Boolean" => 1,
        "System.Int16" or "System.UInt16" or "System.Char" => 2,
        "System.Int32" or "System.UInt32" or "System.Single" => 4,
        "System.Int64" or "System.UInt64" or "System.Double" => 8,
        _ => 1,
    };

    // ---- capabilities ------------------------------------------------------------------------------------------------

    // Calls, by the start of the callee's full name (Namespace.Type::Method(...)).
    static readonly (string Kind, string Prefix)[] CallRules =
    [
        ("in-memory loading", "System.Reflection.Assembly::Load(System.Byte[]"),
        ("in-memory loading", "System.AppDomain::Load(System.Byte[]"),
        ("in-memory loading", "System.Reflection.Assembly::get_EntryPoint("),
        ("assembly loading", "System.Reflection.Assembly::LoadFile("),
        ("assembly loading", "System.Reflection.Assembly::LoadFrom("),
        ("download", "System.Net.WebClient::DownloadData"),
        ("download", "System.Net.WebClient::DownloadFile"),
        ("download", "System.Net.WebClient::DownloadString"),
        ("download", "System.Net.Http.HttpClient::GetByteArrayAsync("),
        ("download", "System.Net.Http.HttpClient::GetStringAsync("),
        ("download", "System.Net.Http.HttpClient::GetStreamAsync("),
        ("http", "System.Net.WebRequest::Create("),
        ("http", "System.Net.Http.HttpClient::PostAsync("),
        ("http", "System.Net.Http.HttpClient::SendAsync("),
        ("upload", "System.Net.WebClient::Upload"),
        ("execute", "System.Diagnostics.Process::Start("),
        ("tcp connection", "System.Net.Sockets.TcpClient::Connect("),
        ("tcp connection", "System.Net.Sockets.TcpClient::ConnectAsync("),
        ("tcp connection", "System.Net.Sockets.Socket::Connect("),
        ("tcp connection", "System.Net.Sockets.Socket::ConnectAsync("),
        ("tls", "System.Net.Security.SslStream::AuthenticateAsClient"),
        ("registry write", "Microsoft.Win32.RegistryKey::SetValue("),
        ("registry write", "Microsoft.Win32.Registry::SetValue("),
        ("screen capture", "System.Drawing.Graphics::CopyFromScreen("),
        ("clipboard", "System.Windows.Forms.Clipboard::GetText("),
        ("clipboard", "System.Windows.Forms.Clipboard::SetText("),
        ("wmi", "System.Management.ManagementObjectSearcher::.ctor("),
        ("crypto", "System.Security.Cryptography.CryptoStream::.ctor("),
        ("dynamic api resolution", "System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer"),
        ("dynamic code", "System.CodeDom.Compiler.CodeDomProvider::CompileAssemblyFrom"),
        ("dynamic code", "Microsoft.VisualBasic.VBCodeProvider::"),
        ("call by name", "Microsoft.VisualBasic.Interaction::CallByName("),
        ("call by name", "Microsoft.VisualBasic.CompilerServices.NewLateBinding::LateCall("),
        ("call by name", "Microsoft.VisualBasic.CompilerServices.NewLateBinding::LateGet("),
        ("call by name", "System.Type::InvokeMember("),
        ("process enumeration", "System.Diagnostics.Process::GetProcesses("),
        ("process termination", "System.Diagnostics.Process::Kill("),
        ("environment", "System.Environment::get_MachineName("),
        ("environment", "System.Environment::get_UserName("),
        ("dynamic code", "System.Reflection.Emit."),
        ("dynamic code", "Microsoft.CSharp.CSharpCodeProvider::"),
        ("single instance", "System.Threading.Mutex::.ctor("),
        ("single instance", "System.Threading.Mutex::OpenExisting("),
        ("single instance", "System.Threading.Mutex::TryOpenExisting("),
        ("drive enumeration", "System.IO.DriveInfo::GetDrives("),
        // the common capture libraries' entry points (DirectShow and wave-in wrappers)
        ("webcam", "AForge.Video.DirectShow.VideoCaptureDevice::.ctor("),
        ("webcam", "AForge.Video.DirectShow.FilterInfoCollection::.ctor("),
        ("audio capture", "NAudio.Wave.WaveInEvent::StartRecording("),
        ("audio capture", "NAudio.Wave.WaveIn::StartRecording("),
    ];

    // P/Invokes, by the entry point's name (also when resolved through GetProcAddress or reflection).
    static readonly (string Kind, string[] Names)[] ImportRules =
    [
        ("process injection", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
                               "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread", "NtCreateThreadEx"]),
        ("process hollowing", ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "Wow64SetThreadContext", "GetThreadContext",
                               "Wow64GetThreadContext", "ResumeThread", "CreateProcessA", "CreateProcessW", "CreateProcess"]),
        ("keylogging", ["SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState"]),
        ("screen capture", ["BitBlt", "PrintWindow"]),
        ("privileges", ["AdjustTokenPrivileges", "RtlAdjustPrivilege"]),
        ("critical process", ["RtlSetProcessIsCritical", "NtSetInformationProcess"]),
        ("shellcode execution", ["CreateThread"]),
        ("window hiding", ["ShowWindow", "GetConsoleWindow"]),
        ("dynamic api resolution", ["GetProcAddress", "LoadLibrary", "LoadLibraryA", "LoadLibraryW"]),
        ("webcam", ["capCreateCaptureWindowA", "capCreateCaptureWindowW", "capCreateCaptureWindow", "capGetDriverDescriptionA",
                    "capGetDriverDescriptionW"]),
        ("audio capture", ["waveInOpen", "waveInStart", "waveInAddBuffer", "mciSendString", "mciSendStringA", "mciSendStringW"]),
    ];

    // Strings, by a fragment (compared case-insensitively).
    static readonly (string Kind, string[] Fragments)[] StringRules =
    [
        ("persistence", [@"currentversion\run", @"currentversion\winlogon", "schtasks", @"\start menu\programs\startup", "userinit"]),
        ("self-deletion", ["choice /c y /n /d y /t", "/c del ", "& del ", "&& del "]),
        ("credential theft", ["login data", "logins.json", @"\local state", "cookies.sqlite", "wallet.dat", @"\telegram desktop", @"local storage\leveldb",
                              "filezilla", @"\exodus\", "electrum", "metamask", @"\.purple\accounts.xml", "web data"]),
        ("defense tampering", ["set-mppreference", "add-mppreference", "exclusionpath", "disableantispyware", "disablerealtimemonitoring", "netsh advfirewall",
                               "amsiscanbuffer", "amsiinitialize", "amsi.dll", "etweventwrite", "ntracecontrol"]),
        ("uac bypass", ["fodhelper", "computerdefaults", @"ms-settings\shell\open\command", "eventvwr", "sdclt"]),
        ("recovery inhibition", ["vssadmin delete shadows", "shadowcopy delete", "recoveryenabled no", "wbadmin delete catalog"]),
        ("hosts file tampering", [@"drivers\etc\hosts"]),
        ("removable drive spreading", ["autorun.inf", "[autorun]"]),
    ];

    // A call made through a proxy (a static method that only passes its arguments on, which obfuscators put in front
    // of every API) is reported where the proxy is called, the code that means it; up to three proxies deep.
    internal static IEnumerable<Capability> Capabilities(Session s, LoadedModule m) => CapabilitiesAt(s, m).SelectMany(c => ThroughProxies(s, c, 0));

    static IEnumerable<Capability> ThroughProxies(Session s, Capability c, int depth)
    {
        var from = c.Site.From;
        var callers = depth < 3 && ProtectionTables.IsThunk(from) ? s.Index.To(c.M.H(from)).Where(x => x.IsCall).ToList() : [];
        if (callers.Count == 0) { yield return c; yield break; }
        foreach (var site in callers)
            foreach (var r in ThroughProxies(s, c with { Site = site, Evidence = $"{c.Evidence} (through proxy {from.Name})" }, depth + 1))
                yield return r;
    }

    static IEnumerable<Capability> CapabilitiesAt(Session s, LoadedModule m)
    {
        var ix = s.Index;
        var imports = ImportRules.SelectMany(r => r.Names.Select(n => (n, r.Kind))).ToDictionary(x => x.n, x => x.Kind, StringComparer.OrdinalIgnoreCase);
        foreach (var x in ix.All.Where(x => x.M == m))
        {
            if (x.Kind == "string" && x.StringValue is { Length: >= 4 } str)
            {
                var lower = str.ToLowerInvariant();
                foreach (var (kind, fragments) in StringRules)
                    if (fragments.FirstOrDefault(f => lower.Contains(f, StringComparison.Ordinal)) is { } hit)
                    {
                        yield return new Capability(m, kind, hit, x, "string \"" + Clip(str) + "\"");
                        break;
                    }
                continue;
            }
            if (!x.IsCall) continue;
            var callee = x.ToName;
            int sep = callee.IndexOf(' ');
            var name = sep >= 0 ? callee[(sep + 1)..] : callee; // without the return type
            var pinvoke = (x.Def as MethodDef)?.ImplMap;
            if (pinvoke != null && imports.TryGetValue(pinvoke.Name.String, out var ik))
                yield return new Capability(m, ik, pinvoke.Name.String, x, $"P/Invoke {pinvoke.Module?.Name}!{pinvoke.Name}");
            else if (CallRules.FirstOrDefault(r => name.StartsWith(r.Prefix, StringComparison.Ordinal)) is { Kind: { } ck } rule)
                yield return new Capability(m, ck, rule.Prefix.TrimEnd('('), x, "calls " + Clip(name, 120));
            // an API looked up by name: GetProcAddress(h, "VirtualAllocEx") (P/Invoked, so by its entry point, or a
            // managed wrapper), type.GetMethod("Load")
            if ((pinvoke?.Name.String == "GetProcAddress" || name.Contains("::GetProcAddress(", StringComparison.Ordinal)
                 || name.StartsWith("System.Type::GetMethod(", StringComparison.Ordinal))
                && NameArgument(x) is { } api && imports.TryGetValue(api, out var rk))
                yield return new Capability(m, rk, api, x, $"resolves {api} by name");
            // an API name handed to a resolver wrapper: LoadApi<T>("kernel32", "WriteProcessMemory")
            else if (pinvoke == null && StringArguments(x).FirstOrDefault(imports.ContainsKey) is { } wrapped)
                yield return new Capability(m, imports[wrapped], wrapped, x, $"passes \"{wrapped}\" to {Clip(name, 100)}");
        }
    }

    // The string pushed just before a call that takes the API name last (GetProcAddress, GetMethod).
    static string? NameArgument(XRef x)
    {
        if (!TryBody(x.From, out var ins) || x.Index >= ins.Count) return null;
        int k = Prev(ins, x.Index);
        return k >= 0 && ins[k].OpCode.Code == Code.Ldstr ? ins[k].Operand as string : null;
    }

    // The string literals pushed right before a call (up to four arguments back).
    static IEnumerable<string> StringArguments(XRef x)
    {
        if (!TryBody(x.From, out var ins) || x.Index >= ins.Count) yield break;
        for (int k = Prev(ins, x.Index), n = 0; k >= 0 && n < 4; k = Prev(ins, k), n++)
        {
            if (ins[k].OpCode.Code == Code.Ldstr && ins[k].Operand is string str) yield return str;
            else if (!ins[k].IsLdcI4() && ins[k].OpCode.Code != Code.Ldnull) yield break;
        }
    }

    static string Clip(string s, int max = 80) => s.Length <= max ? s : s[..max] + "…";

    // ---- iocs --------------------------------------------------------------------------------------------------------

    // Literals are sample data: patterns are bounded, every match has a timeout, and only the first 64 KB of a literal
    // is searched (a multi-MB base64 literal made the e-mail pattern quadratic, past the statement timeout's reach).
    const RegexOptions Rx = RegexOptions.Compiled | RegexOptions.CultureInvariant;
    static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(250);
    const int MaxLiteral = 64 * 1024;
    static readonly Regex Url = new(@"\b(?:https?|ftp|wss?|tcp)://[^\s""'<>\\^`{|}]+", Rx | RegexOptions.IgnoreCase, MatchTimeout);
    static readonly Regex Ip = new(@"(?<![\w.=])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])", Rx, MatchTimeout);
    static readonly Regex Email = new(@"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b", Rx, MatchTimeout);
    static readonly Regex TelegramToken = new(@"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", Rx, MatchTimeout);
    static readonly Regex Domain = new(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?::\d{1,5})?$", Rx, MatchTimeout);
    static readonly Regex Btc = new(@"^(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", Rx, MatchTimeout);
    static readonly Regex Eth = new(@"^0x[a-fA-F0-9]{40}$", Rx, MatchTimeout);
    static readonly Regex Xmr = new(@"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", Rx, MatchTimeout);
    static readonly Regex Registry = new(@"^(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\\]|^(?:SOFTWARE|Software|SYSTEM|System)\\(?:Microsoft|Classes|Policies|CurrentControlSet|WOW6432Node)\\", Rx, MatchTimeout);

    // TLDs malware infrastructure uses, plus dynamic-DNS and tunnel suffixes; anything else as a bare name is too likely
    // to be a file name or a namespace ("config.json", "System.Net"). The reserved names of RFC 2606 (example, test) are
    // what documentation and test builds use.
    static readonly HashSet<string> Tlds = new(StringComparer.Ordinal)
    {
        "com", "net", "org", "ru", "io", "xyz", "top", "info", "biz", "cc", "tk", "me", "co", "us", "uk", "de", "cn", "su", "pw", "ws", "online",
        "site", "club", "live", "host", "fun", "store", "shop", "app", "dev", "gg", "ml", "ga", "cf", "gq", "in", "br", "fr", "nl", "it", "pl",
        "ir", "tr", "ua", "kz", "by", "eu", "to", "sh", "ly", "cloud", "space", "website", "tech", "icu", "buzz", "monster", "rest", "lol",
        "example", "test",
    };

    const int MaxResourceText = 256 * 1024;

    // A dotted number handed straight to a version or object-identifier constructor ("6.9.0.114" to Version, "1.9.4.1"
    // to an OID): a version, not an address.
    static bool VersionArgument(XRef x)
    {
        if (!TryBody(x.From, out var ins) || x.Index + 1 >= ins.Count) return false;
        int k = x.Index + 1;
        while (k < ins.Count && ins[k].OpCode.Code == Code.Nop) k++;
        if (k >= ins.Count || ins[k].OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj) || ins[k].Operand is not IMethod target) return false;
        var type = target.DeclaringType?.Name.String ?? "";
        return type == "Version" || type.Contains("ObjectIdentifier", StringComparison.Ordinal) || type == "Oid"
               || target.Name.String is "Branch" or "FromOid";
    }

    internal static IEnumerable<Ioc> Iocs(Session s, LoadedModule m)
    {
        // a literal used at many sites is searched once
        var found = new Dictionary<string, List<(string Kind, string Value, string Source)>>(StringComparer.Ordinal);
        foreach (var x in s.Index.All.Where(x => x.M == m && x.Kind == "string" && x.StringValue is { Length: >= 6 }))
        {
            if (!found.TryGetValue(x.StringValue!, out var hits))
            {
                var text = x.StringValue!.Length > MaxLiteral ? x.StringValue[..MaxLiteral] : x.StringValue;
                hits = Find(text).Select(h => (h.Kind, h.Value, "literal"))
                    .Concat(Base64Text(text) is { } decoded ? Find(decoded).Select(h => (h.Kind, h.Value, "base64")) : [])
                    .DistinctBy(h => (h.Kind, h.Value)).ToList();
                found[x.StringValue!] = hits;
            }
            bool versionLike = hits.Any(h => h.Kind == "ip") && VersionArgument(x);
            foreach (var (kind, value, source) in hits)
                if (!(versionLike && kind == "ip")) yield return new Ioc(m, kind, value, x.From, x.Offset, source);
        }
        // names handed to an API that takes one: a mutex's name, as a literal, a field's value once the program started
        // (decoded at startup, computed by a decryptor, or stored) or a decrypted string
        var fold = new ProtectionTables.Fold(s);
        foreach (var x in s.Index.All.Where(x => x.M == m && x.IsCall && x.ToName.Contains(" System.Threading.Mutex::", StringComparison.Ordinal)))
        {
            if (x.Operand is not IMethod api || api.MethodSig?.Params is not { } ps) continue;
            int k = -1;
            for (int i = 0; i < ps.Count && k < 0; i++) if (ps[i].ElementType == ElementType.String) k = i;
            if (k < 0 || !TryBody(x.From, out var ins) || x.Index >= ins.Count || ArgumentProducer(ins, x.Index, ps.Count - 1 - k) is not int at) continue;
            (object? Value, string Source) name = ins[at].OpCode.Code switch
            {
                Code.Ldstr => (ins[at].Operand as string, "literal"),
                Code.Ldsfld when ins[at].Operand is IField f && FieldDefOf(f) is { } fd && FieldValues(s, m).TryGetValue(fd, out var fv)
                    => (fv.Value, fv.Source == "decoded" ? "decoded" : "computed"),
                Code.Call => (Computed(s, fold, ins, at + 1)?.Value, "computed"),
                _ => default,
            };
            // a name that is still base64 ciphertext is what the program decrypts before using it: not the mutex's name
            if (name.Value is string { Length: > 0 } n)
                yield return new Ioc(m, "mutex", n, x.From, x.Offset, name.Source != "literal" && ValueKind(n) == "ciphertext" ? "encrypted" : name.Source,
                    Fields: ins[at].Operand is IField nf ? nf.FullName : null);
        }
        // settings as their decoders leave them (decoded_fields), and a host field with a port field beside it
        foreach (var d in DecodedFields(s, m))
            if (d.Field != null && d.Value is string decoded)
                foreach (var (kind, value) in Find(decoded.Length > MaxLiteral ? decoded[..MaxLiteral] : decoded))
                    yield return new Ioc(m, kind, value, d.Decoder, d.Offset, "decoded", Fields: d.Field.FullName);
        foreach (var pair in HostPorts(s, m)) yield return pair;
        // text the program carries in its resources: a config file, a script, a .resources string
        foreach (var res in m.Module.Resources.OfType<EmbeddedResource>())
        {
            byte[] data;
            try { data = res.CreateReader().ToArray(); } catch (Exception) { continue; }
            if (ResourceTables.ReadSet(m, res) is { } set)
            {
                foreach (var e in set.ResourceElements)
                    if (ResourceTables.ElementValue(e) is string { Length: >= 6 } entry)
                        foreach (var (kind, value) in Find(entry.Length > MaxLiteral ? entry[..MaxLiteral] : entry))
                            yield return new Ioc(m, kind, value, null, 0, "resource", $"{res.Name}/{e.Name}");
            }
            else if (data.Length >= 6 && ResourceTables.Content(data.Length > MaxResourceText ? data[..MaxResourceText] : data) is "text" or "xml" or "json")
            {
                var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, MaxResourceText));
                foreach (var (kind, value) in Find(text).Concat(text.Split('\n').SelectMany(line => Find(line.Trim()))).Distinct())
                    yield return new Ioc(m, kind, value, null, 0, "resource", res.Name);
            }
        }
        // what the decryptors return, interpreted: configs are usually encrypted
        var seen = new HashSet<(string, string, uint)>();
        foreach (var call in ProtectionTables.Calls(s, m, null, 5))
            if (call.Plain.Value is (string plain, "ok"))
                foreach (var (kind, value) in Find(plain.Length > MaxLiteral ? plain[..MaxLiteral] : plain))
                    if (seen.Add((kind, value, call.Site.Offset))) yield return new Ioc(m, kind, value, call.Site.From, call.Site.Offset, "decrypted");
    }

    // The instruction that pushes a call's argument, counted from the last (0): walking back, each instruction's pushes
    // and pops say where the arguments' expressions start; a branch in between and the answer is not known.
    static int? ArgumentProducer(IList<Instruction> ins, int call, int fromLast)
    {
        int pos = 0;
        for (int i = call - 1; i >= 0 && call - i <= 64; i--)
        {
            var x = ins[i];
            if (x.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call)) return null;
            x.CalculateStackUsage(false, out int push, out int pop);
            if (pos == fromLast && push > 0) return i;
            pos += push - pop;
        }
        return null;
    }

    const int MaxPairs = 20;
    static readonly Regex PortList = new(@"^\s*\d{1,5}(?:\s*[,;|]\s*\d{1,5})*\s*$", Rx, MatchTimeout);

    // A settings type keeps its hosts in one field and its ports in another ("a.example,b.example" and "8080,443"): a C2
    // is the pair, which neither value shows alone. Pairs of the first host field and the first port field of each type.
    static IEnumerable<Ioc> HostPorts(Session s, LoadedModule m)
    {
        var values = FieldValues(s, m).Where(kv => kv.Key.IsStatic && kv.Key.DeclaringType != null);
        foreach (var type in values.GroupBy(kv => kv.Key.DeclaringType))
        {
            var fields = type.OrderBy(kv => kv.Key.MDToken.Raw).ToList();
            var host = fields.Select(kv => (kv.Key, kv.Value, Hosts: kv.Value.Value is string v ? Find(v).Where(h => h.Kind == "domain" && !h.Value.Contains(':')
                                                                                                       || h.Kind == "ip" && !h.Value.Contains(':')).Select(h => h.Value).Distinct().ToList() : []))
                .FirstOrDefault(h => h.Hosts.Count > 0);
            var port = fields.Select(kv => (kv.Key, kv.Value, Ports: Ports(kv.Value.Value))).FirstOrDefault(p => p.Ports.Count > 0);
            if (host.Key == null || port.Key == null) continue;
            var source = host.Value.Source == "decoded" || port.Value.Source == "decoded" ? "decoded" : host.Value.Source;
            foreach (var pair in host.Hosts.SelectMany(h => port.Ports.Select(p => $"{h}:{p}")).Take(MaxPairs))
                yield return new Ioc(m, "host:port", pair, null, 0, source, Fields: $"{host.Key.FullName} + {port.Key.FullName}");
        }
    }

    static List<int> Ports(object? v)
    {
        if (v is long l) return l is >= 1 and <= 65535 ? [(int)l] : [];
        if (v is not string s || s.Length > 200 || !PortList.IsMatch(s)) return [];
        var ports = s.Split([',', ';', '|'], StringSplitOptions.TrimEntries).Select(p => int.TryParse(p, out var n) ? n : 0).ToList();
        return ports.All(p => p is >= 1 and <= 65535) ? ports.Distinct().ToList() : [];
    }

    // XML namespaces and schema identifiers are URLs nobody connects to; a host without a dot or a port ("http://update")
    // is a placeholder
    static readonly string[] SchemaHosts = ["www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
                                            "schemas.android.com", "purl.org", "ns.adobe.com", "xmlns.com", "www.xml.org"];

    static bool Addressable(string url)
    {
        var rest = url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var host = rest.Split('/', '?', '#')[0];
        var at = host.LastIndexOf('@');
        if (at >= 0) host = host[(at + 1)..];
        var name = host.Split(':')[0];
        if (SchemaHosts.Contains(name)) return false;
        return name.Contains('.') || host.Contains(':') || name == "localhost";
    }

    static List<(string Kind, string Value)> Find(string text)
    {
        try { return FindAll(text).ToList(); }
        catch (RegexMatchTimeoutException) { return []; } // a literal built to defeat the patterns is not an indicator
    }

    static IEnumerable<(string Kind, string Value)> FindAll(string text)
    {
        foreach (Match u in Url.Matches(text))
        {
            var v = u.Value.TrimEnd('.', ',', ')', ';');
            var lower = v.ToLowerInvariant();
            if (!Addressable(lower)) continue;
            yield return (lower.Contains("discord.com/api/webhooks") || lower.Contains("discordapp.com/api/webhooks") ? "discord webhook"
                          : lower.Contains("api.telegram.org/bot") ? "telegram bot" : "url", v);
        }
        foreach (Match t in TelegramToken.Matches(text)) yield return ("telegram token", t.Value);
        foreach (Match e in Email.Matches(text))
            if (!ProtocolIds.Any(d => e.Value.EndsWith(d, StringComparison.OrdinalIgnoreCase))) yield return ("email", e.Value);
        // an address alone (or as host:port), not a dotted number inside text ("version 6.9.0.114", an OID)
        if (!Url.IsMatch(text))
            foreach (Match ip in Ip.Matches(text))
                if (ValidIp(ip.Value) && (ip.Value.Contains(':') || ip.Length == text.Trim().Length)) yield return ("ip", ip.Value);
        // a whole literal, or each item of a host list ("a.duckdns.org:9469,b.duckdns.org:9469") or of key=value settings
        foreach (var item in text.Split([',', ';', '|', '=', ' ', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Prepend(text.Trim()).Distinct())
            foreach (var hit in Whole(item))
                yield return hit;
    }

    // SSH and similar protocol identifiers look like e-mail addresses (keepalive@openssh.com).
    static readonly string[] ProtocolIds = ["@openssh.com", "@openssh.org", "@libssh.org", "@ssh.com"];

    static IEnumerable<(string Kind, string Value)> Whole(string whole)
    {
        if (whole.Length > 260) yield break; // hosts, wallets and registry keys are short
        if (Domain.Match(whole) is { Success: true } d && Tlds.Contains(d.Groups[1].Value)) yield return ("domain", whole);
        if (Btc.IsMatch(whole) && !whole.All(char.IsAsciiHexDigit)) yield return ("btc wallet", whole); // not a hex string
        if (Eth.IsMatch(whole) && whole[2..].Distinct().Count() >= 8) yield return ("eth wallet", whole); // not 0x00...01
        if (Xmr.IsMatch(whole)) yield return ("xmr wallet", whole);
        if (Registry.IsMatch(whole)) yield return ("registry", whole);
    }

    // Four octets up to 255; not an assembly version (4.0.0.0), 0.0.0.0, or an X.509 object identifier (1.3.6.1, 2.5.29.14:
    // the arcs certificate code is full of).
    static readonly string[] OidArcs = ["1.2.", "1.3.", "2.5.", "2.16.", "2.23."];

    static bool ValidIp(string v)
    {
        var ip = v.Split(':')[0];
        var parts = ip.Split('.');
        if (parts.Any(p => !int.TryParse(p, out var n) || n > 255 || p.Length > 1 && p[0] == '0')) return false;
        // not 0.x, a broadcast, or a version (two or more zero parts without a port: 1.0.1.0, 2.0.0.1; loopback is not one)
        return parts[0] != "0" && ip != "255.255.255.255" && (v.Contains(':') || parts[0] == "127" || parts.Count(p => p == "0") < 2)
               && !OidArcs.Any(a => ip.StartsWith(a, StringComparison.Ordinal));
    }

    // A base64 literal that decodes to readable text (a hidden URL or host), or null.
    static string? Base64Text(string s)
    {
        if (s.Length < 12 || s.Length % 4 != 0 || !s.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '+' or '/' or '=')) return null;
        try
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(s));
            return text.Length > 0 && text.Count(ch => ch >= 0x20 && ch < 0x7F) >= text.Length * 0.95 ? text : null;
        }
        catch (FormatException) { return null; }
    }
}
