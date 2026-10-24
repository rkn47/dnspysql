// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql.Tables;

/// <summary>
/// The questions of a malware triage that otherwise take a page of joins over il and xrefs: what a type's constructors
/// store in its fields (where configs live) and what the code does (injection, persistence, download and execute, ...)
/// and at which call. Every row points at the IL that holds the evidence, so it can be decompiled or given to bp_set.
/// Both read the IL as it is; decoded_fields is the one table here that interprets code (Emulator), and only when asked.
/// </summary>
public static class TriageTables
{
    public sealed record FieldInit(LoadedModule M, IField Field, MethodDef SetIn, uint Offset, string Kind, object? Value, string Source = "literal");
    public sealed record Capability(LoadedModule M, string Kind, string Api, XRef Site, string Evidence);
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
            .Text("source", f => f.Source, doc: "literal | getter (a method returning a constant). A value a call computes is not here: " +
                                                "decryptor_calls and decoded_fields interpret it")
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

    public sealed record Piece(long Index, string Value);

    static void RegisterTextTables(Session s)
    {
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
                        else if (Prev(ins, i) is var k and >= 0 && ins[k].OpCode.Code == Code.Call && ins[k].Operand is IMethod g
                                 && ProtectionTables.Getter(g, fold.Getters) is { } got)
                            yield return new FieldInit(m, f, ctor, ins[i].Offset, KindOf(got.Value), got.Value, "getter");
                    }
            }
    }

    static FieldDef? FieldDefOf(IField f)
    {
        try { return f.ResolveFieldDef(); } catch (Exception) { return null; } // a reference that does not resolve names no field here
    }

    // ---- decoded settings ----------------------------------------------------------------------------------------------

    // Per module, until the next edit (or a change of the emulation setting): what its decoders leave, and the fields
    // whose interpreted value was asked for.
    sealed class Cache
    {
        public (long Revision, int Epoch) Key = (-1, -1);
        public List<Decoded>? Decoded;
        public readonly Dictionary<FieldDef, (object? Value, string Source)?> Values = new();
    }
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, Cache> _caches = new();
    // set while the decoders are interpreted: nothing they do asks for a field's value, but a cycle must not start one
    [ThreadStatic] static int _busy;

    static Cache CacheOf(Session s, LoadedModule m)
    {
        var c = _caches.GetValue(m, _ => new Cache());
        lock (c)
            if (c.Key != (s.Ws.Revision, s.EmulationEpoch))
            {
                (c.Key, c.Decoded) = ((s.Ws.Revision, s.EmulationEpoch), null);
                c.Values.Clear();
            }
        return c;
    }

    // decoded_fields interprets a module's decoders when it is read (or when decryptor_calls folds a field they write):
    // a few, each on a small budget, and no more once the module has used its time
    const int MaxDecoders = 8;
    static readonly TimeSpan DecodeTime = TimeSpan.FromSeconds(20);

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

    /// <summary>A settings type and one of its decoders, found from the IL alone: what decoded_fields would interpret.</summary>
    internal sealed record DecoderSite(TypeDef Settings, MethodDef Decoder, Dictionary<FieldDef, uint> Stored);

    // A settings type: its static constructor stores string literals into three or more of its static fields. Its decoders:
    // parameterless static methods (not the static constructor) that read two or more of its static fields and store two
    // or more back with a value a call returned. Nothing here is about one family; the shape is what settings code has.
    internal static IEnumerable<DecoderSite> Decoders(Session s, LoadedModule m)
    {
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
                yield return new DecoderSite(t, decoder, stored);
        }
    }

    static IEnumerable<Decoded> FindDecoded(Session s, LoadedModule m)
    {
        int decoders = 0;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        foreach (var (t, decoder, stored) in Decoders(s, m))
        {
            if (++decoders > MaxDecoders || clock.Elapsed > DecodeTime)
            {
                yield return new Decoded(m, null, t, null, null, decoder, 0,
                    $"not run: this module's decoders used their budget ({MaxDecoders} decoders, {DecodeTime.TotalSeconds:N0} s)");
                yield break;
            }
            var run = Emulator.Decode(s, decoder, t);
            foreach (var (f, before, after) in run.Changed)
                yield return new Decoded(m, f, t, before, after, decoder, stored.GetValueOrDefault(f), run.Error);
            if (run.Changed.Count == 0)
                yield return new Decoded(m, null, t, null, null, decoder, 0, run.Error ?? "the decoder left every field as the static constructor stored it");
        }
    }

    /// <summary>
    /// A static field's value once the program has started, interpreted, for folding Decrypt(Settings.Host) to a call with
    /// a known argument (decryptor_calls): what its decoder leaves (decoded), else what its static constructor leaves
    /// (computed). Null when neither gives one, or while the decoders are being interpreted.
    /// </summary>
    internal static (object? Value, string Source)? KnownValue(Session s, FieldDef fd)
    {
        if (_busy > 0 || s.Ws.Find(fd.Module) is not { } lm) return null;
        var c = CacheOf(s, lm);
        lock (c) if (c.Values.TryGetValue(fd, out var known)) return known;
        (object? Value, string Source)? v = null;
        try
        {
            if (DecodedFields(s, lm).FirstOrDefault(d => d.Field == fd && d.Value != null) is { } d) v = (d.Value, "decoded");
            else if (Emulator.StaticValue(s, fd) is { Value: { } value }) v = (value, "computed");
        }
        catch (Exception e) when (e is not (OperationCanceledException or OutOfMemoryException)) { v = null; } // a sample's code is not ours to fail on
        lock (c) c.Values[fd] = v;
        return v;
    }

    /// <summary>The decoder that left the field's decoded value, if one did.</summary>
    internal static MethodDef? DecodedBy(Session s, FieldDef fd) =>
        _busy > 0 || s.Ws.Find(fd.Module) is not { } lm ? null : DecodedFields(s, lm).FirstOrDefault(d => d.Field == fd && d.Value != null)?.Decoder;

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
        // a hex digest or a GUID's digits are base64 characters too, and decode to noise: they are text
        if (s.All(char.IsAsciiHexDigit)) return "text";
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
}
