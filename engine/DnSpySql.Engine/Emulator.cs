// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

/// <summary>
/// An IL interpreter for the pure helpers malware hides its strings behind (string decryptors, constant tables): it
/// reads the method's IL and computes the result itself, so the sample never runs. A call into the sample is
/// interpreted the same way; a call into the framework is made only for an allowlist of types that compute on data
/// in memory (strings, encodings, conversions, arrays, hashes and ciphers, in-memory and compression streams). Nothing
/// it can create reaches a file, the network, a process or the registry, so an allowed call cannot either. Reflection,
/// delegates and types are descriptions the interpreter keeps (MethodStub, DelegateStub, TypeStub, ...), never real
/// MethodInfos, delegates or System.Types: invoking one is a call like any other. Anything else stops the emulation
/// with a reason.
/// </summary>
public sealed class Emulator
{
    public sealed class Failed(string why) : Exception(why)
    {
        public bool Located { get; init; }
    }

    // where a call stopped ("... at IL_0123 of 0x0600000D"), recorded by the innermost frame's exception filter (Mark)
    (MethodDef Method, uint Offset) _at;

    Failed Locate(Failed e) => e.Located || _at.Method == null ? e
        : new Failed($"{e.Message} (at IL_{_at.Offset:X4} of 0x{_at.Method.MDToken.Raw:X8})") { Located = true };

    /// <summary>An instance of a sample-defined class: its type and instance fields.</summary>
    sealed class Obj(TypeDef type)
    {
        public readonly TypeDef Type = type;
        public readonly Dictionary<IField, object?> Fields = new(FieldEq.Instance);
    }

    /// <summary>A managed pointer (ldloca, ldarga, ldelema, ldsflda, ldflda): reads and writes through to its slot.</summary>
    sealed class Ref(Func<object?> get, Action<object?> set)
    {
        public object? Get() => get();
        public void Set(object? v) => set(v);
    }

    /// <summary>ldftn/ldvirtftn: the method a delegate will call.</summary>
    sealed record FnPtr(IMethod Method, MethodDef? Def);

    /// <summary>A delegate: invoking it interprets its method (a sample method is never run, only interpreted).</summary>
    sealed record DelegateStub(object? Target, FnPtr Fn);

    /// <summary>The sample's own assembly (GetExecutingAssembly): its manifest resources, read from the file.</summary>
    sealed record AsmStub(LoadedModule M);

    /// <summary>AppDomain.CurrentDomain: subscribing to its resolve events is accepted and ignored.</summary>
    sealed record AppDomainStub;

    // Assemblies the code loads from bytes (Assembly.Load(byte[])): parsed, never run, and kept here by name, so a
    // resource linked to one is found where the CLR's AssemblyResolve would find it.
    readonly Dictionary<string, LoadedModule> _loaded = new(StringComparer.OrdinalIgnoreCase);

    AsmStub LoadAssembly(byte[] bytes)
    {
        if (bytes.Length > 256 << 20) throw new Failed("Assembly.Load of more than 256 MB");
        ModuleDefMD md;
        try { md = ModuleDefMD.Load(bytes, new ModuleCreationOptions { TryToLoadPdbFromDisk = false }); }
        catch (Exception e) when (e is BadImageFormatException or IOException or ArgumentException or InvalidDataException)
        { throw new Failed($"Assembly.Load of bytes that are not a .NET module ({e.GetType().Name})"); }
        var name = md.Assembly?.Name.String ?? md.Name.String;
        if (!_loaded.TryGetValue(name, out var lm))
            _loaded[name] = lm = new LoadedModule { Id = 0, Module = md, Path = $"{name} (loaded by the code)", OriginalBytes = bytes };
        return new AsmStub(lm);
    }

    /// <summary>new Thread(start): started, its code is not run (one thread here; startup threads are usually watchdogs).</summary>
    sealed record ThreadStub(object? Start);

    /// <summary>Process.GetCurrentProcess(), for anti-debug checks: a pseudo handle and an id, nothing else.</summary>
    sealed record ProcessStub;

    /// <summary>typeof(SampleType).Module: its name (as loaded from bytes) and its base address (GetHINSTANCE).</summary>
    sealed record ModuleStub(LoadedModule M);

    /// <summary>typeof(SampleType): its module, assembly and members, for reflection.</summary>
    sealed record TypeStub(TypeDef Type);

    /// <summary>
    /// typeof(T) of a type the interpreter models (primitives, string, allowed framework types, arrays of them; T resolved
    /// in generic code): a wrapper, not a System.Type, answering the few questions generic code asks of a type.
    /// </summary>
    sealed record ClrTypeStub(Type Type, TypeDef? Def = null)
    {
        public bool Equals(ClrTypeStub? o) => o != null && o.Type == Type;
        public override int GetHashCode() => Type.GetHashCode();
    }

    /// <summary>typeof(T) of a framework type outside the allowlist (Environment, say): its name and members, for lookups.</summary>
    sealed record RefTypeStub(TypeDef Def);

    /// <summary>
    /// A method or field reflection found (ldtoken, GetMethod, ResolveMethod, ...): a description, never a MethodInfo.
    /// Invoking the method is a call like any other: a sample method is interpreted, a framework one goes through the
    /// allowlist. Def is set for sample methods only.
    /// </summary>
    sealed record MethodStub(IMethod Method, MethodDef? Def);
    sealed record FieldStub(IField Field, FieldDef? Def);

    /// <summary>A ResourceManager over one of the sample's .resources files.</summary>
    sealed record RmStub(LoadedModule M, string BaseName);

    sealed class FieldEq : IEqualityComparer<IField>
    {
        public static readonly FieldEq Instance = new();
        public bool Equals(IField? a, IField? b) => a == b || a != null && b != null && a.FullName == b.FullName;
        public int GetHashCode(IField f) => f.FullName.GetHashCode();
    }

    readonly Session _s;
    readonly Dictionary<IField, object?> _statics = new(FieldEq.Instance);
    readonly HashSet<TypeDef> _initialized = new();
    readonly Func<CancellationToken> _cancel;
    long _steps;
    // A call's budget, and a static constructor's: those run once per session and can be long (a decompressor or a
    // table builder behind control-flow obfuscation), while a decryptor call is short.
    public long MaxSteps { get; init; } = 20_000_000;
    public long MaxStaticSteps { get; init; } = 200_000_000;
    long _limit;
    const int MaxDepth = 64, MaxArray = 16 << 20;

    public Emulator(Session s, Func<CancellationToken>? cancel = null)
    {
        _s = s;
        _cancel = cancel ?? (() => CancellationToken.None);
    }

    // One per session, holding the sample's static state (a decryptor's tables, initialized once like the CLR would),
    // and started afresh after any edit to the model.
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Session, StrongBox> _sessions = new();
    sealed class StrongBox { public long Revision = -1; public Emulator? Value; }

    public static Emulator For(Session s)
    {
        var box = _sessions.GetValue(s, _ => new StrongBox());
        lock (box)
        {
            if (box.Value == null || box.Revision != s.Ws.Revision)
            {
                box.Value = new Emulator(s, () => s.Db.Cancellation);
                box.Revision = s.Ws.Revision;
            }
            return box.Value;
        }
    }

    readonly Dictionary<string, (object? Value, string? Error)> _memo = new(StringComparer.Ordinal);

    // The image anti-tamper code reads and decrypts through pointers: a copy of the file at a made-up base address.
    // FullyQualifiedName says "<Unknown>" (loaded from bytes), so the code uses the file layout, which is this copy.
    const long ImageBase = 0x10000000;
    byte[]? _image;
    LoadedModule? _imageOf;

    /// <summary>The image after the code that ran changed it, or null if nothing asked for it.</summary>
    public byte[]? Image => _image;

    byte[] ImageOf(LoadedModule m)
    {
        if (_image == null) { _image = (byte[])(m.FileBytes ?? m.OriginalBytes).Clone(); _imageOf = m; }
        else if (_imageOf != m) throw new Failed("pointers into a second module's image");
        return _image;
    }

    int At(object? address, int size)
    {
        long a = address switch { long l => l, int i => (uint)i, _ => throw new Failed($"pointer access through a {Describe(address)}") };
        long off = a - ImageBase;
        if (_image == null || off < 0 || off + size > _image.Length) throw new Failed($"pointer 0x{a:X} outside the module image");
        return (int)off;
    }

    object Read(Code op, object? address)
    {
        int size = op switch { Code.Ldind_I1 or Code.Ldind_U1 => 1, Code.Ldind_I2 or Code.Ldind_U2 => 2, Code.Ldind_I8 or Code.Ldind_I or Code.Ldind_R8 => 8, _ => 4 };
        var span = _image.AsSpan(At(address, size), size);
        // each arm boxed as itself: a switch expression would otherwise widen them all to double
        return op switch
        {
            Code.Ldind_I1 => (object)(int)(sbyte)span[0], Code.Ldind_U1 => (object)(int)span[0],
            Code.Ldind_I2 => (object)(int)BitConverter.ToInt16(span), Code.Ldind_U2 => (object)(int)BitConverter.ToUInt16(span),
            Code.Ldind_I8 or Code.Ldind_I => (object)BitConverter.ToInt64(span), Code.Ldind_R4 => (object)(double)BitConverter.ToSingle(span),
            Code.Ldind_R8 => (object)BitConverter.ToDouble(span),
            Code.Ldind_I4 or Code.Ldind_U4 => (object)BitConverter.ToInt32(span),
            _ => throw new Failed($"{op} through a pointer"),
        };
    }

    long _written; // bytes stored into the image

    void Write(Code op, object? address, object? v)
    {
        int size = op switch { Code.Stind_I1 => 1, Code.Stind_I2 => 2, Code.Stind_I8 or Code.Stind_I or Code.Stind_R8 => 8, _ => 4 };
        var span = _image.AsSpan(At(address, size), size);
        _written += size;
        long l = v switch { int i => i, long x => x, double d => (long)d, _ => throw new Failed($"{op} of a {Describe(v)}") };
        switch (size)
        {
            case 1: span[0] = (byte)l; break;
            case 2: BitConverter.TryWriteBytes(span, (short)l); break;
            case 4: if (op == Code.Stind_R4) BitConverter.TryWriteBytes(span, (float)Num(v)); else BitConverter.TryWriteBytes(span, (int)l); break;
            default: if (op == Code.Stind_R8) BitConverter.TryWriteBytes(span, Num(v)); else BitConverter.TryWriteBytes(span, l); break;
        }
    }

    /// <summary>
    /// Interprets a routine that rewrites the module's own image through pointers (a self-decrypting startup routine:
    /// method bodies decrypted in place) and returns the image it leaves. Only that routine runs: its type's static
    /// constructor, which usually calls it, is not run, so nothing is rewritten twice.
    /// </summary>
    public byte[] Untamper(MethodDef initializer)
    {
        lock (_gate)
        {
            _initialized.Add(initializer.DeclaringType);
            if (initializer.Module?.GlobalType is { } global) _initialized.Add(global); // it usually calls the routine: not twice
            (_steps, _limit) = (0, MaxStaticSteps);
            _untampering = true;
            _at = default;
            try { Invoke(initializer, [], null, 0); }
            catch (Decrypted) { } // it went on to call code it had just decrypted: its work is done
            catch (Failed e) { throw Locate(e); }
            catch (Exception e) when (e is not (OperationCanceledException or OutOfMemoryException))
            { throw Locate(new Failed($"emulator error {e.GetType().Name}: {e.Message}")); }
            return _image ?? throw new Failed("the initializer never read the module's image (not an anti-tamper initializer?)");
        }
    }

    /// <summary>
    /// Call, remembered per method and arguments for this emulator's life (until the next edit): decryptors are pure, and
    /// decryptor_calls, field_inits and iocs ask for the same plaintexts. Returns the SQL value or the reason.
    /// </summary>
    public (object? Value, string? Error) Cached(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs = null)
    {
        var key = $"{method.Module?.Mvid}:{method.MDToken.Raw:X8}:{string.Join(",", genericArgs?.Select(g => g.FullName) ?? [])}:" +
                  string.Join("\u0001", args.Select(a => a switch { null => "null", byte[] b => "b" + Convert.ToHexString(b), _ => a.GetType().Name + a }));
        lock (_gate)
        {
            if (_memo.TryGetValue(key, out var hit)) return hit;
            try { hit = (ToSql(Call(method, args, genericArgs)), null); }
            catch (Failed e) { hit = (null, e.Message); }
            return _memo[key] = hit;
        }
    }

    /// <summary>Runs a method on the given arguments and returns its result; throws Failed with the reason it could not.</summary>
    // The emulator is shared by a session's statements (an MCP or HTTP server can run two): one call at a time.
    readonly object _gate = new();

    public object? Call(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs = null)
    {
        lock (_gate) return CallLocked(method, args, genericArgs);
    }

    object? CallLocked(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs)
    {
        _steps = 0;
        _limit = MaxSteps;
        _at = default;
        if (!method.IsStatic) throw new Failed("only static methods can be called directly");
        var a = new object?[method.Parameters.Count];
        if (args.Count != a.Length) throw new Failed($"{method.Name} takes {a.Length} argument(s), got {args.Count}");
        try
        {
            for (int i = 0; i < a.Length; i++) a[i] = FromSql(args[i], method.Parameters[i].Type);
            return Invoke(method, a, genericArgs, 0);
        }
        catch (Failed e) { throw Locate(e); }
        catch (Exception e) when (e is not (OperationCanceledException or OutOfMemoryException))
        { throw Locate(new Failed($"emulator error {e.GetType().Name}: {e.Message}")); }
    }

    // SQL values as the method's parameters expect them: integers as int32/int64, text as a string, blobs as byte[].
    static object? FromSql(object? v, TypeSig t) => t.ElementType switch
    {
        ElementType.I8 or ElementType.U8 => Convert.ToInt64(v),
        ElementType.R4 or ElementType.R8 => Convert.ToDouble(v),
        ElementType.String => v?.ToString(),
        ElementType.SZArray when v is byte[] b => b,
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4
            => v is null ? 0 : unchecked((int)Convert.ToInt64(v)),
        _ => v,
    };

    /// <summary>The result as SQL can hold it: text, integer, real or blob.</summary>
    public static object? ToSql(object? v) => v switch
    {
        null => null,
        string or long or double or byte[] => v,
        int i => (long)i,
        char[] cs => new string(cs),
        bool b => b ? 1L : 0L,
        StringBuilder sb => sb.ToString(),
        Array a => System.Text.Json.JsonSerializer.Serialize(a.Cast<object?>().Select(ToSql)),
        _ => v.ToString(),
    };

    // ---- interpretation ----------------------------------------------------------------------------------------------

    int _depth; // the innermost interpreted frame, for callbacks from the framework

    // While untampering: a call into a body that is encrypted in the file, once the image has been written, means the
    // initializer has decrypted the bodies (in the process it would now run the decrypted code, which is not ours to run).
    bool _untampering;
    sealed class Decrypted : Exception;

    // The module initializer (<Module>'s static constructor) runs before any other code of its module, as in the CLR:
    // it loads the assemblies, tables and keys the rest of the code reads.
    readonly HashSet<ModuleDef> _modulesStarted = new();

    object? Invoke(MethodDef m, object?[] args, IList<TypeSig>? genericArgs, int depth)
    {
        // _depth is the innermost frame while this one runs, and the caller's again once it returns: callbacks and
        // reflected calls made in a loop stay at the same depth
        var outer = _depth;
        try { return InvokeFrame(m, args, genericArgs, depth); }
        finally { _depth = outer; }
    }

    // The startup routines untamper() already applied: in its copy they would decrypt the decrypted bodies (and whatever
    // else they rewrite) a second time, so a call to one does nothing. Kept per module count: modules are only added.
    HashSet<MethodDef>? _applied;
    int _appliedFor = -1;

    bool Applied(MethodDef m)
    {
        var mods = _s.Ws.Modules;
        if (_appliedFor != mods.Count)
        {
            _applied = mods.Where(x => x.UntamperedBy != null).Select(x => x.Module.ResolveToken(x.UntamperedBy!.Value) as MethodDef)
                .OfType<MethodDef>().ToHashSet();
            _appliedFor = mods.Count;
        }
        return _applied!.Count > 0 && _applied.Contains(m);
    }

    object? InvokeFrame(MethodDef m, object?[] args, IList<TypeSig>? genericArgs, int depth)
    {
        if (depth > MaxDepth) throw new Failed("call depth exceeded");
        if (!_untampering && m.IsStatic && args.Length == 0 && Applied(m)) return null;
        if (args.Length != m.Parameters.Count)
            throw new Failed($"{m.Name} called with {args.Length} argument(s) for {m.Parameters.Count} parameter(s)");
        if (m.Module is { } mod && _modulesStarted.Add(mod) && mod.GlobalType is { } global && global != m.DeclaringType)
            EnsureStaticInit(global, depth);
        _depth = depth;
        if (m.IsStatic || m.IsConstructor) EnsureStaticInit(m.DeclaringType, depth);
        if (_untampering && _written > 0 && _s.Ws.Find(m.Module) is { } ml
            && DnSpySql.Tables.HexTables.Undecodable(ml).ContainsKey(m.MDToken.Raw)) throw new Decrypted();
        // byte[] f(byte[]) given a well-formed LZMA stream: decoded natively (Lzma), not by interpreting the sample's
        // decoder, which behind control-flow obfuscation can take hundreds of millions of steps
        if (m.IsStatic && args is [byte[] packed] && m.MethodSig is { Params: [SZArraySig { Next.ElementType: ElementType.U1 }] } ms
            && ms.RetType is SZArraySig { Next.ElementType: ElementType.U1 } && Lzma.TryDecode(packed) is { } unpacked)
            return unpacked;
        if (!m.HasBody || m.Body == null) throw new Failed($"{m.FullName} has no IL body (native, abstract or extern)");
        if (!_untampering && Undecodable(m)) throw new Failed($"the body of 0x{m.MDToken.Raw:X8} does not decode as IL in the file (encrypted until runtime)");
        var body = m.Body;
        if (body.Instructions.Count == 0) throw new Failed($"{m.FullName} has an empty body (encrypted until runtime?)");
        var locals = new object?[body.Variables.Count];
        for (int i = 0; i < locals.Length; i++) locals[i] = Zero(body.Variables[i].Type);
        var c = Compile(body, m);
        var code = c.Code;
        var ops = c.Ops;
        var stack = new EvalStack(body.MaxStack);
        int pc = 0;
        try
        {
        while (true)
        {
            if ((uint)pc >= (uint)code.Length) throw new Failed($"ran off the end of {m.Name}");
            if (++_steps > _limit) throw new Failed($"stopped after {_limit:N0} IL instructions");
            if ((_steps & 0xFFF) == 0) _cancel().ThrowIfCancellationRequested();
            var x = code[pc];
            var op = ops[pc++];
            switch (op)
            {
                case Code.Nop: case Code.Readonly: case Code.Volatile: case Code.Unaligned: case Code.Tailcall: case Code.Constrained: break;
                case Code.Ldarg: case Code.Ldarg_S: case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
                    stack.Push(args[ArgIndex(m, x)]); break;
                case Code.Starg: case Code.Starg_S:
                    args[ArgIndex(m, x)] = Copy(stack.Pop()); break;
                case Code.Ldarga: case Code.Ldarga_S:
                    { int k = ArgIndex(m, x); stack.Push(new Ref(() => args[k], v => args[k] = v)); break; }
                case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
                    stack.Push(locals[x.GetLocal(body.Variables).Index]); break;
                case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
                    locals[x.GetLocal(body.Variables).Index] = Store(stack.Pop(), x.GetLocal(body.Variables).Type); break;
                case Code.Ldloca: case Code.Ldloca_S:
                    { int k = x.GetLocal(body.Variables).Index; stack.Push(new Ref(() => locals[k], v => locals[k] = v)); break; }
                case Code.Ldnull: stack.Push(null); break;
                case Code.Ldc_I4: case Code.Ldc_I4_S: case Code.Ldc_I4_M1: case Code.Ldc_I4_0: case Code.Ldc_I4_1: case Code.Ldc_I4_2: case Code.Ldc_I4_3:
                case Code.Ldc_I4_4: case Code.Ldc_I4_5: case Code.Ldc_I4_6: case Code.Ldc_I4_7: case Code.Ldc_I4_8:
                    stack.Push(Box(x.GetLdcI4Value())); break;
                case Code.Ldstr: stack.Push((string)x.Operand); break;
                case Code.Ldc_I8: stack.Push((long)x.Operand); break;
                case Code.Ldc_R4: stack.Push((double)(float)x.Operand); break;
                case Code.Ldc_R8: stack.Push((double)x.Operand); break;
                case Code.Dup: stack.Push(stack.Peek()); break;
                case Code.Pop: stack.Pop(); break;

                case Code.Add: case Code.Add_Ovf: case Code.Add_Ovf_Un: case Code.Sub: case Code.Sub_Ovf: case Code.Sub_Ovf_Un:
                case Code.Mul: case Code.Mul_Ovf: case Code.Mul_Ovf_Un: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
                case Code.And: case Code.Or: case Code.Xor: case Code.Shl: case Code.Shr: case Code.Shr_Un:
                    { var b = stack.Pop(); var a = stack.Pop(); stack.Push(Arith(op, a, b)); break; }
                // (object) on every arm: int, long and double arms would make the switch double
                case Code.Neg: stack.Push(stack.Pop() switch { int i => Box(unchecked(-i)), long l => (object)unchecked(-l), double d => (object)(-d), var v => throw Bad("neg", v) }); break;
                case Code.Not: stack.Push(stack.Pop() switch { int i => Box(~i), long l => (object)~l, var v => throw Bad("not", v) }); break;

                case Code.Conv_I1: case Code.Conv_I2: case Code.Conv_I4: case Code.Conv_I8: case Code.Conv_U1: case Code.Conv_U2: case Code.Conv_U4:
                case Code.Conv_U8: case Code.Conv_I: case Code.Conv_U: case Code.Conv_R4: case Code.Conv_R8: case Code.Conv_R_Un:
                case Code.Conv_Ovf_I1: case Code.Conv_Ovf_I2: case Code.Conv_Ovf_I4: case Code.Conv_Ovf_I8: case Code.Conv_Ovf_U1: case Code.Conv_Ovf_U2:
                case Code.Conv_Ovf_U4: case Code.Conv_Ovf_U8: case Code.Conv_Ovf_I: case Code.Conv_Ovf_U:
                case Code.Conv_Ovf_I1_Un: case Code.Conv_Ovf_I2_Un: case Code.Conv_Ovf_I4_Un: case Code.Conv_Ovf_I8_Un: case Code.Conv_Ovf_U1_Un:
                case Code.Conv_Ovf_U2_Un: case Code.Conv_Ovf_U4_Un: case Code.Conv_Ovf_U8_Un: case Code.Conv_Ovf_I_Un: case Code.Conv_Ovf_U_Un:
                    stack.Push(Conv(op, stack.Pop())); break;

                case Code.Ceq: { var b = stack.Pop(); var a = stack.Pop(); stack.Push(Eq(a, b) ? 1 : 0); break; }
                case Code.Cgt: case Code.Cgt_Un: case Code.Clt: case Code.Clt_Un:
                    { var b = stack.Pop(); var a = stack.Pop(); stack.Push(Compare(op, a, b) ? 1 : 0); break; }

                case Code.Br: case Code.Br_S: case Code.Leave: case Code.Leave_S:
                    pc = c.Target[pc - 1]; break;
                case Code.Brtrue: case Code.Brtrue_S: if (Truth(stack.Pop())) pc = c.Target[pc - 1]; break;
                case Code.Brfalse: case Code.Brfalse_S: if (!Truth(stack.Pop())) pc = c.Target[pc - 1]; break;
                case Code.Beq: case Code.Beq_S: case Code.Bne_Un: case Code.Bne_Un_S: case Code.Bge: case Code.Bge_S: case Code.Bge_Un: case Code.Bge_Un_S:
                case Code.Bgt: case Code.Bgt_S: case Code.Bgt_Un: case Code.Bgt_Un_S: case Code.Ble: case Code.Ble_S: case Code.Ble_Un: case Code.Ble_Un_S:
                case Code.Blt: case Code.Blt_S: case Code.Blt_Un: case Code.Blt_Un_S:
                    { var b = stack.Pop(); var a = stack.Pop(); if (Branch(op, a, b)) pc = c.Target[pc - 1]; break; }
                case Code.Switch:
                    {
                        var targets = c.Switch[pc - 1]!;
                        var v = stack.Pop() switch { int i => (uint)i, long l => (ulong)l, var o => throw Bad("switch", o) };
                        if (v < (ulong)targets.Length) pc = targets[v];
                        break;
                    }
                case Code.Endfinally: case Code.Endfilter:
                    throw new Failed("exception handling is not emulated");
                case Code.Ret:
                    return m.MethodSig.RetType.ElementType == ElementType.Void ? null : stack.Pop();
                case Code.Throw: case Code.Rethrow:
                    throw new Failed($"{m.Name} throws");

                case Code.Newarr:
                    {
                        long n = AsLong(stack.Pop());
                        if (n < 0 || n > MaxArray) throw new Failed($"array of {n} elements");
                        var et = (ITypeDefOrRef)x.Operand;
                        if (SampleStruct(et.ToTypeSig()) is { } st)
                        {
                            if (n > 1 << 20) throw new Failed($"array of {n} sample structs");
                            var arr = new object?[n];
                            for (int k = 0; k < n; k++) arr[k] = Zero(st.ToTypeSig());
                            stack.Push(arr);
                        }
                        else stack.Push(Array.CreateInstance(ElementClr(et), (int)n));
                        break;
                    }
                case Code.Ldlen: stack.Push(Arr(stack.Pop()).Length); break;
                case Code.Ldelem_I1: case Code.Ldelem_U1: case Code.Ldelem_I2: case Code.Ldelem_U2: case Code.Ldelem_I4: case Code.Ldelem_U4:
                case Code.Ldelem_I8: case Code.Ldelem_I: case Code.Ldelem_R4: case Code.Ldelem_R8: case Code.Ldelem_Ref: case Code.Ldelem:
                    { var i = (int)AsLong(stack.Pop()); var a = Arr(stack.Pop()); stack.Push(Stack(a.GetValue(Check(a, i)))); break; }
                case Code.Stelem_I1: case Code.Stelem_I2: case Code.Stelem_I4: case Code.Stelem_I8: case Code.Stelem_I: case Code.Stelem_R4:
                case Code.Stelem_R8: case Code.Stelem_Ref: case Code.Stelem:
                    {
                        var v = stack.Pop(); var i = (int)AsLong(stack.Pop()); var a = Arr(stack.Pop());
                        var et = a.GetType().GetElementType()!;
                        a.SetValue(et == typeof(object) ? Copy(v) : ToClr(v, et), Check(a, i)); // object[] holds sample objects too
                        break;
                    }
                case Code.Ldelema:
                    {
                        var i = (int)AsLong(stack.Pop()); var a = Arr(stack.Pop()); Check(a, i);
                        var t = a.GetType().GetElementType()!;
                        stack.Push(new Ref(() => Stack(a.GetValue(i)), v => a.SetValue(t == typeof(object) ? v : ToClr(v, t), i)));
                        break;
                    }
                case Code.Ldind_I1: case Code.Ldind_U1: case Code.Ldind_I2: case Code.Ldind_U2: case Code.Ldind_I4: case Code.Ldind_U4:
                case Code.Ldind_I8: case Code.Ldind_I: case Code.Ldind_R4: case Code.Ldind_R8: case Code.Ldind_Ref: case Code.Ldobj:
                    { var p = stack.Pop(); stack.Push(p is Ref pr ? Copy(pr.Get()) : op is Code.Ldind_Ref or Code.Ldobj ? throw Bad("indirect load", p) : Read(op, p)); break; }
                case Code.Stind_I1: case Code.Stind_I2: case Code.Stind_I4: case Code.Stind_I8: case Code.Stind_I: case Code.Stind_R4:
                case Code.Stind_R8: case Code.Stind_Ref: case Code.Stobj:
                    {
                        var v = stack.Pop(); var p = stack.Pop();
                        if (p is Ref pr) pr.Set(v);
                        else if (op is Code.Stind_Ref or Code.Stobj) throw Bad("indirect store", p);
                        else Write(op, p, v);
                        break;
                    }
                case Code.Initobj:
                    {
                        var t = (ITypeDefOrRef)x.Operand;
                        AsRef(stack.Pop()).Set(Zero(t.ToTypeSig()));
                        break;
                    }

                case Code.Ldsfld: stack.Push(LoadStatic((IField)x.Operand, depth)); break;
                case Code.Stsfld: StoreStatic((IField)x.Operand, stack.Pop(), depth); break;
                case Code.Ldsflda:
                    {
                        var f = (IField)x.Operand;
                        LoadStatic(f, depth);
                        stack.Push(new Ref(() => _statics[f], v => _statics[f] = v));
                        break;
                    }
                case Code.Ldfld:
                    {
                        var f = (IField)x.Operand;
                        var o = stack.Pop();
                        if (o is Ref r) o = r.Get();
                        stack.Push(o is Obj ob ? Field(ob, f) : throw new Failed($"field {f.Name} of a {Describe(o)}"));
                        break;
                    }
                case Code.Stfld:
                    {
                        var f = (IField)x.Operand;
                        var v = stack.Pop(); var o = stack.Pop();
                        if (o is Ref r) o = r.Get();
                        if (o is not Obj ob) throw new Failed($"field {f.Name} of a {Describe(o)}");
                        ob.Fields[f] = Store(v, f.FieldSig?.Type);
                        break;
                    }
                case Code.Ldflda:
                    {
                        var f = (IField)x.Operand;
                        var target = stack.Pop();
                        if ((target is Ref fr ? fr.Get() : target) is not Obj ob) throw new Failed($"address of field {f.Name} of a non-sample object");
                        stack.Push(new Ref(() => Field(ob, f), v => ob.Fields[f] = v));
                        break;
                    }

                case Code.Ldtoken:
                    // only for RuntimeHelpers.InitializeArray(array, field): the field's RVA data
                    if (x.Operand is FieldDef { InitialValue: { } data }) { stack.Push(data); break; }
                    if (x.Operand is ITypeDefOrRef tc) { stack.Push(TypeOf(tc.ToTypeSig(), genericArgs) ?? throw new Failed($"ldtoken of {tc.FullName}, which does not resolve")); break; }
                    if (x.Operand is FieldDef or MemberRef { IsFieldRef: true }) { var lf = (IField)x.Operand; stack.Push(new FieldStub(lf, FieldOf(lf))); break; }
                    if (x.Operand is IMethod lm) { stack.Push(MethodOf(lm)); break; }
                    throw new Failed($"ldtoken of {x.Operand}");

                case Code.Box: stack.Push(Copy(stack.Pop())); break; // a boxed struct is a copy
                case Code.Unbox_Any: case Code.Unbox:
                    stack.Push(Unbox(stack.Pop(), ((ITypeDefOrRef)x.Operand).ToTypeSig(), genericArgs)); break;
                case Code.Castclass: case Code.Isinst:
                    {
                        var v = stack.Pop();
                        bool fits = v == null || Fits(v, ((ITypeDefOrRef)x.Operand).ToTypeSig(), genericArgs);
                        if (!fits && op == Code.Castclass) throw new Failed($"cast of a {Describe(v)} to {x.Operand}");
                        stack.Push(fits ? v : null);
                        break;
                    }

                case Code.Call: case Code.Callvirt: case Code.Newobj:
                    {
                        var target = (IMethod)x.Operand;
                        var sig = target.MethodSig ?? throw new Failed($"call without a signature: {target}");
                        int n = sig.Params.Count + (sig.HasThis && op != Code.Newobj ? 1 : 0);
                        var a = new object?[n];
                        for (int i = n - 1; i >= 0; i--) a[i] = stack.Pop();
                        object? result;
                        // A static constructor is often a row of independent initializers (a module initializer that sets up
                        // several things in turn). One that cannot be interpreted is skipped and the others still run;
                        // what it would have set stays unset, and reading that reports why (EnsureStaticInit, LoadStatic).
                        if (m.IsStaticConstructor && op == Code.Call && n == 0 && sig.RetType.ElementType == ElementType.Void && !_untampering)
                        {
                            // each initializer gets the static-constructor budget of its own: one that loops does not starve the next
                            var (steps, limit) = (_steps, _limit);
                            (_steps, _limit) = (0, MaxStaticSteps);
                            try { result = CallTarget(target, a, op, genericArgs, depth, m); }
                            catch (Failed e) { _skipped.TryAdd(m.DeclaringType, e.Message); result = null; }
                            finally { (_steps, _limit) = (steps, limit); }
                        }
                        else result = CallTarget(target, a, op, genericArgs, depth, m);
                        if (op == Code.Newobj || sig.RetType.ElementType != ElementType.Void) stack.Push(result);
                        break;
                    }
                case Code.Ldftn:
                    stack.Push(Fn((IMethod)x.Operand, null)); break;
                case Code.Ldvirtftn:
                    { var o = stack.Pop(); stack.Push(Fn((IMethod)x.Operand, o is Ref r ? r.Get() : o)); break; }
                case Code.Calli:
                    throw new Failed("calli (function pointer call) is not emulated");
                case Code.UNKNOWN1:
                    throw new Failed($"invalid IL: {x.OpCode.Name} refers to nothing (encrypted until runtime?)");
                default:
                    throw new Failed($"opcode {x.OpCode.Name} is not emulated");
            }
        }
        }
        // the innermost frame names where a call stopped; the filter runs before unwinding, so nothing is caught here
        catch (Exception) when (Mark(m, code, pc)) { throw; }
    }

    bool Mark(MethodDef m, Instruction[] code, int pc)
    {
        if (_at.Method == null && pc > 0 && pc <= code.Length) _at = (m, code[pc - 1].Offset);
        return false;
    }

    FnPtr Fn(IMethod method, object? self)
    {
        MethodDef? def = null;
        try { def = method.ResolveMethodDef(); } catch (Exception) { }
        if (def != null && !Sample(def.DeclaringType)) def = null;
        if (def != null && self is Obj o) def = Override(o.Type, def) ?? def;
        return new FnPtr(method, def);
    }

    // A body as arrays, branch targets as indices, built once per body: decompressors call tiny methods millions of
    // times. Per emulator, which lives until the next edit (IL edits change a body in place).
    sealed class Compiled
    {
        public required Instruction[] Code;
        public required Code[] Ops;
        public required int[] Target;
        public required int[]?[] Switch;
    }

    readonly Dictionary<CilBody, Compiled> _compiled = new(ReferenceEqualityComparer.Instance);

    Compiled Compile(CilBody body, MethodDef m)
    {
        if (_compiled.TryGetValue(body, out var c)) return c;
        var code = body.Instructions.ToArray();
        int vars = body.Variables.Count, pars = m.Parameters.Count;
        // An instruction whose operand does not resolve: bytes that decode as IL without being IL, an encrypted body.
        // It runs as Code.UNKNOWN1, which stops.
        bool Invalid(Instruction x) => CodeIndex.InvalidOperand(x, vars, pars);
        var index = new Dictionary<Instruction, int>(code.Length, ReferenceEqualityComparer.Instance);
        for (int i = 0; i < code.Length; i++) index.TryAdd(code[i], i);
        int At(object? t) => t is Instruction ti && index.TryGetValue(ti, out var k) ? k : -1; // -1: off the body, stops at the next step
        c = new Compiled
        {
            Code = code,
            Ops = code.Select(x => Invalid(x) ? Code.UNKNOWN1 : x.OpCode.Code).ToArray(),
            Target = code.Select(x => At(x.Operand)).ToArray(),
            Switch = code.Select(x => x.Operand is Instruction[] ts ? ts.Select(t => At(t)).ToArray() : null).ToArray(),
        };
        return _compiled[body] = c;
    }

    // Bodies that do not decode in the file of an unedited module (anti-tamper, garbage IL), checked once per method.
    readonly Dictionary<MethodDef, bool> _undecodable = new(ReferenceEqualityComparer.Instance);

    bool Undecodable(MethodDef m)
    {
        if (_undecodable.TryGetValue(m, out var bad)) return bad;
        bad = _s.Ws.Find(m.Module) is { Dirty: false } lm && DnSpySql.Tables.HexTables.Undecodable(lm).ContainsKey(m.MDToken.Raw);
        return _undecodable[m] = bad;
    }

    // Boxed small integers, shared: arithmetic and constants box an int per instruction otherwise.
    static readonly object[] _boxes = Enumerable.Range(-256, 1281).Select(i => (object)i).ToArray();
    static object Box(int v) => v >= -256 && v <= 1024 ? _boxes[v + 256] : v;

    /// <summary>The evaluation stack: an array (Stack&lt;T&gt; checks versions on every call), and "empty" is a reason, not a crash.</summary>
    sealed class EvalStack(int capacity)
    {
        object?[] _items = new object?[Math.Max(capacity, 8)];
        int _count;

        public void Push(object? v)
        {
            if (_count == _items.Length)
            {
                if (_count >= 1 << 16) throw new Failed("evaluation stack overflow");
                Array.Resize(ref _items, _count * 2);
            }
            _items[_count++] = v;
        }

        public object? Pop() => _count > 0 ? _items[--_count] : throw new Failed("evaluation stack empty (invalid IL)");
        public object? Peek() => _count > 0 ? _items[_count - 1] : throw new Failed("evaluation stack empty (invalid IL)");
    }

    static int ArgIndex(MethodDef m, Instruction x) => x.OpCode.Code switch
    {
        Code.Ldarg_0 => 0, Code.Ldarg_1 => 1, Code.Ldarg_2 => 2, Code.Ldarg_3 => 3,
        _ => x.Operand is Parameter p ? p.Index : throw new Failed("bad argument operand"),
    };

    static Failed Bad(string what, object? v) => new($"{what} on a {Describe(v)}");
    static string Describe(object? v) => v == null ? "null" : v is Obj o ? o.Type.FullName : v.GetType().Name;

    static Ref AsRef(object? v) => v as Ref ?? throw new Failed($"indirect access through a {Describe(v)}");
    static Array Arr(object? v) => v as Array ?? throw new Failed($"array access on a {Describe(v)}");
    static int Check(Array a, int i) => i >= 0 && i < a.Length ? i : throw new Failed($"index {i} outside an array of {a.Length}");
    static long AsLong(object? v) => v switch { int i => i, long l => l, _ => throw Bad("index", v) };
    static bool Truth(object? v) => v switch { null => false, int i => i != 0, long l => l != 0, double d => d != 0, _ => true };

    // ---- statics and sample objects ------------------------------------------------------------------------------------

    // A static constructor often runs unrelated initializers in a row. When one stops the emulation, the fields set before it are kept, and a field left null is filled by
    // its own initializer if it has exactly one (LoadStatic); otherwise reading it reports why the constructor stopped.
    readonly Dictionary<TypeDef, string> _initFailed = new();
    readonly Dictionary<TypeDef, string> _skipped = new(); // the first initializer a static constructor skipped, and why

    void EnsureStaticInit(TypeDef? t, int depth)
    {
        if (t == null || !_initialized.Add(t)) return;
        foreach (var f in t.Fields.Where(f => f.IsStatic)) _statics.TryAdd(f, Zero(f.FieldSig?.Type));
        if (t.FindStaticConstructor() is not { } cctor) return;
        var (steps, limit) = (_steps, _limit);
        (_steps, _limit) = (0, MaxStaticSteps);
        try { Invoke(cctor, [], null, depth + 1); }
        catch (Failed e) { _initFailed[t] = $"static constructor of {t.Name}: {e.Message}"; }
        finally { (_steps, _limit) = (steps, limit); }
    }

    object? LoadStatic(IField f, int depth)
    {
        if (f.ResolveFieldDef() is { } fd && Sample(fd.DeclaringType))
        {
            EnsureStaticInit(fd.DeclaringType, depth);
            var v = _statics.GetValueOrDefault(f, Zero(f.FieldSig?.Type));
            if (v == null && _guessed.Add(fd) && Initializer(fd) is { } init)
            {
                Invoke(init, [], null, depth + 1);
                v = _statics.GetValueOrDefault(f);
            }
            if (v == null && (_initFailed.TryGetValue(fd.DeclaringType, out var why) || _skipped.TryGetValue(fd.DeclaringType, out why)))
                throw new Failed(why.StartsWith("static constructor", StringComparison.Ordinal) ? why : $"static constructor of {fd.DeclaringType.Name}: {why}");
            return v;
        }
        // framework constants: String.Empty, BitConverter.IsLittleEndian
        return f.FullName switch
        {
            "System.String System.String::Empty" => "",
            "System.Boolean System.BitConverter::IsLittleEndian" => BitConverter.IsLittleEndian ? 1 : 0,
            _ => throw new Failed($"static field {f.FullName}"),
        };
    }

    // A static reference field still null when read was filled at startup by a method other than the static
    // constructor (an Init() that Main calls first). When exactly one parameterless static method stores into it, that
    // method is interpreted as the program would have run it.
    readonly HashSet<FieldDef> _guessed = new();

    MethodDef? Initializer(FieldDef fd)
    {
        if (_s.Ws.Find(fd.Module) is not { } lm) return null;
        var writers = _s.Index.To(lm.H(fd)).Where(x => x.Kind == "write").Select(x => x.From).Distinct().ToList();
        return writers is [{ IsStatic: true, IsStaticConstructor: false } w] && w.MethodSig?.Params.Count == 0 ? w : null;
    }

    void StoreStatic(IField f, object? v, int depth)
    {
        if (f.ResolveFieldDef() is not { } fd || !Sample(fd.DeclaringType)) throw new Failed($"store into {f.FullName}");
        EnsureStaticInit(fd.DeclaringType, depth);
        _statics[f] = Store(v, f.FieldSig?.Type);
    }

    bool Sample(TypeDef? t) => t != null && ModuleOf(t.Module) != null;

    // The module of the sample's code: one the workspace holds, or one the code loaded from bytes (Assembly.Load), whose
    // methods are interpreted the same way when the code calls them through reflection.
    LoadedModule? ModuleOf(ModuleDef? m) =>
        m == null ? null : _s.Ws.Find(m) ?? (_loaded.Count == 0 ? null : _loaded.Values.FirstOrDefault(l => l.Module == m));

    // ---- calls ---------------------------------------------------------------------------------------------------------

    // Per call target, computed once: its full name (dnlib builds the string on every read), its definition if it
    // resolves, and for framework members the bound member. Decryptors call the same few methods millions of times.
    readonly Dictionary<IMethod, string> _names = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<IMethod, MethodDef?> _defs = new(ReferenceEqualityComparer.Instance);
    readonly Dictionary<IMethod, Bound> _bound = new(ReferenceEqualityComparer.Instance);
    sealed record Bound(Type Type, Type[] Ps, MethodBase Member, ParameterInfo[] Params);

    string NameOf(IMethod m)
    {
        if (!_names.TryGetValue(m, out var n)) _names[m] = n = m.FullName;
        return n;
    }

    MethodDef? DefOf(IMethod m)
    {
        if (_defs.TryGetValue(m, out var d)) return d;
        try { d = m.ResolveMethodDef(); } catch (Exception) { d = null; }
        return _defs[m] = d;
    }

    object? CallTarget(IMethod target, object?[] a, Code op, IList<TypeSig>? context, int depth, MethodDef caller)
    {
        var generic = (target as MethodSpec)?.GenericInstMethodSig?.GenericArguments.Select(g => Resolve(g, context)).ToList();
        var name = NameOf(target);
        if (name.Contains("System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray("))
        {
            var arr = Arr(a[0]);
            if (a[1] is not byte[] data) throw new Failed("InitializeArray without field data");
            Buffer.BlockCopy(data, 0, arr, 0, Math.Min(data.Length, Buffer.ByteLength(arr)));
            return null;
        }
        if (name.StartsWith("System.Void System.Object::.ctor(", StringComparison.Ordinal)) return null;
        // new SomeDelegate(target, ldftn method), and calling it
        if (op == Code.Newobj && a.Length == 2 && a[1] is FnPtr fp) return new DelegateStub(a[0], fp);
        if (op != Code.Newobj && a.Length > 0 && (a[0] is Ref dr ? dr.Get() : a[0]) is DelegateStub d)
        {
            if (target.Name != "Invoke") throw new Failed($"{target.Name} on a delegate");
            var rest = a[1..];
            if (d.Fn.Def is { } fd)
                return Invoke(fd, fd.IsStatic ? rest : [d.Target, .. rest], generic, depth + 1);
            return Framework(d.Fn.Method, d.Fn.Method.MethodSig?.HasThis == true ? [d.Target, .. rest] : rest, Code.Call,
                             (d.Fn.Method as MethodSpec)?.GenericInstMethodSig?.GenericArguments.ToList(), context, caller);
        }

        var def = DefOf(target);
        // VirtualProtect: the copy is writable already. The old protection reported is what Windows would report for a
        // loaded image's code: execute-read (0x20).
        if (def?.ImplMap?.Name.String is "VirtualProtect")
        {
            if (a.Length == 4 && a[3] is Ref old) old.Set(0x20);
            return 1;
        }
        // anti-debug checks get the answer of a process without a debugger
        switch (def?.ImplMap?.Name.String)
        {
            case "CheckRemoteDebuggerPresent":
                if (a.Length == 2 && a[1] is Ref present) present.Set(0);
                return 1;
            case "IsDebuggerPresent":
                return 0;
        }
        if (def != null && Sample(def.DeclaringType))
        {
            if (op == Code.Newobj)
            {
                EnsureStaticInit(def.DeclaringType, depth);
                var o = def.DeclaringType.IsValueType ? (Obj)Zero(def.DeclaringType.ToTypeSig())! : new Obj(def.DeclaringType);
                Invoke(def, [o, .. a], generic, depth + 1);
                return o;
            }
            if (op == Code.Callvirt && a.Length > 0 && (a[0] is Ref r ? r.Get() : a[0]) is Obj self)
                def = Override(self.Type, def) ?? def;
            if (!def.IsStatic && a[0] is Ref rr) a[0] = rr.Get(); // a struct's this: the instance itself, so its changes stay
            return Invoke(def, a, generic, depth + 1);
        }
        if (target.Name.String is "LateGet" or "LateCall" && name.Contains(" Microsoft.VisualBasic.CompilerServices.NewLateBinding::", StringComparison.Ordinal))
            return LateBound(a, depth);
        return Framework(target, a, op, generic, context, caller);
    }

    // VB late binding: NewLateBinding.LateGet/LateCall(instance, type, name, args, argNames, typeArgs, copyBack[, ignore]),
    // obj.Name(args) on a variable typed Object. The member is looked up by name and argument count on the instance, as
    // the VB runtime does, and called like any other call: a sample object's method is interpreted, a framework member
    // must be declared by an allowed type and is bounded the same way.
    object? LateBound(object?[] a, int depth)
    {
        if (a.Length < 7) throw new Failed("late-bound call with an unexpected signature");
        object? Val(object? v) => v is Ref r ? r.Get() : v;
        var instance = Val(a[0]);
        var name = Val(a[2]) as string ?? throw new Failed("late-bound call without a member name");
        if (Val(a[1]) != null || Val(a[4]) != null || Val(a[5]) != null)
            throw new Failed($"late-bound {name} on a type, or with named or generic arguments");
        var args = Val(a[3]) is Array arr ? arr.Cast<object?>().ToArray() : [];
        // CopyBack: the runtime clears it for parameters that are not ByRef, and none is here
        if (Val(a[6]) is bool[] copyBack) Array.Clear(copyBack);
        else if (Val(a[6]) is int[] copyBackInts) Array.Clear(copyBackInts);
        switch (instance)
        {
            case null: throw new Failed($"late-bound {name} on null");
            case Obj o:
                foreach (var t in Bases(o.Type))
                    foreach (var m in t.Methods)
                        if (!m.IsStatic && (m.Name == name || m.Name == "get_" + name) && m.MethodSig?.Params.Count == args.Length)
                            return Invoke(m, [o, .. args], null, depth + 1);
                throw new Failed($"late-bound {name}: {o.Type.FullName} has no such member");
        }
        if (instance.GetType().DeclaringType == typeof(Emulator)) throw new Failed($"late-bound {name} on a {Describe(instance)}");
        var type = instance.GetType();
        var candidates = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Concat(type.GetInterfaces().SelectMany(i => i.GetMethods()))
            .Where(m => (m.Name == name || m.Name == "get_" + name) && !m.IsGenericMethodDefinition && m.GetParameters().Length == args.Length);
        foreach (var method in candidates)
        {
            var mps = method.GetParameters();
            if (!DeclaredAllowed(method) || Blocked.Contains(method.Name) || method.ReturnType == typeof(Type)
                || mps.Any(p => p.ParameterType.IsByRef || p.ParameterType == typeof(Type) || !Modelled(p.ParameterType)))
                continue;
            var call = new object?[args.Length];
            bool fits = true;
            for (int i = 0; i < args.Length && fits; i++)
            {
                var v = Val(args[i]);
                var pt = mps[i].ParameterType;
                fits = v is not Obj && (v == null ? !pt.IsValueType : pt.IsPrimitive || pt.IsEnum ? v is int or long or double : pt.IsInstanceOfType(v));
                if (fits) call[i] = ToClr(v, pt);
            }
            if (!fits) continue;
            var full = $"{method.DeclaringType}.{method.Name} (late-bound)";
            object? result;
            try
            {
                Bounded(method, mps, call);
                result = method.Invoke(instance, call);
            }
            catch (TargetInvocationException e) when (e.InnerException is Failed inner) { throw inner; }
            catch (TargetInvocationException e) { throw new Failed($"{full} threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}"); }
            catch (Exception e) when (e is ArgumentException or InvalidCastException or OverflowException or FormatException or TargetException
                                           or TargetParameterCountException or NotSupportedException or IndexOutOfRangeException)
            { throw new Failed($"{full}: {e.Message}"); }
            if (result is Type || result is Delegate) throw new Failed($"{full} returned a type or delegate");
            if (result is string { Length: > MaxArray } || result is Array { Length: > MaxArray }) throw new Failed("result too large");
            return Stack(result);
        }
        throw new Failed($"late-bound {type.Name}.{name}: no allowed member takes these {args.Length} arguments");
    }

    // The method a virtual call on a sample object lands in: the most derived one with that name and signature, or one
    // that names it in its overrides (explicit interface implementations).
    static MethodDef? Override(TypeDef type, MethodDef declared)
    {
        var cmp = new SigComparer();
        foreach (var t in Bases(type))
            foreach (var m in t.Methods)
                if (m.IsVirtual && (m.Name == declared.Name && cmp.Equals(m.MethodSig, declared.MethodSig)
                                    || m.Overrides.Any(o => o.MethodDeclaration.FullName == declared.FullName)))
                    return m;
        return null;
    }

    // ---- framework calls (allowlist) -----------------------------------------------------------------------------------

#pragma warning disable SYSLIB0021, SYSLIB0022, SYSLIB0023, SYSLIB0041, SYSLIB0045
    // Types whose members compute on data in memory. The emulated code can only obtain instances of these, so none of
    // their members can reach a file, the network, a process or reflection either (no FileStream or Type ever exists).
    static readonly Dictionary<string, Type> Allowed = new Type[]
    {
        typeof(object), typeof(string), typeof(char), typeof(bool), typeof(byte), typeof(sbyte), typeof(short), typeof(ushort), typeof(int),
        typeof(uint), typeof(long), typeof(ulong), typeof(float), typeof(double), typeof(decimal), typeof(IntPtr), typeof(UIntPtr),
        typeof(StringBuilder), typeof(Encoding), typeof(UTF8Encoding), typeof(ASCIIEncoding), typeof(UnicodeEncoding), typeof(UTF32Encoding),
        typeof(Convert), typeof(Math), typeof(BitConverter), typeof(Array), typeof(Buffer), typeof(Enumerable), typeof(StringComparison),
        typeof(IEnumerable<>), typeof(List<>), typeof(Dictionary<,>), typeof(System.Collections.IEnumerable), typeof(System.Collections.Hashtable),
        typeof(System.Collections.ArrayList), typeof(System.Collections.Generic.IEnumerator<>), typeof(System.Collections.IEnumerator),
        typeof(System.IO.Stream), typeof(System.IO.MemoryStream), typeof(System.IO.BinaryReader), typeof(System.IO.Compression.GZipStream),
        typeof(System.IO.Compression.DeflateStream), typeof(System.IO.Compression.CompressionMode), typeof(System.IO.SeekOrigin),
        typeof(CryptoStream), typeof(CryptoStreamMode), typeof(ICryptoTransform), typeof(HashAlgorithm), typeof(MD5), typeof(MD5CryptoServiceProvider),
        typeof(SHA1), typeof(SHA1Managed), typeof(SHA1CryptoServiceProvider), typeof(SHA256), typeof(SHA256Managed), typeof(SHA256CryptoServiceProvider),
        typeof(SHA384), typeof(SHA512), typeof(SHA512Managed), typeof(KeyedHashAlgorithm), typeof(HMAC), typeof(HMACMD5), typeof(HMACSHA1),
        typeof(HMACSHA256), typeof(SymmetricAlgorithm), typeof(Aes), typeof(AesManaged), typeof(AesCryptoServiceProvider), typeof(Rijndael),
        typeof(RijndaelManaged), typeof(TripleDES), typeof(TripleDESCryptoServiceProvider), typeof(DES), typeof(DESCryptoServiceProvider),
        typeof(RC2), typeof(RC2CryptoServiceProvider), typeof(DeriveBytes), typeof(Rfc2898DeriveBytes), typeof(PasswordDeriveBytes),
        typeof(CipherMode), typeof(PaddingMode), typeof(HashAlgorithmName), typeof(System.Globalization.CultureInfo),
        typeof(System.Runtime.InteropServices.OSPlatform), typeof(System.Runtime.InteropServices.RuntimeInformation),
        typeof(Func<>), typeof(Func<,>), typeof(Func<,,>), typeof(Func<,,,>), typeof(Action<>), typeof(Action<,>), typeof(Predicate<>),
        typeof(Microsoft.VisualBasic.CompilerServices.Conversions), typeof(Microsoft.VisualBasic.CompilerServices.Operators),
        typeof(Microsoft.VisualBasic.Strings), typeof(Microsoft.VisualBasic.CompilerServices.StringType), typeof(IDisposable),
    }.ToDictionary(t => t.FullName!.Split('`')[0] + (t.IsGenericTypeDefinition ? "`" + t.GetGenericArguments().Length : ""), t => t);
#pragma warning restore SYSLIB0021, SYSLIB0022, SYSLIB0023, SYSLIB0041, SYSLIB0045

    // Types allowed only for the members named: System.IO.Path's string helpers, not GetTempFileName (which creates a
    // file) or GetFullPath (which reads the current directory).
    static readonly Dictionary<string, (Type Type, HashSet<string> Members)> Partly = new()
    {
        ["System.IO.Path"] = (typeof(Path), ["Combine", "GetFileName", "GetFileNameWithoutExtension", "GetExtension", "ChangeExtension",
                                            "GetDirectoryName", "HasExtension", "IsPathRooted", "GetInvalidFileNameChars", "GetInvalidPathChars"]),
    };

    // Members of allowed types that hand out something outside the allowlist or touch the environment.
    static readonly string[] Blocked = ["GetType", "CreateInstance", "ChangeType", "CreateFromName", "Create(System.String)", "set_CurrentCulture"];

    object? Framework(IMethod target, object?[] a, Code op, List<TypeSig>? generic, IList<TypeSig>? context, MethodDef caller)
    {
        if (Stubbed(target, a, op, caller, out var stubbed)) return stubbed;
        var full = NameOf(target);
        // a member bound before, with no generic context in its signature: same type, same member
        var cacheable = generic == null && !full.Contains('!');
        var bound = cacheable && _bound.TryGetValue(target, out var hit) ? hit : null;
        var declaring = target.DeclaringType;
        var name = target.Name.String;
        if (Nondeterministic(full)) throw new Failed($"call into {full}: random or time-dependent, the result differs on every run");
        var type = bound?.Type ?? Clr(declaring?.ToTypeSig(), context)
                   ?? (declaring != null && Partly.TryGetValue(declaring.FullName, out var partly) && partly.Members.Contains(name) ? partly.Type : null)
                   ?? throw new Failed($"call into {full} (not on the allowlist)");
        if (bound == null && Blocked.Any(b => name == b || full.Contains("::" + b, StringComparison.Ordinal)))
            throw new Failed($"call into {full} (blocked)");
        var sig = target.MethodSig!;
        var ps = bound?.Ps ?? sig.Params.Select(p => Clr(p, context, generic) ?? throw new Failed($"parameter type {p.FullName} of {full}")).ToArray();
        object? self = null;
        object?[] args;
        if (op == Code.Newobj || !sig.HasThis) args = a;
        else
        {
            self = a[0] is Ref r ? r.Get() : a[0];
            if (self == null) throw new Failed($"{full} on null");
            if (self is Obj) throw new Failed($"{full} on a sample object");
            if (type.IsValueType) self = ToClr(self, type); // char.ToString(): the stack holds the char as an int
            args = a[1..];
        }
        // byref parameters (Array.Resize<T>(ref T[], int)) are passed as their value and written back after
        var refs = new Ref?[args.Length];
        var call = new object?[args.Length];
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is Ref rf && ps[i].IsByRef) { refs[i] = rf; call[i] = ToClr(rf.Get(), ps[i].GetElementType()!); }
            else if (args[i] is DelegateStub ds && typeof(Delegate).IsAssignableFrom(ps[i])) call[i] = MakeDelegate(ds, ps[i]);
            else call[i] = ToClr(args[i] is Ref r2 ? r2.Get() : args[i], ps[i]);
        }
        object? result;
        try
        {
            if (op == Code.Newobj)
            {
                var ctor = bound?.Member as ConstructorInfo
                           ?? type.GetConstructor(BindingFlags.Public | BindingFlags.Instance, ps) ?? throw new Failed($"constructor {full}");
                var cps = bound?.Params ?? ctor.GetParameters();
                if (cacheable && bound == null) _bound[target] = new Bound(type, ps, ctor, cps);
                Bounded(ctor, cps, call);
                result = ctor.Invoke(call);
            }
            else
            {
                MethodInfo method;
                ParameterInfo[] mps;
                if (bound?.Member is MethodInfo bm) (method, mps) = (bm, bound.Params);
                else
                {
                    method = Find(type, name, ps, generic?.Select(g => Clr(g, context) ?? throw new Failed($"type argument {g.FullName}")).ToArray(),
                                  sig.HasThis) ?? throw new Failed($"{full} not found in this runtime");
                    // the member actually called must be declared by an allowed type (an inherited member of a base outside the
                    // allowlist, such as MarshalByRefObject's, is not), or be one of object's few value members
                    if (!DeclaredAllowed(method)) throw new Failed($"call into {method.DeclaringType}.{method.Name} (not on the allowlist)");
                    mps = method.GetParameters();
                    // a delegate argument can only be one MakeDelegate built (nothing else creates delegates), which interprets
                    if (mps.Any(p => p.ParameterType == typeof(Type))) throw new Failed($"{full} takes a type");
                    if (method.ReturnType == typeof(Type)) throw new Failed($"{full} returns a type");
                    if (cacheable) _bound[target] = new Bound(type, ps, method, mps);
                }
                Bounded(method, mps, call);
                result = method.Invoke(method.IsStatic ? null : self, call);
                if (result is Type || result is Delegate) throw new Failed($"{full} returned a type or delegate");
            }
        }
        catch (TargetInvocationException e) when (e.InnerException is Failed inner) { throw inner; } // from a delegate the framework called back
        catch (TargetInvocationException e) { throw new Failed($"{full} threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}"); }
        catch (Exception e) when (e is ArgumentException or InvalidCastException or OverflowException or FormatException or AmbiguousMatchException
                                       or TargetException or TargetParameterCountException or NotSupportedException or IndexOutOfRangeException)
        { throw new Failed($"{full}: {e.Message}"); }
        for (int i = 0; i < refs.Length; i++) refs[i]?.Set(Stack(call[i]));
        if (result is string { Length: > MaxArray } || result is Array { Length: > MaxArray }) throw new Failed("result too large");
        return Stack(result);
    }

    // ---- reflection over the code's own metadata ------------------------------------------------------------------------

    // typeof(T) as the interpreter models it: a sample type, an allowed framework type (a System.Type the allowlist
    // knows), or another framework type known by name only.
    object? TypeOf(TypeSig sig, IList<TypeSig>? context)
    {
        var tdr = sig.ToTypeDefOrRef();
        TypeDef? def = null;
        try { def = sig is TypeDefOrRefSig ? tdr?.ResolveTypeDef() : null; } catch (Exception) { }
        if (def != null && Sample(def)) return new TypeStub(def);
        if (Clr(sig, context) is { } clr) return new ClrTypeStub(clr, def);
        return def != null ? new RefTypeStub(def) : null;
    }

    MethodStub MethodOf(IMethod m) => new(m, Fn(m, null).Def);

    FieldDef? FieldOf(IField f)
    {
        try { return f.ResolveFieldDef() is { } d && Sample(d.DeclaringType) ? d : null; } catch (Exception) { return null; }
    }

    static TypeDef? DefOfType(object? t) => t switch { TypeStub s => s.Type, RefTypeStub r => r.Def, ClrTypeStub c => c.Def, _ => null };
    static string? NameOfType(object? t) => t switch { TypeStub s => s.Type.ReflectionFullName, RefTypeStub r => r.Def.ReflectionFullName, ClrTypeStub c => c.Type.FullName, _ => null };
    static bool IsTypeStub(object? t) => t is TypeStub or RefTypeStub or ClrTypeStub;

    // BindingFlags as GetMethods/GetFields filter by them: Instance 4, Static 8, Public 16, NonPublic 32, DeclaredOnly 2
    static bool Binds(int flags, bool isStatic, bool isPublic) =>
        (flags & (isStatic ? 8 : 4)) != 0 && (flags & (isPublic ? 16 : 32)) != 0;

    static IEnumerable<TypeDef> Hierarchy(TypeDef? t, bool declaredOnly) => t == null ? [] : declaredOnly ? [t] : Bases(t);

    // A type and its bases, each once: hostile metadata can make a type its own base (directly or in a ring), and an
    // unresolvable base ends the walk
    static IEnumerable<TypeDef> Bases(TypeDef? t)
    {
        var seen = new HashSet<TypeDef>();
        for (int n = 0; t != null && n < 256 && seen.Add(t); n++)
        {
            yield return t;
            try { t = t.BaseType?.ResolveTypeDef(); } catch (Exception) { t = null; }
        }
    }

    // Members as Type.GetMethods/GetFields see them: the type's own, then the bases' non-private ones (statics of a base
    // only with FlattenHierarchy, 0x40), a method hidden or overridden by a more derived one with the same name and
    // signature not again
    IEnumerable<MethodDef> ReflectedMethods(TypeDef def, int flags)
    {
        var cmp = new SigComparer();
        var seen = new List<MethodDef>();
        bool first = true;
        foreach (var t in Hierarchy(def, (flags & 2) != 0))
        {
            foreach (var m in t.Methods)
            {
                if (m.IsConstructor || !Binds(flags, m.IsStatic, m.IsPublic)) continue;
                if (!first && (m.IsPrivate || m.IsStatic && (flags & 0x40) == 0)) continue;
                if (seen.Any(d => d.Name == m.Name && cmp.Equals(d.MethodSig, m.MethodSig))) continue;
                seen.Add(m);
                yield return m;
            }
            first = false;
        }
    }

    IEnumerable<FieldDef> ReflectedFields(TypeDef def, int flags)
    {
        bool first = true;
        foreach (var t in Hierarchy(def, (flags & 2) != 0))
        {
            foreach (var f in t.Fields)
                if (Binds(flags, f.IsStatic, f.IsPublic) && (first || !f.IsPrivate && (!f.IsStatic || (flags & 0x40) != 0)))
                    yield return f;
            first = false;
        }
    }

    bool Reflected(IMethod target, string full, object? self, object?[] a, Code op, MethodDef caller, out object? result)
    {
        result = null;
        object? Arg(int i) => i < a.Length ? (a[i] is Ref r ? r.Get() : a[i]) : null;
        var name = target.Name.String;
        // the declaring type, from the cached full name ("ret Declaring::Name(...)"): this runs on every framework call
        int colons = full.IndexOf("::", StringComparison.Ordinal), space = colons < 0 ? -1 : full.LastIndexOf(' ', colons);
        if (colons < 0 || !full.AsSpan(space + 1).StartsWith("System.", StringComparison.Ordinal)) return false;
        var declaring = full[(space + 1)..colons];
        switch (declaring)
        {
            case "System.Reflection.MethodBase" or "System.Reflection.MethodInfo" or "System.Reflection.MemberInfo" or "System.Reflection.FieldInfo"
                or "System.Reflection.ConstructorInfo" or "System.Type" or "System.Reflection.TypeInfo" or "System.RuntimeMethodHandle"
                or "System.RuntimeFieldHandle" or "System.RuntimeTypeHandle" or "System.ModuleHandle" or "System.Reflection.Module"
                or "System.Delegate" or "System.Reflection.Assembly" or "System.Activator":
                break;
            default: return false;
        }
        switch (name)
        {
            case "op_Equality" or "op_Inequality" when a.Length == 2 && Arg(0) is null or MethodStub or FieldStub or ModuleStub or AsmStub
                                                                     && Arg(1) is null or MethodStub or FieldStub or ModuleStub or AsmStub:
                result = (Equals(Arg(0), Arg(1)) ^ name == "op_Inequality") ? 1 : 0; return true;
            case "GetMethodFromHandle" when Arg(0) is MethodStub:
            case "GetFieldFromHandle" when Arg(0) is FieldStub:
                result = Arg(0); return true;
            case "get_MethodHandle" or "get_FieldHandle" or "get_TypeHandle" when self is MethodStub or FieldStub or TypeStub or RefTypeStub or ClrTypeStub:
                result = self; return true;
            case "get_ModuleHandle" when self is ModuleStub:
                result = self; return true;
            case "get_ManifestModule" when self is AsmStub am:
                result = new ModuleStub(am.M); return true;
            case "GetModules" or "GetLoadedModules" when self is AsmStub am2:
                result = new object?[] { new ModuleStub(am2.M) }; return true;
            case "get_Assembly" when self is ModuleStub mas:
                result = new AsmStub(mas.M); return true;
            case "GetType" when self is AsmStub at && Arg(1) is string typeName:
                {
                    var found = at.M.Module.Find(typeName, true);
                    if (found == null && Arg(2) is int and not 0) throw new Failed($"Assembly.GetType(\"{typeName}\"): no such type");
                    result = found == null ? null : new TypeStub(found); return true;
                }
            // tokens of the module: ModuleHandle.ResolveMethodHandle, Module.ResolveMethod, ...
            case "ResolveMethodHandle" or "ResolveMethod" or "ResolveFieldHandle" or "ResolveField" or "ResolveTypeHandle" or "ResolveType" or "ResolveMember"
                when self is ModuleStub rm && Arg(1) is int token:
                {
                    object? resolved;
                    try { resolved = rm.M.Module.ResolveToken(token); } catch (Exception) { resolved = null; }
                    result = resolved switch
                    {
                        IMethod rmeth when resolved is MethodDef or MethodSpec or MemberRef { IsMethodRef: true } => MethodOf(rmeth),
                        IField rf => new FieldStub(rf, FieldOf(rf)),
                        ITypeDefOrRef rt => TypeOf(rt.ToTypeSig(), null),
                        _ => null,
                    } ?? throw new Failed($"Module.{name}(0x{token:X8}): no such member");
                    return true;
                }
            case "GetMethod" or "GetField" or "GetProperty" when IsTypeStub(self) && Arg(1) is string member:
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.{name} on {NameOfType(self)}, whose members are not known");
                    int flags = a.Skip(2).Select(v => v is Ref r ? r.Get() : v).OfType<int>().FirstOrDefault(16 | 8 | 4);
                    var types = a.Skip(2).Select(v => v is Ref r ? r.Get() : v).OfType<Array>().FirstOrDefault()?.Cast<object?>().Select(NameOfType).ToArray();
                    if (name == "GetField")
                    {
                        var fd = ReflectedFields(def, flags).FirstOrDefault(f => f.Name == member);
                        result = fd == null ? null : new FieldStub(fd, FieldOf(fd));
                        return true;
                    }
                    var methodName = name == "GetProperty" ? "get_" + member : member;
                    var candidates = ReflectedMethods(def, flags).Where(m => m.Name == methodName
                        && (types == null || m.MethodSig?.Params.Count == types.Length
                            && m.MethodSig.Params.Select(p => p.ReflectionFullName).SequenceEqual(types))).ToList();
                    if (candidates.Count > 1 && types == null) throw new Failed($"Type.{name}(\"{member}\"): ambiguous match");
                    result = candidates.Count == 0 ? null : MethodOf(candidates[0]);
                    return true;
                }
            case "GetMethods" or "GetFields" when IsTypeStub(self):
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.{name} on {NameOfType(self)}, whose members are not known");
                    int flags = Arg(1) is int f ? f : 16 | 8 | 4;
                    result = name == "GetMethods"
                        ? ReflectedMethods(def, flags).Select(m => (object?)MethodOf(m)).ToArray()
                        : ReflectedFields(def, flags).Select(fd => (object?)new FieldStub(fd, FieldOf(fd))).ToArray();
                    return true;
                }
            case "get_Name" when self is MethodStub or FieldStub or TypeStub or RefTypeStub:
                result = self switch
                {
                    MethodStub ms => ms.Method.Name.String, FieldStub fs => fs.Field.Name.String,
                    TypeStub ts => ts.Type.Name.String, _ => ((RefTypeStub)self).Def.Name.String,
                };
                return true;
            case "get_FullName" when self is TypeStub or RefTypeStub:
                result = NameOfType(self); return true;
            case "get_MetadataToken" when self is MethodStub or FieldStub or TypeStub:
                result = self switch
                {
                    MethodStub ms => (int)ms.Method.MDToken.Raw, FieldStub fs => (int)fs.Field.MDToken.Raw, _ => (int)((TypeStub)self).Type.MDToken.Raw,
                };
                return true;
            case "get_IsStatic" when self is MethodStub or FieldStub:
                result = (self is MethodStub ms2 ? ms2.Method.MethodSig?.HasThis == false : Resolves((FieldStub)self)?.IsStatic == true) ? 1 : 0;
                return true;
            case "get_FieldType" when self is FieldStub fst && fst.Field.FieldSig?.Type is { } ft:
                result = TypeOf(ft, null); return true;
            case "get_ReturnType" when self is MethodStub mrt && mrt.Method.MethodSig?.RetType is { } rt:
                result = TypeOf(rt, null); return true;
            case "get_DeclaringType" when self is MethodStub or FieldStub:
                result = (self is MethodStub md ? md.Method.DeclaringType : ((FieldStub)self).Field.DeclaringType) is { } dt ? TypeOf(dt.ToTypeSig(), null) : null;
                return true;
            // statics through FieldInfo
            case "GetValue" when self is FieldStub gv:
                if (Resolves(gv) is { IsLiteral: true } constant) { result = Stack(constant.Constant?.Value); return true; }
                if (gv.Def is not { IsStatic: true }) throw new Failed($"FieldInfo.GetValue of {gv.Field.FullName}");
                result = LoadStatic(gv.Def, _depth + 1); return true;
            case "SetValue" when self is FieldStub sv && a.Length == 3:
                if (sv.Def is not { IsStatic: true }) throw new Failed($"FieldInfo.SetValue of {sv.Field.FullName}");
                StoreStatic(sv.Def, Arg(2), _depth + 1); return true;
            // calls through MethodBase.Invoke and Type.InvokeMember: like a direct call
            case "Invoke" when self is MethodStub iv && a.Length == 3:
                result = InvokeStub(iv, Arg(1), Arg(2) as Array, caller); return true;
            case "InvokeMember" when IsTypeStub(self) && Arg(1) is string im && a.Length >= 6:
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.InvokeMember on {NameOfType(self)}, whose members are not known");
                    // InvokeMethod (0x100) calls the method, GetProperty (0x1000) the getter; fields, setters and
                    // constructors through InvokeMember are not modelled
                    int imFlags = Arg(2) is int imf ? imf : 0;
                    bool invoke = (imFlags & 0x100) != 0, getter = (imFlags & 0x1000) != 0;
                    if (!invoke && !getter || (imFlags & (0x200 | 0x400 | 0x800 | 0x2000)) != 0)
                        throw new Failed($"Type.InvokeMember(\"{im}\") with binding flags 0x{imFlags:X} (only methods and getters are modelled)");
                    var args = Arg(5) as Array;
                    int count = args?.Length ?? 0;
                    var m = ReflectedMethods(def, imFlags | 4 | 8 | 16 | 32)
                                .FirstOrDefault(x => (invoke && x.Name == im || getter && x.Name == "get_" + im) && x.MethodSig?.Params.Count == count)
                            ?? throw new Failed($"Type.InvokeMember(\"{im}\"): {NameOfType(self)} has no method of {count} parameter(s)");
                    result = InvokeStub(MethodOf(m), Arg(4), args, caller); return true;
                }
            case "CreateDelegate" when declaring == "System.Delegate":
                {
                    // CreateDelegate(type, method[, throw]) and CreateDelegate(type, target, method)
                    var ms = a.Select(v => v is Ref r ? r.Get() : v).OfType<MethodStub>().FirstOrDefault()
                             ?? throw new Failed("Delegate.CreateDelegate of something other than a method");
                    var targetObj = a.Length == 3 && Arg(1) is not MethodStub && Arg(2) is MethodStub ? Arg(1) : null;
                    result = new DelegateStub(targetObj, new FnPtr(ms.Method, ms.Def)); return true;
                }
            case "CreateDelegate" when self is MethodStub cd:
                result = new DelegateStub(a.Length == 3 ? Arg(2) : null, new FnPtr(cd.Method, cd.Def)); return true;
            case "CreateInstance" when declaring == "System.Activator" && a.Length == 1 && Arg(0) is TypeStub ct && ct.Type.FindDefaultConstructor() is { } ctor:
                result = CallTarget(ctor, [], Code.Newobj, null, _depth, caller); return true;
        }
        return false;
    }

    // Reflected calls nest without an interpreted frame between them (Invoke of MethodBase.Invoke itself): each one is
    // a frame and a step of its own, so a cycle ends at the depth limit instead of the native stack.
    int _reflectedDepth;

    object? InvokeStub(MethodStub m, object? instance, Array? args, MethodDef caller)
    {
        if (++_steps > _limit) throw new Failed($"stopped after {_limit:N0} IL instructions");
        var list = args?.Cast<object?>().Select(Stack).ToArray() ?? [];
        var sig = m.Method.MethodSig ?? throw new Failed($"MethodBase.Invoke of {m.Method.Name}, whose signature does not parse");
        if (list.Length != sig.Params.Count)
            throw new Failed($"MethodBase.Invoke of {m.Method.Name} with {list.Length} argument(s) for {sig.Params.Count} parameter(s)");
        if (sig.HasThis && instance == null) throw new Failed($"MethodBase.Invoke of instance method {m.Method.Name} on null");
        if (++_reflectedDepth > MaxDepth) { _reflectedDepth--; throw new Failed("reflected calls nested too deep"); }
        try { return CallTarget(m.Method, sig.HasThis ? [instance, .. list] : list, sig.HasThis ? Code.Callvirt : Code.Call, null, _depth + 1, caller); }
        finally { _reflectedDepth--; }
    }

    // What a decryptor may ask of its environment, answered without touching it: its own assembly's resources come from
    // the file, and machine-specific values come back as placeholders (%TEMP%\, %USERNAME%), so the plaintext says
    // where a path would go instead of naming the analyst's machine.
    bool Stubbed(IMethod target, object?[] a, Code op, MethodDef caller, out object? result)
    {
        result = null;
        var full = NameOf(target);
        var self = a.Length > 0 && target.MethodSig?.HasThis == true && op != Code.Newobj ? (a[0] is Ref r ? r.Get() : a[0]) : null;
        string? Arg(int i) => i < a.Length ? (a[i] is Ref rr ? rr.Get() : a[i]) as string : null;
        var module = ModuleOf(caller.Module) ?? throw new Failed("caller outside the loaded modules");
        if (Reflected(target, full, self, a, op, caller, out result)) return true;
        switch (full)
        {
            case "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()":
            case "System.Reflection.Assembly System.Reflection.Assembly::GetCallingAssembly()":
            case "System.Reflection.Assembly System.Reflection.Assembly::GetEntryAssembly()":
                result = new AsmStub(module); return true;
            case "System.Void System.Resources.ResourceManager::.ctor(System.String,System.Reflection.Assembly)" when a[1] is AsmStub asm:
                result = new RmStub(asm.M, Arg(0) ?? throw new Failed("ResourceManager without a name")); return true;
            case "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" when a[0] is TypeStub or ClrTypeStub or RefTypeStub:
                result = a[0]; return true;
            case "System.Type System.Type::GetElementType()" when self is ClrTypeStub ct:
                result = ct.Type.GetElementType() is { } et ? new ClrTypeStub(et) : null; return true;
            case "System.Boolean System.Type::get_IsArray()" when self is ClrTypeStub ct:
                result = ct.Type.IsArray ? 1 : 0; return true;
            case "System.Boolean System.Type::get_IsValueType()" when self is ClrTypeStub ct:
                result = ct.Type.IsValueType ? 1 : 0; return true;
            case "System.Boolean System.Type::get_IsPrimitive()" when self is ClrTypeStub ct:
                result = ct.Type.IsPrimitive ? 1 : 0; return true;
            case "System.TypeCode System.Type::GetTypeCode(System.Type)" when a[0] is ClrTypeStub ct:
                result = (int)Type.GetTypeCode(ct.Type); return true;
            case "System.Boolean System.Type::op_Equality(System.Type,System.Type)":
            case "System.Boolean System.Type::op_Inequality(System.Type,System.Type)":
                if (a[0] is not (null or TypeStub or ClrTypeStub or RefTypeStub) || a[1] is not (null or TypeStub or ClrTypeStub or RefTypeStub)) return false;
                result = (Equals(a[0], a[1]) ^ target.Name == "op_Inequality") ? 1 : 0; return true;
            case "System.Array System.Array::CreateInstance(System.Type,System.Int32)" when a[0] is ClrTypeStub or TypeStub:
                {
                    var length = Convert.ToInt64(a[1]);
                    if (length < 0 || length > MaxArray) throw new Failed($"Array.CreateInstance of {length:N0} elements");
                    result = Array.CreateInstance(a[0] is ClrTypeStub ce ? ce.Type : ElementClr(((TypeStub)a[0]!).Type), (int)length);
                    return true;
                }
            case "System.Reflection.Module System.Type::get_Module()" when self is TypeStub tm:
                result = new ModuleStub(ModuleOf(tm.Type.Module)!); return true;
            case "System.String System.Reflection.Module::get_FullyQualifiedName()" when self is ModuleStub:
                result = "<Unknown>"; return true; // loaded from bytes: the image is in the file layout
            case "System.String System.Reflection.Module::get_ScopeName()" when self is ModuleStub ms:
                result = ms.M.Module.Name.String; return true;
            case "System.IntPtr System.Runtime.InteropServices.Marshal::GetHINSTANCE(System.Reflection.Module)" when a[0] is ModuleStub hm:
                ImageOf(hm.M);
                result = ImageBase; return true;
            case "System.Reflection.Assembly System.Type::get_Assembly()" when self is TypeStub ts2:
                result = new AsmStub(ModuleOf(ts2.Type.Module)!); return true;
            case "System.Boolean System.Reflection.Assembly::op_Equality(System.Reflection.Assembly,System.Reflection.Assembly)":
            case "System.Boolean System.Reflection.Assembly::op_Inequality(System.Reflection.Assembly,System.Reflection.Assembly)":
                result = (Equals(a[0], a[1]) ^ target.Name == "op_Inequality") ? 1 : 0; return true;
            case "System.String System.Environment::get_SystemDirectory()": result = @"%SystemRoot%\system32"; return true;
            case "System.String System.IO.Path::GetTempFileName()": result = @"%TEMP%\tmp0000.tmp"; return true;
            case "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])" when a[0] is byte[] asmBytes:
                result = LoadAssembly(asmBytes); return true;
            case "System.Object System.Runtime.CompilerServices.RuntimeHelpers::GetObjectValue(System.Object)":
                result = Copy(a[0] is Ref gr ? gr.Get() : a[0]); return true;
            case "System.AppDomain System.AppDomain::get_CurrentDomain()":
                result = new AppDomainStub(); return true;
            case "System.Void System.AppDomain::add_AssemblyResolve(System.ResolveEventHandler)" when self is AppDomainStub:
            case "System.Void System.AppDomain::add_ResourceResolve(System.ResolveEventHandler)" when self is AppDomainStub:
            case "System.Void System.AppDomain::add_TypeResolve(System.ResolveEventHandler)" when self is AppDomainStub:
                return true; // the loaded assemblies are found by name (_loaded); the handler is not needed
            // lock statements: one thread here, so locks are always free
            case "System.Void System.Threading.Monitor::Enter(System.Object)":
            case "System.Void System.Threading.Monitor::Exit(System.Object)":
                return true;
            case "System.Void System.Threading.Monitor::Enter(System.Object,System.Boolean&)":
                if (a.Length == 2 && a[1] is Ref taken) taken.Set(1);
                return true;
            case "System.Void System.Threading.Thread::.ctor(System.Threading.ThreadStart)":
            case "System.Void System.Threading.Thread::.ctor(System.Threading.ParameterizedThreadStart)":
                result = new ThreadStub(a[0]); return true;
            case "System.Void System.Threading.Thread::Start()" when self is ThreadStub:
            case "System.Void System.Threading.Thread::Start(System.Object)" when self is ThreadStub:
            case "System.Void System.Threading.Thread::set_IsBackground(System.Boolean)" when self is ThreadStub:
            case "System.Void System.Threading.Thread::set_Priority(System.Threading.ThreadPriority)" when self is ThreadStub:
            case "System.Void System.Threading.Thread::set_Name(System.String)" when self is ThreadStub:
                return true;
            case "System.Void System.Threading.Thread::Join()" when self is ThreadStub:
            case "System.Boolean System.Threading.Thread::Join(System.Int32)" when self is ThreadStub:
                throw new Failed("Thread.Join: the code waits for a thread's result, and a started thread's code is not run here");
            case "System.Diagnostics.Process System.Diagnostics.Process::GetCurrentProcess()":
                result = new ProcessStub(); return true;
            case "System.IntPtr System.Diagnostics.Process::get_Handle()" when self is ProcessStub:
                result = -1L; return true; // the current-process pseudo handle
            case "System.Int32 System.Diagnostics.Process::get_Id()" when self is ProcessStub:
                result = 4242; return true;
            case "System.Boolean System.Diagnostics.Debugger::get_IsAttached()":
            case "System.Boolean System.Diagnostics.Debugger::IsLogging()":
                result = 0; return true;
            case "System.Void System.Environment::FailFast(System.String)":
            case "System.Void System.Environment::Exit(System.Int32)":
                throw new Failed($"the code would end the process here ({target.Name})");
            case "System.String System.IO.Path::GetTempPath()": result = "%TEMP%\\"; return true;
            case "System.String System.Environment::GetEnvironmentVariable(System.String)": result = $"%{Arg(0)}%"; return true;
            case "System.String System.Environment::get_UserName()": result = "%USERNAME%"; return true;
            case "System.String System.Environment::get_MachineName()": result = "%COMPUTERNAME%"; return true;
            case "System.String System.Environment::get_UserDomainName()": result = "%USERDOMAIN%"; return true;
            case "System.String System.Environment::get_NewLine()": result = "\r\n"; return true;
            case "System.String System.Environment::GetFolderPath(System.Environment/SpecialFolder)":
                result = $"%{Enum.GetName(typeof(Environment.SpecialFolder), (int)AsLong(a[0])) ?? "folder " + a[0]}%"; return true;
        }
        // pointers are numbers here: IntPtr/UIntPtr conversions keep the value
        if (target.DeclaringType?.FullName is "System.IntPtr" or "System.UIntPtr"
            && target.Name.String is "op_Explicit" or "op_Implicit" or "ToPointer" or "ToInt64" or "ToInt32" or "ToUInt64" or "ToUInt32" or ".ctor")
        {
            var v = (a.Length > 0 ? (op == Code.Newobj ? a[0] : a[^1]) : null) is var x && x is Ref xr ? xr.Get() : x;
            if (op == Code.Newobj && a.Length == 1) { result = v; return true; }
            result = target.Name.String is "ToInt32" or "ToUInt32" ? (object)(int)AsLong(v) : AsLong(v);
            return true;
        }
        if (target.FullName == "System.Int32 System.IntPtr::get_Size()") { result = 8; return true; }
        if (self is AsmStub sa)
        {
            var resources = sa.M.Module.Resources;
            switch (target.Name.String)
            {
                case "GetManifestResourceStream" when Arg(1) is { } rn:
                    // the CLR returns null and the code then fails on it; the reason names the resource instead
                    var res = resources.FirstOrDefault(x => x.Name == rn);
                    // linked to another assembly: the one the code loaded under that name
                    if (res is AssemblyLinkedResource linked && _loaded.TryGetValue(linked.Assembly.Name.String, out var holder))
                        res = holder.Module.Resources.FirstOrDefault(x => x.Name == rn);
                    // a name the module does not have gives null, as in the CLR: code that probes for an optional resource goes on
                    result = res switch
                    {
                        EmbeddedResource er => new MemoryStream(er.CreateReader().ToArray(), false),
                        AssemblyLinkedResource al => throw new Failed(
                            $"GetManifestResourceStream(\"{rn}\"): linked to assembly {al.Assembly.Name}, which the code has not loaded"),
                        _ => null,
                    };
                    return true;
                case "GetManifestResourceNames":
                    result = resources.Select(x => x.Name.String).ToArray(); return true;
                case "Equals":
                    result = Equals(sa, a[1] is Ref ar ? ar.Get() : a[1]) ? 1 : 0; return true;
                default: throw new Failed($"Assembly.{target.Name} on the sample's assembly");
            }
        }
        if (self is RmStub rm)
        {
            if (target.Name.String is not ("GetString" or "GetObject" or "GetStream")) throw new Failed($"ResourceManager.{target.Name}");
            var res = rm.M.Module.Resources.FirstOrDefault(x => x.Name == rm.BaseName + ".resources")
                      ?? throw new Failed($"no resource {rm.BaseName}.resources");
            var set = DnSpySql.Tables.ResourceTables.ReadSet(rm.M, res) ?? throw new Failed($"{res.Name} does not parse");
            var e = set.ResourceElements.FirstOrDefault(x => x.Name == Arg(1));
            result = e == null ? null : DnSpySql.Tables.ResourceTables.ElementValue(e) is var v && target.Name == "GetStream" && v is byte[] b ? new MemoryStream(b, false) : Stack(v);
            return true;
        }
        return false;
    }

    // A real delegate for the framework (Enumerable.Select(s, c => ...)) whose body calls back into the interpreter: the
    // framework calls it, the sample's lambda is interpreted, never run.
    Delegate MakeDelegate(DelegateStub d, Type delegateType)
    {
        var invoke = delegateType.GetMethod("Invoke")!;
        var ps = invoke.GetParameters().Select(p => System.Linq.Expressions.Expression.Parameter(p.ParameterType)).ToArray();
        var args = System.Linq.Expressions.Expression.NewArrayInit(typeof(object), ps.Select(p => System.Linq.Expressions.Expression.Convert(p, typeof(object))));
        var call = System.Linq.Expressions.Expression.Call(System.Linq.Expressions.Expression.Constant(this),
            typeof(Emulator).GetMethod(nameof(Callback), BindingFlags.NonPublic | BindingFlags.Instance)!,
            System.Linq.Expressions.Expression.Constant(d), args, System.Linq.Expressions.Expression.Constant(invoke.ReturnType, typeof(Type)));
        System.Linq.Expressions.Expression body = invoke.ReturnType == typeof(void)
            ? System.Linq.Expressions.Expression.Block(typeof(void), call)
            : System.Linq.Expressions.Expression.Convert(call, invoke.ReturnType);
        return System.Linq.Expressions.Expression.Lambda(delegateType, body, ps).Compile();
    }

    object? Callback(DelegateStub d, object?[] args, Type returns)
    {
        var a = args.Select(Stack).ToArray();
        object? r = d.Fn.Def is { } fd
            ? Invoke(fd, fd.IsStatic ? a : [d.Target, .. a], null, _depth + 1)
            : throw new Failed("a delegate to a framework method passed to the framework");
        return returns == typeof(void) ? null : ToClr(r, returns);
    }

    static readonly HashSet<string> ObjectMembers = ["ToString", "Equals", "GetHashCode", "CompareTo"];

    static bool Nondeterministic(string full) =>
        full.Contains(" System.Random::", StringComparison.Ordinal) || full.Contains(" System.Security.Cryptography.RandomNumberGenerator::", StringComparison.Ordinal)
        || full.Contains(" System.Guid::NewGuid(", StringComparison.Ordinal) || full.Contains(" System.DateTime::get_Now(", StringComparison.Ordinal)
        || full.Contains(" System.DateTime::get_UtcNow(", StringComparison.Ordinal) || full.Contains(" System.Environment::get_TickCount", StringComparison.Ordinal)
        || full.Contains(" System.Diagnostics.Stopwatch::", StringComparison.Ordinal);

    // A parameter type the interpreter can hand to the framework: a value it models (primitives, strings, enums, arrays
    // of them) or an instance of an allowed type
    static bool Modelled(Type t) =>
        t.IsPrimitive || t.IsEnum || t == typeof(string) || t == typeof(object) || t == typeof(decimal)
        || t.IsArray && Modelled(t.GetElementType()!) || Allowed.ContainsValue(t.IsGenericType ? t.GetGenericTypeDefinition() : t);

    static bool DeclaredAllowed(MethodInfo method)
    {
        var declared = method.DeclaringType!.IsGenericType ? method.DeclaringType.GetGenericTypeDefinition() : method.DeclaringType;
        return Allowed.ContainsValue(declared)
               || Partly.TryGetValue(declared.FullName!, out var pt) && pt.Members.Contains(method.Name)
               || (declared == typeof(object) || declared == typeof(ValueType) || declared == typeof(Enum)) && ObjectMembers.Contains(method.Name);
    }

    // A framework call is one step to the interpreter and cannot be interrupted, so what it is asked to do is bounded
    // before it runs: key-derivation iterations, and the sizes of what it allocates or produces.
    const long MaxIterations = 1_000_000;
    static readonly HashSet<string> SizeParameters = new(StringComparer.OrdinalIgnoreCase)
        { "count", "length", "capacity", "newSize", "totalWidth", "repeatCount", "cb", "numBytes", "minimumLength", "maxCapacity" };

    static void Bounded(MethodBase m, ParameterInfo[] ps, object?[] args)
    {
        for (int i = 0; i < ps.Length && i < args.Length; i++)
        {
            if (args[i] is not (int or long or uint or ulong or short or ushort)) continue;
            long v = Convert.ToInt64(args[i]);
            var name = ps[i].Name ?? "";
            if (name.Equals("iterations", StringComparison.OrdinalIgnoreCase) || m.Name is "set_IterationCount")
            {
                if (v > MaxIterations) throw new Failed($"{m.DeclaringType?.Name}.{m.Name} with {v:N0} iterations (more than {MaxIterations:N0})");
            }
            else if (SizeParameters.Contains(name) || m.Name is "SetLength" or "set_Capacity" or "set_Length")
            {
                if (v > MaxArray) throw new Failed($"{m.DeclaringType?.Name}.{m.Name} with {name} {v:N0} (more than {MaxArray:N0})");
            }
        }
    }

    static MethodInfo? Find(Type type, string name, Type[] ps, Type[]? generic, bool instance)
    {
        var flags = BindingFlags.Public | (instance ? BindingFlags.Instance : BindingFlags.Static);
        foreach (var m in type.GetMethods(flags | BindingFlags.FlattenHierarchy).Where(m => m.Name == name && m.GetParameters().Length == ps.Length))
            {
                var mm = m;
                if (m.IsGenericMethodDefinition)
                {
                    if (generic == null || generic.Length != m.GetGenericArguments().Length) continue;
                    try { mm = m.MakeGenericMethod(generic); } catch (ArgumentException) { continue; }
                }
                if (mm.GetParameters().Select(p => p.ParameterType).SequenceEqual(ps, ParamEq.Instance)) return mm;
            }
        return null;
    }

    // dnlib names a generic method's parameter by its generic parameter (!!0); here it is already the closed type.
    sealed class ParamEq : IEqualityComparer<Type>
    {
        public static readonly ParamEq Instance = new();
        public bool Equals(Type? a, Type? b) => a == b || a != null && b != null && (a.IsByRef ? a.GetElementType() : a) == (b.IsByRef ? b.GetElementType() : b);
        public int GetHashCode(Type t) => 0;
    }

    // ---- types ---------------------------------------------------------------------------------------------------------

    static TypeSig Resolve(TypeSig sig, IList<TypeSig>? context) =>
        sig is GenericMVar mv && context != null && mv.Number < context.Count ? context[(int)mv.Number] : sig;

    // The runtime type of an allowed framework type, or null (sample types and anything off the allowlist).
    static Type? Clr(TypeSig? sig, IList<TypeSig>? context, IList<TypeSig>? methodGeneric = null)
    {
        if (sig == null) return null;
        if (sig is GenericMVar mv)
        {
            var list = methodGeneric ?? context;
            return list != null && mv.Number < list.Count ? Clr(list[(int)mv.Number], context) : null;
        }
        sig = sig.RemovePinnedAndModifiers();
        return sig.ElementType switch
        {
            ElementType.Boolean => typeof(bool), ElementType.Char => typeof(char), ElementType.I1 => typeof(sbyte), ElementType.U1 => typeof(byte),
            ElementType.I2 => typeof(short), ElementType.U2 => typeof(ushort), ElementType.I4 => typeof(int), ElementType.U4 => typeof(uint),
            ElementType.I8 => typeof(long), ElementType.U8 => typeof(ulong), ElementType.R4 => typeof(float), ElementType.R8 => typeof(double),
            ElementType.String => typeof(string), ElementType.Object => typeof(object), ElementType.I => typeof(IntPtr), ElementType.U => typeof(UIntPtr),
            ElementType.SZArray => Clr(sig.Next, context, methodGeneric)?.MakeArrayType(),
            ElementType.ByRef => Clr(sig.Next, context, methodGeneric)?.MakeByRefType(),
            ElementType.GenericInst when sig is GenericInstSig gi && Allowed.TryGetValue(gi.GenericType.TypeDefOrRef.FullName, out var def)
                => gi.GenericArguments.Select(g => Clr(g, context, methodGeneric)).ToArray() is var targs && targs.All(t => t != null)
                    ? def.MakeGenericType(targs!) : null,
            ElementType.Class or ElementType.ValueType => Allowed.GetValueOrDefault(sig.ToTypeDefOrRef().FullName),
            _ => null,
        };
    }

    // Arrays of sample types are object[]: their elements are sample objects or nulls; a sample enum is its integer.
    Type ElementClr(ITypeDefOrRef t) => Clr(t.ToTypeSig(), null)
        ?? (t.ResolveTypeDef() is { IsEnum: true } en && Clr(en.GetEnumUnderlyingType(), null) is { } u ? u : null)
        ?? (t.IsValueType ? throw new Failed($"array of struct {t.FullName}") : typeof(object));

    // A sample struct type (not an enum), or null.
    TypeDef? SampleStruct(TypeSig? sig)
    {
        if (sig?.RemovePinnedAndModifiers() is not ValueTypeSig vt) return null;
        var td = vt.TypeDefOrRef.ResolveTypeDef();
        return td != null && !td.IsEnum && Sample(td) ? td : null;
    }

    // The zero of a type: a fresh struct (its struct fields too), an enum's 0, or Default.
    object? Zero(TypeSig? sig)
    {
        if (SampleStruct(sig) is { } st)
        {
            var o = new Obj(st);
            foreach (var f in st.Fields.Where(f => !f.IsStatic)) o.Fields[f] = Zero(f.FieldSig?.Type);
            return o;
        }
        if (sig?.RemovePinnedAndModifiers() is ValueTypeSig e && e.TypeDefOrRef.ResolveTypeDef() is { IsEnum: true } en)
            return Default(en.GetEnumUnderlyingType());
        return Default(sig);
    }

    object? Field(Obj o, IField f) => o.Fields.TryGetValue(f, out var v) ? v : o.Fields[f] = Zero(f.FieldSig?.Type);

    // A struct is copied when stored or loaded by value; everything else is shared.
    static object? Copy(object? v)
    {
        if (v is not Obj { Type.IsValueType: true } o) return v;
        var c = new Obj(o.Type);
        foreach (var (f, fv) in o.Fields) c.Fields[f] = Copy(fv);
        return c;
    }

    static object? Default(TypeSig? t) => t?.RemovePinnedAndModifiers().ElementType switch
    {
        ElementType.Boolean or ElementType.Char or ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 => 0,
        ElementType.I8 or ElementType.U8 or ElementType.I or ElementType.U => 0L,
        ElementType.R4 or ElementType.R8 => 0.0,
        _ => null,
    };

    // A value as the evaluation stack holds it: int32, int64, F (double), or a reference.
    static object? Stack(object? v) => v switch
    {
        bool b => b ? 1 : 0, char c => (int)c, sbyte s => (int)s, byte b => (int)b, short s => (int)s, ushort u => (int)u,
        uint u => unchecked((int)u), ulong u => unchecked((long)u), float f => (double)f, IntPtr p => (long)p, UIntPtr p => unchecked((long)(ulong)p),
        Enum e => Convert.ToInt32(e),
        _ => v,
    };

    // A stack value stored into a typed slot, as the CLR truncates it (stloc to a byte local keeps the low byte); a
    // struct is copied.
    static object? Store(object? v, TypeSig? t) => v is Obj { Type.IsValueType: true } ? Copy(v) : t?.RemovePinnedAndModifiers().ElementType switch
    {
        ElementType.I1 => v is int or long ? (int)unchecked((sbyte)AsLong(v)) : v,
        ElementType.U1 or ElementType.Boolean => v is int or long ? (int)unchecked((byte)AsLong(v)) : v,
        ElementType.I2 => v is int or long ? (int)unchecked((short)AsLong(v)) : v,
        ElementType.U2 or ElementType.Char => v is int or long ? (int)unchecked((ushort)AsLong(v)) : v,
        ElementType.I4 or ElementType.U4 => v is long l ? unchecked((int)l) : v,
        ElementType.I8 or ElementType.U8 => v is int i ? (long)i : v,
        ElementType.R4 => v is double d ? (double)(float)d : v,
        _ => v,
    };

    // A stack value as a framework parameter of type t expects it.
    static object? ToClr(object? v, Type t)
    {
        if (v == null) return null;
        if (t.IsEnum) return Enum.ToObject(t, Convert.ToInt64(v));
        if (t == typeof(object) || !t.IsPrimitive && t != typeof(decimal)) return v is Obj ? throw new Failed("a sample object passed to the framework") : v;
        unchecked
        {
            long l = v switch { int i => i, long x => x, double d => (long)d, _ => 0 };
            return Type.GetTypeCode(t) switch
            {
                TypeCode.Boolean => l != 0, TypeCode.Char => (char)l, TypeCode.SByte => (sbyte)l, TypeCode.Byte => (byte)l, TypeCode.Int16 => (short)l,
                TypeCode.UInt16 => (ushort)l, TypeCode.Int32 => (int)l, TypeCode.UInt32 => (uint)l, TypeCode.Int64 => l, TypeCode.UInt64 => (ulong)l,
                TypeCode.Single => v is double d1 ? (float)d1 : (float)l, TypeCode.Double => v is double d2 ? d2 : (double)l,
                _ when t == typeof(IntPtr) => (IntPtr)l, _ when t == typeof(UIntPtr) => (UIntPtr)(ulong)l,
                _ => v,
            };
        }
    }

    object? Unbox(object? v, TypeSig t, IList<TypeSig>? context)
    {
        t = Resolve(t, context);
        if (v == null) return t.IsValueType ? throw new Failed("unbox of null") : null;
        return t.IsValueType ? Store(v is double or int or long ? v : Stack(v), t) : v;
    }

    static FieldDef? Resolves(FieldStub f)
    {
        try { return f.Def ?? f.Field.ResolveFieldDef(); } catch (Exception) { return null; }
    }

    static TypeDef? Resolves(ITypeDefOrRef t)
    {
        try { return t.ResolveTypeDef(); } catch (Exception) { return null; }
    }

    bool Fits(object v, TypeSig t, IList<TypeSig>? context)
    {
        t = Resolve(t, context);
        if (v is Obj o)
            foreach (var x in Bases(o.Type))
                if (x.FullName == t.FullName || x.Interfaces.Any(i => i.Interface.FullName == t.FullName)) return true;
        if (t.ElementType == ElementType.Object) return true;
        if (v is DelegateStub)
            return t.ToTypeDefOrRef() is { } dt && (dt.FullName is "System.Delegate" or "System.MulticastDelegate"
                                                   || (Resolves(dt)?.BaseType?.FullName is "System.MulticastDelegate" or "System.Delegate"));
        if (v is MethodStub) return t.FullName is "System.Reflection.MethodInfo" or "System.Reflection.MethodBase" or "System.Reflection.MemberInfo";
        if (v is FieldStub) return t.FullName is "System.Reflection.FieldInfo" or "System.Reflection.MemberInfo";
        if (v is TypeStub or ClrTypeStub or RefTypeStub) return t.FullName is "System.Type" or "System.Reflection.TypeInfo" or "System.Reflection.MemberInfo";
        return Clr(t, context) is { } clr && clr.IsInstanceOfType(v is int i && clr != typeof(int) ? ToClr(i, clr) : v);
    }

    // ---- arithmetic ----------------------------------------------------------------------------------------------------

    static object Arith(Code op, object? a, object? b)
    {
        try
        {
            if (a is double || b is double)
            {
                double fx = Num(a), fy = Num(b);
                return op switch
                {
                    Code.Add or Code.Add_Ovf or Code.Add_Ovf_Un => fx + fy, Code.Sub or Code.Sub_Ovf or Code.Sub_Ovf_Un => fx - fy,
                    Code.Mul or Code.Mul_Ovf or Code.Mul_Ovf_Un => fx * fy, Code.Div or Code.Div_Un => fx / fy, Code.Rem or Code.Rem_Un => fx % fy,
                    _ => throw new Failed($"{op} on floating point"),
                };
            }
            if (a is int x32 && b is int y32)
            {
                if (op is Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un && y32 == 0) throw new Failed("division by zero");
                return Box(op switch
                {
                    Code.Add => unchecked(x32 + y32), Code.Add_Ovf => checked(x32 + y32), Code.Add_Ovf_Un => (int)checked((uint)x32 + (uint)y32),
                    Code.Sub => unchecked(x32 - y32), Code.Sub_Ovf => checked(x32 - y32), Code.Sub_Ovf_Un => (int)checked((uint)x32 - (uint)y32),
                    Code.Mul => unchecked(x32 * y32), Code.Mul_Ovf => checked(x32 * y32), Code.Mul_Ovf_Un => (int)checked((uint)x32 * (uint)y32),
                    Code.Div => x32 == int.MinValue && y32 == -1 ? throw new Failed("overflow") : x32 / y32,
                    Code.Div_Un => (int)((uint)x32 / (uint)y32),
                    Code.Rem => y32 == -1 ? 0 : x32 % y32,
                    Code.Rem_Un => (int)((uint)x32 % (uint)y32),
                    Code.And => x32 & y32, Code.Or => x32 | y32, Code.Xor => x32 ^ y32,
                    Code.Shl => x32 << y32, Code.Shr => x32 >> y32, Code.Shr_Un => (int)((uint)x32 >> y32),
                    _ => throw new Failed($"{op}"),
                });
            }
            if (op is Code.Shl or Code.Shr or Code.Shr_Un)
            {
                long v = AsLong(a);
                int n = (int)AsLong(b);
                return a is int i32
                    ? (object)(op switch { Code.Shl => i32 << n, Code.Shr => i32 >> n, _ => (int)((uint)i32 >> n) })
                    : (object)(op switch { Code.Shl => v << n, Code.Shr => v >> n, _ => (long)((ulong)v >> n) });
            }
            long x = AsLong(a), y = AsLong(b);
            if (op is Code.Div or Code.Div_Un or Code.Rem or Code.Rem_Un && y == 0) throw new Failed("division by zero");
            return op switch
            {
                Code.Add => unchecked(x + y), Code.Add_Ovf => checked(x + y), Code.Add_Ovf_Un => (long)checked((ulong)x + (ulong)y),
                Code.Sub => unchecked(x - y), Code.Sub_Ovf => checked(x - y), Code.Sub_Ovf_Un => (long)checked((ulong)x - (ulong)y),
                Code.Mul => unchecked(x * y), Code.Mul_Ovf => checked(x * y), Code.Mul_Ovf_Un => (long)checked((ulong)x * (ulong)y),
                Code.Div => x == long.MinValue && y == -1 ? throw new Failed("overflow") : x / y,
                Code.Div_Un => (long)((ulong)x / (ulong)y),
                Code.Rem => y == -1 ? 0 : x % y,
                Code.Rem_Un => (long)((ulong)x % (ulong)y),
                Code.And => x & y, Code.Or => x | y, Code.Xor => x ^ y,
                _ => throw new Failed($"{op}"),
            };
        }
        catch (OverflowException) { throw new Failed($"{op} overflows"); }
    }

    static double Num(object? v) => v switch { int i => i, long l => l, double d => d, _ => throw Bad("arithmetic", v) };

    static object Conv(Code op, object? v)
    {
        if (v is null or Ref or Obj or string or Array) throw Bad("conversion", v);
        bool ovf = op.ToString().Contains("Ovf");
        bool un = op is Code.Conv_R_Un || op.ToString().EndsWith("_Un");
        try
        {
            long l = v switch
            {
                int i => un ? (uint)i : i,
                long x => x,
                double d => ovf ? checked((long)d) : unchecked((long)d),
                _ => throw Bad("conversion", v),
            };
            if (op is Code.Conv_R4) return (double)(float)Num(v);
            if (op is Code.Conv_R8) return Num(v);
            if (op is Code.Conv_R_Un) return v is int i2 ? (double)(uint)i2 : v is long l2 ? (double)(ulong)l2 : Num(v);
            var name = op.ToString().Replace("Conv_Ovf_", "").Replace("Conv_", "").Replace("_Un", "");
            // (object) on every arm: mixed int and long arms would make the whole switch long, and conv.i4 must give an int32
            if (ovf)
                return name switch
                {
                    "I1" => (object)(int)checked((sbyte)l), "U1" => (object)(int)checked((byte)l), "I2" => (object)(int)checked((short)l),
                    "U2" => (object)(int)checked((ushort)l), "I4" => (object)checked((int)l), "U4" => (object)(int)checked((uint)l),
                    "U8" or "U" => (object)(un || l >= 0 ? l : throw new OverflowException()),
                    _ => (object)l,
                };
            unchecked
            {
                return name switch
                {
                    "I1" => (object)(int)(sbyte)l, "U1" => (object)(int)(byte)l, "I2" => (object)(int)(short)l, "U2" => (object)(int)(ushort)l,
                    "I4" => (object)(int)l, "U4" => (object)(int)(uint)l,
                    "U8" or "U" => (object)(v is int i3 ? (long)(uint)i3 : l),
                    _ => (object)l,
                };
            }
        }
        catch (OverflowException) { throw new Failed($"{op} overflows"); }
    }

    static bool Eq(object? a, object? b) => (a, b) switch
    {
        (int x, int y) => x == y, (long or int, long or int) => AsLong(a) == AsLong(b), (double, _) or (_, double) => Num(a) == Num(b),
        (string x, string y) => ReferenceEquals(x, y) || x == y,
        _ => ReferenceEquals(a, b),
    };

    static bool Compare(Code op, object? a, object? b)
    {
        bool un = op is Code.Cgt_Un or Code.Clt_Un, gt = op is Code.Cgt or Code.Cgt_Un;
        // references compare only against null: "x != null" compiles to ldloc x; ldnull; cgt.un
        if (a is not (int or long or double) || b is not (int or long or double))
            return op == Code.Cgt_Un ? a != null && b == null : op == Code.Clt_Un && a == null && b != null;
        if (a is double || b is double)
        {
            double x = Num(a), y = Num(b);
            bool nan = double.IsNaN(x) || double.IsNaN(y);
            return gt ? x > y || un && nan : x < y || un && nan;
        }
        if (un)
        {
            ulong x = a is int i ? (uint)i : (ulong)(long)a, y = b is int j ? (uint)j : (ulong)(long)b;
            return gt ? x > y : x < y;
        }
        long p = AsLong(a), q = AsLong(b);
        return gt ? p > q : p < q;
    }

    static bool Branch(Code op, object? a, object? b) => op switch
    {
        Code.Beq or Code.Beq_S => Eq(a, b),
        Code.Bne_Un or Code.Bne_Un_S => !Eq(a, b),
        Code.Bge or Code.Bge_S => !Compare(Code.Clt, a, b),
        Code.Bge_Un or Code.Bge_Un_S => !Compare(Code.Clt_Un, a, b),
        Code.Bgt or Code.Bgt_S => Compare(Code.Cgt, a, b),
        Code.Bgt_Un or Code.Bgt_Un_S => Compare(Code.Cgt_Un, a, b),
        Code.Ble or Code.Ble_S => !Compare(Code.Cgt, a, b),
        Code.Ble_Un or Code.Ble_Un_S => !Compare(Code.Cgt_Un, a, b),
        Code.Blt or Code.Blt_S => Compare(Code.Clt, a, b),
        _ => Compare(Code.Clt_Un, a, b),
    };
}
