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
public sealed partial class Emulator
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

    // One per session (and purpose), holding the sample's static state (a decryptor's tables, initialized once like the
    // CLR would), and started afresh after any edit to the model.
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Session, Dictionary<string, StrongBox>> _sessions = new();
    sealed class StrongBox { public long Revision = -1; public Emulator? Value; }

    public static Emulator For(Session s) => For(s, "calls", 200_000_000);

    // field_inits asks what static constructors leave in fields: a smaller budget per constructor, since it may ask of
    // every settings type of a module, and in an interpreter of its own, whose static state no decryptor call shares
    static Emulator For(Session s, string purpose, long maxStaticSteps)
    {
        var boxes = _sessions.GetValue(s, _ => new());
        lock (boxes)
        {
            if (!boxes.TryGetValue(purpose, out var box)) boxes[purpose] = box = new StrongBox();
            if (box.Value == null || box.Revision != s.Ws.Revision)
            {
                box.Value = new Emulator(s, () => s.Db.Cancellation) { MaxStaticSteps = maxStaticSteps };
                box.Revision = s.Ws.Revision;
            }
            return box.Value;
        }
    }

    /// <summary>
    /// Every way into the interpreter (Call, Cached, Decode, StaticValue, Untamper) asks this first: with the session's
    /// emulation setting off, nothing is interpreted and each says why.
    /// </summary>
    static void EnsureEnabled(Session s)
    {
        if (!s.Settings["emulation"].AsBool) throw new Failed("emulation is off: SELECT set_setting('emulation', 1) to interpret code");
    }

    /// <summary>Lets go of the session's interpreters and the state they hold (static fields, an image copy, results): close() frees them.</summary>
    public static void Reset(Session s)
    {
        if (!_sessions.TryGetValue(s, out var boxes)) return;
        lock (boxes) boxes.Clear();
    }

    /// <summary>What a decoder did to a settings type's static fields: each field it changed (SQL values before and after), and why it stopped, if it did.</summary>
    public sealed record DecoderRun(IReadOnlyList<(FieldDef Field, object? Before, object? After)> Changed, string? Error);

    /// <summary>
    /// Interprets a decoder: a parameterless static method that rewrites a settings type's static fields at startup
    /// (Host = Decrypt(Host), with a key derived from another field). The type's static constructor runs first, as in the
    /// CLR. A fresh interpreter each time, so the decoded state does not leak into other results.
    /// </summary>
    public static DecoderRun Decode(Session s, MethodDef decoder, TypeDef settings)
    {
        try { EnsureEnabled(s); } catch (Failed off) { return new DecoderRun([], off.Message); }
        // a small budget: a settings constructor and its decoder are short, and every decoder of a module starts afresh
        var e = new Emulator(s, () => s.Db.Cancellation) { MaxStaticSteps = 10_000_000 };
        lock (e._gate) return e.DecodeLocked(decoder, settings);
    }

    DecoderRun DecodeLocked(MethodDef decoder, TypeDef settings)
    {
        (_steps, _limit, _at, _scratchUsed) = (0, MaxStaticSteps, default, 0);
        var fields = settings.Fields.Where(f => f.IsStatic && !f.IsLiteral).ToList();
        var before = new Dictionary<FieldDef, object?>();
        string? error = null;
        // a byte[] field decrypted in place is the same array: what it held before is a copy
        object? Value(FieldDef f) => ToSql(_statics.GetValueOrDefault(f)) is byte[] b ? b.Clone() : ToSql(_statics.GetValueOrDefault(f));
        try
        {
            EnsureStaticInit(settings, 0);
            foreach (var f in fields) before[f] = Value(f);
            (_steps, _limit) = (0, MaxStaticSteps);
            Invoke(decoder, [], null, 0);
        }
        catch (Failed e) { error = Locate(e).Message; }
        catch (Exception e) when (e is not (OperationCanceledException or OutOfMemoryException))
        { error = Locate(new Failed($"emulator error {e.GetType().Name}: {e.Message}")).Message; }
        var changed = new List<(FieldDef, object?, object?)>();
        foreach (var f in fields)
            if (before.TryGetValue(f, out var b) && Value(f) is var a && !SameSql(a, b)) changed.Add((f, b, a));
        // values decoded on top of a static constructor that stopped half way are said to be so
        if (_initFailed.TryGetValue(settings, out var why)) error = error == null ? why : $"{error}; {why}";
        return new DecoderRun(changed, error);
    }

    static bool SameSql(object? a, object? b) => a is byte[] x && b is byte[] y ? x.AsSpan().SequenceEqual(y) : Equals(a, b);

    /// <summary>The value the static constructor of the field's type leaves in it (interpreted), or why there is none.</summary>
    public static (object? Value, string? Error) StaticValue(Session s, FieldDef f)
    {
        try { EnsureEnabled(s); } catch (Failed off) { return (null, off.Message); }
        var e = For(s, "statics", 2_000_000);
        lock (e._gate)
        {
            (e._steps, e._limit, e._at, e._scratchUsed) = (0, e.MaxStaticSteps, default, 0);
            try
            {
                e.EnsureStaticInit(f.DeclaringType, 0);
                var v = ToSql(e._statics.GetValueOrDefault(f));
                return v != null ? (v, null) : (null, e._initFailed.GetValueOrDefault(f.DeclaringType) ?? e._skipped.GetValueOrDefault(f.DeclaringType));
            }
            catch (Exception x) when (x is not (OperationCanceledException or OutOfMemoryException))
            { return (null, $"emulator error {x.GetType().Name}: {x.Message}"); } // field_inits goes on to the next field
        }
    }

    readonly Dictionary<string, (object? Value, string? Error)> _memo = new(StringComparer.Ordinal);

    /// <summary>
    /// Interprets a routine that rewrites the module's own image through pointers (a self-decrypting startup routine:
    /// method bodies decrypted in place) and returns the image it leaves. Only that routine runs: its type's static
    /// constructor, which usually calls it, is not run, so nothing is rewritten twice.
    /// </summary>
    public byte[] Untamper(MethodDef initializer)
    {
        EnsureEnabled(_s);
        lock (_gate)
        {
            _initialized.Add(initializer.DeclaringType);
            if (initializer.Module?.GlobalType is { } global) _initialized.Add(global); // it usually calls the routine: not twice
            (_steps, _limit) = (0, MaxStaticSteps);
            _untampering = true;
            _at = default;
            _scratchUsed = 0;
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
    /// decryptor_calls, inline_strings and the field values they fold ask for the same plaintexts. Returns the SQL value
    /// or the reason.
    /// </summary>
    public (object? Value, string? Error) Cached(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs = null)
    {
        try { EnsureEnabled(_s); } catch (Failed off) { return (null, off.Message); } // not remembered: the setting can change

        var key = $"{method.Module?.Mvid}:{method.MDToken.Raw:X8}:{string.Join(",", genericArgs?.Select(g => g.FullName) ?? [])}:" +
                  string.Join("\u0001", args.Select(a => a switch { null => "null", byte[] b => "b" + Convert.ToHexString(b), _ => a.GetType().Name + a }));
        lock (_gate)
        {
            if (_memo.TryGetValue(key, out var hit)) return hit;
            if (_exhausted.TryGetValue(method, out var spent) && spent.Calls >= MaxExhausted)
                return (null, $"not interpreted: the last {spent.Calls} calls of this method each used the whole step budget ({spent.Reason})");
            try
            {
                hit = (ToSql(Call(method, args, genericArgs)), null);
                _exhausted.Remove(method);
            }
            catch (Failed e)
            {
                hit = (null, e.Message);
                if (e.Message.StartsWith(StepBudget, StringComparison.Ordinal))
                    _exhausted[method] = (_exhausted.GetValueOrDefault(method).Calls + 1, e.Message);
            }
            return _memo[key] = hit;
        }
    }

    // Calls in a row, per method, that ran out of steps, and why the last one stopped. Code can make every call of a
    // method spin until the budget (an anti-emulation loop, or state the interpreter got wrong); after a few such calls
    // the rest are not tried, or a method called from ten thousand sites costs hours.
    readonly Dictionary<MethodDef, (int Calls, string Reason)> _exhausted = new();
    const int MaxExhausted = 3;
    const string StepBudget = "stopped after ";

    /// <summary>Runs a method on the given arguments and returns its result; throws Failed with the reason it could not.</summary>
    // The emulator is shared by a session's statements (an MCP or HTTP server can run two): one call at a time.
    readonly object _gate = new();

    public object? Call(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs = null)
    {
        EnsureEnabled(_s);
        lock (_gate) return CallLocked(method, args, genericArgs);
    }

    object? CallLocked(MethodDef method, IReadOnlyList<object?> args, IList<TypeSig>? genericArgs)
    {
        _steps = 0;
        _limit = MaxSteps;
        _at = default;
        _scratchUsed = 0;
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
        Array a => System.Text.Json.JsonSerializer.Serialize(a.Cast<object?>().Select(ToSql), JsonFloats),
        _ => v.ToString(),
    };

    // a double[] the code builds may hold NaN or an infinity, which plain JSON cannot write
    static readonly System.Text.Json.JsonSerializerOptions JsonFloats =
        new() { NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals };
}
