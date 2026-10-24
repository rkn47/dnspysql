// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

// The interpreter itself: frames and opcodes, static state and sample objects, calls into the sample, the CLR types
// values are kept as, and arithmetic.
public sealed partial class Emulator
{
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
                        // new T[n] in generic code is an array of the T this frame was called with (a T[] that
                        // Buffer.BlockCopy fills must be an int[], not an object[])
                        var es = Resolve(et.ToTypeSig(), genericArgs);
                        if (SampleStruct(es) is { } st)
                        {
                            if (n > 1 << 20) throw new Failed($"array of {n} sample structs");
                            var arr = new object?[n];
                            for (int k = 0; k < n; k++) arr[k] = Zero(st.ToTypeSig());
                            stack.Push(arr);
                        }
                        else stack.Push(Array.CreateInstance(ElementClr(es), (int)n));
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
                // stackalloc, and the block copies and fills anti-tamper routines run over it and the image
                case Code.Localloc: stack.Push(Localloc(AsLong(stack.Pop()))); break;
                case Code.Cpblk:
                    {
                        long n = AsLong(stack.Pop()); var src = stack.Pop(); var dst = stack.Pop();
                        if (n < 0 || n > int.MaxValue) throw new Failed($"cpblk of {n} bytes");
                        if (n > 0) { var (sb, so) = At(src, (int)n); sb.AsSpan(so, (int)n).CopyTo(Bytes(dst, (int)n)); }
                        break;
                    }
                case Code.Initblk:
                    {
                        long n = AsLong(stack.Pop()); var value = (byte)AsLong(stack.Pop()); var dst = stack.Pop();
                        if (n < 0 || n > int.MaxValue) throw new Failed($"initblk of {n} bytes");
                        if (n > 0) Bytes(dst, (int)n).Fill(value);
                        break;
                    }
                case Code.Sizeof:
                    // sizeof(T) in generic code (Get<T>: copy sizeof(T) bytes) is the size of the T this frame was called with
                    stack.Push(SizeOf(Resolve(((ITypeDefOrRef)x.Operand).ToTypeSig().RemovePinnedAndModifiers(), genericArgs), 0));
                    break;

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
            "System.IntPtr System.IntPtr::Zero" or "System.UIntPtr System.UIntPtr::Zero" => 0L,
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
        // a P/Invoke the environment model answers (VirtualProtect, anti-debug checks: Emulator.Environment.cs)
        if (def?.ImplMap is { } map && AnsweredNative(map.Name.String, caller, a, out var native)) return native;
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

    // ---- types ---------------------------------------------------------------------------------------------------------

    // sizeof: a primitive's size, an enum's underlying type's, and a pointer's for a reference (class, string, array,
    // object); the layout of a struct is not modelled
    static int SizeOf(TypeSig t, int depth) => t.RemovePinnedAndModifiers().ElementType switch
    {
        ElementType.Boolean or ElementType.I1 or ElementType.U1 => 1,
        ElementType.Char or ElementType.I2 or ElementType.U2 => 2,
        ElementType.I4 or ElementType.U4 or ElementType.R4 => 4,
        ElementType.I8 or ElementType.U8 or ElementType.R8 or ElementType.I or ElementType.U or ElementType.Ptr or ElementType.FnPtr => 8,
        ElementType.Class or ElementType.String or ElementType.Object or ElementType.SZArray or ElementType.Array => 8,
        ElementType.ValueType when depth < 4 && t is ValueTypeSig vt && Resolves(vt.TypeDefOrRef) is { IsEnum: true } en
                                   && en.GetEnumUnderlyingType() is { } u => SizeOf(u, depth + 1),
        _ => throw new Failed($"sizeof({t.FullName}): the size of a struct is not modelled"),
    };

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
    Type ElementClr(ITypeDefOrRef t) => ElementClr(t.ToTypeSig());

    Type ElementClr(TypeSig s) => Clr(s, null)
        ?? (s.ToTypeDefOrRef() is { } t && Resolves(t) is { IsEnum: true } en && Clr(en.GetEnumUnderlyingType(), null) is { } u ? u : null)
        ?? (s.IsValueType ? throw new Failed($"array of struct {s.FullName}") : typeof(object));

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

    // (also IlArgs' constant folding of call arguments)
    internal static object Arith(Code op, object? a, object? b)
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

    internal static object Conv(Code op, object? v)
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

    // bge and ble branch unless the opposite comparison holds. On floats that comparison takes the other unordered flag
    // (ECMA-335 III.3.6: bge is clt.un; brfalse, bge.un is clt; brfalse), so a NaN fails bge/ble and passes bge.un/ble.un;
    // on integers .un only means unsigned.
    static bool Branch(Code op, object? a, object? b)
    {
        bool real = a is double || b is double;
        return op switch
        {
            Code.Beq or Code.Beq_S => Eq(a, b),
            Code.Bne_Un or Code.Bne_Un_S => !Eq(a, b),
            Code.Bge or Code.Bge_S => !Compare(real ? Code.Clt_Un : Code.Clt, a, b),
            Code.Bge_Un or Code.Bge_Un_S => !Compare(real ? Code.Clt : Code.Clt_Un, a, b),
            Code.Bgt or Code.Bgt_S => Compare(Code.Cgt, a, b),
            Code.Bgt_Un or Code.Bgt_Un_S => Compare(Code.Cgt_Un, a, b),
            Code.Ble or Code.Ble_S => !Compare(real ? Code.Cgt_Un : Code.Cgt, a, b),
            Code.Ble_Un or Code.Ble_Un_S => !Compare(real ? Code.Cgt : Code.Cgt_Un, a, b),
            Code.Blt or Code.Blt_S => Compare(Code.Clt, a, b),
            _ => Compare(Code.Clt_Un, a, b),
        };
    }
}
