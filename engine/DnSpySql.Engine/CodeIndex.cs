// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

public sealed class XRef
{
    public required LoadedModule M;
    public required MethodDef From;
    public int Index;
    public uint Offset;
    public required string OpCode;
    /// <summary>call | callvirt | newobj | ldftn | ldvirtftn | jmp | async | read | write | addr | type | token | string</summary>
    public required string Kind;
    public object? Operand;
    public IMemberDef? Def;
    public long? DefHandle;
    public LoadedModule? DefModule;
    public string ToName = "";
    public string? StringValue;
    public long FromHandle => M.H(From);
    public bool IsCall => Kind is "call" or "callvirt" or "newobj" or "ldftn" or "ldvirtftn" or "jmp" or "async";
}

/// <summary>Whole-workspace reference index built from IL (the analyzer/xref backbone). Rebuilt lazily after edits.</summary>
public sealed class CodeIndex
{
    readonly Session _s;
    long _builtAt = -1;
    List<XRef> _all = new();
    Dictionary<long, List<XRef>> _byFrom = new(), _byTo = new();
    Dictionary<string, List<XRef>> _byName = new(StringComparer.Ordinal);

    public CodeIndex(Session s) { _s = s; }

    public void Invalidate() => _builtAt = -1;
    public void InvalidateIfChanged() { if (_builtAt != _s.Ws.Revision) _builtAt = -1; }

    void Ensure()
    {
        if (_builtAt == _s.Ws.Revision) return;
        var all = new List<XRef>();
        var cache = new Dictionary<object, (IMemberDef?, long?, LoadedModule?)>(ReferenceEqualityComparer.Instance);
        foreach (var lm in _s.Ws.Modules)
            foreach (var t in lm.Module.GetTypes())
                foreach (var m in t.Methods)
                    if (m.HasBody && !Garbage(lm, m))
                    {
                        Scan(lm, m, all, cache);
                        if (StateMachine(lm, m) is { } started) all.Add(started);
                    }
        _all = all;
        _byFrom = all.GroupBy(x => x.FromHandle).ToDictionary(g => g.Key, g => g.ToList());
        _byTo = all.Where(x => x.DefHandle != null).GroupBy(x => x.DefHandle!.Value).ToDictionary(g => g.Key, g => g.ToList());
        _byName = all.GroupBy(x => x.ToName).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
        _builtAt = _s.Ws.Revision;
    }

    // An async method or iterator only starts its state machine (the compiler moved the body into <X>d__N::MoveNext):
    // the edge from the method to MoveNext, from [AsyncStateMachine(typeof(...))], so callers and call graphs walk from
    // the code in MoveNext up to the method that started it. At the instruction that starts it (Start(ref sm), newobj).
    static readonly string[] StateMachineAttributes =
    [
        "System.Runtime.CompilerServices.AsyncStateMachineAttribute", "System.Runtime.CompilerServices.IteratorStateMachineAttribute",
        "System.Runtime.CompilerServices.AsyncIteratorStateMachineAttribute",
    ];

    static XRef? StateMachine(LoadedModule lm, MethodDef m)
    {
        if (!m.HasCustomAttributes) return null;
        try
        {
            var attr = m.CustomAttributes.FirstOrDefault(a => StateMachineAttributes.Contains(a.TypeFullName));
            if (attr?.ConstructorArguments is not [{ Value: TypeSig sig }] || sig.ToTypeDefOrRef()?.ResolveTypeDef() is not { } sm
                || sm.Methods.FirstOrDefault(x => x.Name == "MoveNext" && !x.IsStatic) is not { } moveNext)
                return null;
            var ins = m.Body.Instructions;
            int at = 0;
            for (int i = 0; i < ins.Count; i++)
                if (ins[i].Operand is IMethod im && (im.DeclaringType?.ResolveTypeDef() == sm
                                                     || im is MethodSpec ms && ms.GenericInstMethodSig?.GenericArguments.Any(g => g.ToTypeDefOrRef()?.ResolveTypeDef() == sm) == true))
                { at = i; if (im.Name == "Start" || ins[i].OpCode.Code == Code.Newobj) break; }
            return new XRef
            {
                M = lm, From = m, Index = at, Offset = ins.Count > 0 ? ins[at].Offset : 0, OpCode = "async", Kind = "async",
                Operand = moveNext, Def = moveNext, DefHandle = lm.H(moveNext), DefModule = lm, ToName = moveNext.FullName,
            };
        }
        catch (Exception) { return null; } // a broken attribute blob is not an edge
    }

    /// <summary>
    /// A body that is not IL: encrypted in the file (anti-tamper; method_bodies says so) while the module is as loaded,
    /// or an instruction whose operand refers to nothing. Its bytes decode to random calls and fields, which would
    /// flood xrefs, call graphs and capabilities, so the index leaves it out.
    /// </summary>
    public static bool Garbage(LoadedModule lm, MethodDef m)
    {
        if (!lm.Dirty && DnSpySql.Tables.HexTables.Undecodable(lm).ContainsKey(m.MDToken.Raw)) return true;
        var body = m.Body;
        if (body == null) return false;
        int vars = body.Variables.Count, pars = m.Parameters.Count;
        foreach (var x in body.Instructions)
            if (InvalidOperand(x, vars, pars)) return true;
        return false;
    }

    /// <summary>An instruction whose operand does not resolve: a local or argument the method does not have, a token past its table.</summary>
    public static bool InvalidOperand(Instruction x, int vars, int pars) => x.OpCode.Code switch
    {
        Code.Ldloc_0 or Code.Stloc_0 => vars < 1, Code.Ldloc_1 or Code.Stloc_1 => vars < 2,
        Code.Ldloc_2 or Code.Stloc_2 => vars < 3, Code.Ldloc_3 or Code.Stloc_3 => vars < 4,
        Code.Ldarg_0 => pars < 1, Code.Ldarg_1 => pars < 2, Code.Ldarg_2 => pars < 3, Code.Ldarg_3 => pars < 4,
        _ => x.OpCode.OperandType is not (OperandType.InlineNone or OperandType.InlinePhi) && x.Operand == null,
    };

    /// <summary>Scans one method on demand without building the global index.</summary>
    public List<XRef> ScanMethod(LoadedModule lm, MethodDef m)
    {
        var list = new List<XRef>();
        if (m.HasBody) Scan(lm, m, list, new Dictionary<object, (IMemberDef?, long?, LoadedModule?)>(ReferenceEqualityComparer.Instance));
        return list;
    }

    void Scan(LoadedModule lm, MethodDef m, List<XRef> list, Dictionary<object, (IMemberDef?, long?, LoadedModule?)> cache)
    {
        var ins = m.Body.Instructions;
        for (int i = 0; i < ins.Count; i++)
        {
            var x = ins[i];
            var kind = KindOf(x);
            if (kind == null) continue;
            var r = new XRef { M = lm, From = m, Index = i, Offset = x.Offset, OpCode = x.OpCode.Name, Kind = kind, Operand = x.Operand };
            if (x.Operand is string str) { r.StringValue = str; r.ToName = str; }
            else if (x.Operand != null)
            {
                if (!cache.TryGetValue(x.Operand, out var res))
                {
                    var def = ResolveDef(x.Operand);
                    var dlm = def == null ? null : _s.Ws.Find(def.Module);
                    res = dlm == null ? (null, null, null) : (def, dlm.H(def!), dlm);
                    cache[x.Operand] = res;
                }
                (r.Def, r.DefHandle, r.DefModule) = res;
                r.ToName = (x.Operand as IFullName)?.FullName ?? x.Operand.ToString() ?? "";
            }
            list.Add(r);
        }
    }

    static string? KindOf(Instruction x)
    {
        switch (x.OpCode.Code)
        {
            case Code.Call: return "call";
            case Code.Callvirt: return "callvirt";
            case Code.Newobj: return "newobj";
            case Code.Ldftn: return "ldftn";
            case Code.Ldvirtftn: return "ldvirtftn";
            case Code.Jmp: return "jmp";
            case Code.Ldfld: case Code.Ldsfld: return "read";
            case Code.Stfld: case Code.Stsfld: return "write";
            case Code.Ldflda: case Code.Ldsflda: return "addr";
            case Code.Ldtoken: return "token";
            case Code.Ldstr: return "string";
        }
        return x.OpCode.OperandType == OperandType.InlineType ? "type" : null;
    }

    public static IMemberDef? ResolveDef(object operand)
    {
        try
        {
            return operand switch
            {
                MethodDef md => md,
                FieldDef fd => fd,
                TypeDef td => td,
                MemberRef mr => mr.IsMethodRef ? mr.ResolveMethod() : mr.ResolveField(),
                MethodSpec ms => ms.Method?.ResolveMethodDef(),
                TypeSpec ts => ts.ScopeType?.ResolveTypeDef(),
                ITypeDefOrRef tr => tr.ResolveTypeDef(),
                _ => null,
            };
        }
        catch { return null; }
    }

    public IReadOnlyList<XRef> All { get { Ensure(); return _all; } }
    public IReadOnlyList<XRef> From(long methodHandle) { Ensure(); return _byFrom.TryGetValue(methodHandle, out var l) ? l : Array.Empty<XRef>(); }
    public IReadOnlyList<XRef> To(long defHandle) { Ensure(); return _byTo.TryGetValue(defHandle, out var l) ? l : Array.Empty<XRef>(); }
    public IReadOnlyList<XRef> ToName(string name) { Ensure(); return _byName.TryGetValue(name, out var l) ? l : Array.Empty<XRef>(); }
}
