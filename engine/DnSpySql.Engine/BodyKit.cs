// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.Json;
using DnSpySql.Tables;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

/// <summary>Method body construction helpers (dnSpy's DefaultCilBodyBuilder and IL transforms).</summary>
public static class BodyKit
{
    /// <summary>
    /// Builds a stub body: base ctor call for instance ctors, defaults for out parameters, then `return value` (or the
    /// default of the return type).
    /// </summary>
    public static CilBody Stub(MethodDef m, object? returnValue, bool useValue = false)
    {
        var body = new CilBody { InitLocals = true };
        var il = body.Instructions;
        if (m.IsInstanceConstructor && m.DeclaringType is { IsValueType: false } dt && dt.BaseType != null)
        {
            var baseCtor = new MemberRefUser(m.Module, ".ctor", MethodSig.CreateInstance(m.Module.CorLibTypes.Void), dt.BaseType);
            var resolved = dt.BaseType.ResolveTypeDef()?.FindDefaultConstructor();
            il.Add(OpCodes.Ldarg_0.ToInstruction());
            il.Add(OpCodes.Call.ToInstruction(resolved != null && ReferenceEquals(resolved.Module, m.Module) ? resolved : (IMethod)baseCtor));
        }
        foreach (var p in m.Parameters.Where(p => p.IsNormalMethodParameter && p.Type is ByRefSig && p.ParamDef?.IsOut == true))
        {
            il.Add(Instruction.Create(OpCodes.Ldarg, p));
            il.Add(OpCodes.Initobj.ToInstruction(((ByRefSig)p.Type).Next.ToTypeDefOrRef()));
        }
        var ret = m.ReturnType;
        if (ret.ElementType != ElementType.Void) EmitValue(body, m.Module, ret, useValue ? returnValue : null, useValue);
        il.Add(OpCodes.Ret.ToInstruction());
        body.UpdateInstructionOffsets();
        return body;
    }

    /// <summary>Pushes a constant (or the default) of the given type.</summary>
    public static void EmitValue(CilBody body, ModuleDef module, TypeSig type, object? value, bool hasValue)
    {
        var il = body.Instructions;
        var t = type.RemovePinnedAndModifiers();
        var et = t.ElementType;
        if (t is ValueTypeSig vt && vt.TypeDefOrRef.ResolveTypeDef() is { IsEnum: true } en)
            et = en.GetEnumUnderlyingType()?.ElementType ?? ElementType.I4;
        long L() => hasValue ? Values.ToLong(value) ?? throw new SqlException($"return value {TableKit.Fmt(value)} is not an integer") : 0;
        switch (et)
        {
            case ElementType.Boolean: case ElementType.Char: case ElementType.I1: case ElementType.U1:
            case ElementType.I2: case ElementType.U2: case ElementType.I4: case ElementType.U4:
                il.Add(Instruction.CreateLdcI4((int)L())); break;
            case ElementType.I8: case ElementType.U8:
                il.Add(OpCodes.Ldc_I8.ToInstruction(L())); break;
            case ElementType.R4: il.Add(OpCodes.Ldc_R4.ToInstruction(hasValue ? Convert.ToSingle(value) : 0f)); break;
            case ElementType.R8: il.Add(OpCodes.Ldc_R8.ToInstruction(hasValue ? Convert.ToDouble(value) : 0d)); break;
            case ElementType.I: case ElementType.U: case ElementType.Ptr: case ElementType.FnPtr:
                il.Add(Instruction.CreateLdcI4((int)L()));
                il.Add(OpCodes.Conv_I.ToInstruction());
                break;
            case ElementType.String:
                il.Add(hasValue && value != null ? OpCodes.Ldstr.ToInstruction(Values.ToText(value)!) : OpCodes.Ldnull.ToInstruction());
                break;
            case ElementType.Class: case ElementType.Object: case ElementType.SZArray: case ElementType.Array:
                if (hasValue && value != null) throw new SqlException($"cannot return a constant of type {type.FullName}; only NULL");
                il.Add(OpCodes.Ldnull.ToInstruction());
                break;
            case ElementType.GenericInst when !((GenericInstSig)t).GenericType.IsValueTypeSig:
                il.Add(OpCodes.Ldnull.ToInstruction());
                break;
            default:
                {
                    if (hasValue && value != null) throw new SqlException($"cannot return a constant of type {type.FullName}");
                    var local = new Local(t);
                    body.Variables.Add(local);
                    il.Add(OpCodes.Ldloca.ToInstruction(local));
                    il.Add(OpCodes.Initobj.ToInstruction(t.ToTypeDefOrRef()));
                    il.Add(OpCodes.Ldloc.ToInstruction(local));
                    break;
                }
        }
    }

    public static OpCode ParseOpCode(string name)
    {
        var n = name.Trim().ToLowerInvariant().Replace('_', '.');
        foreach (var op in AllOpCodes.Value) if (op.Name == n) return op;
        throw new SqlException($"unknown opcode '{name}'");
    }

    static readonly Lazy<OpCode[]> AllOpCodes = new(() =>
        typeof(OpCodes).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToArray());

    /// <summary>
    /// Parses an operand from SQL for the given opcode. Integers/floats/strings are literals; branch targets and switch
    /// targets are instruction indexes (switch: comma separated); locals/args are indexes; metadata operands are
    /// handles/tokens (any module; imported into the method's module).
    /// </summary>
    public static object? ParseOperand(Workspace ws, MethodDef method, OpCode op, object? v)
    {
        var body = method.Body;
        var mod = method.Module;
        var importer = new Importer(mod, ImporterOptions.TryToUseDefs);
        long Num() => Values.ToLong(v) ?? throw new SqlException($"{op.Name} needs an integer operand");
        switch (op.OperandType)
        {
            case OperandType.InlineNone: case OperandType.InlinePhi: return null;
            case OperandType.ShortInlineI: return op.Code == Code.Ldc_I4_S ? (object)(sbyte)Num() : (byte)Num();
            case OperandType.InlineI: return (int)Num();
            case OperandType.InlineI8: return Num();
            case OperandType.ShortInlineR: return Convert.ToSingle(v);
            case OperandType.InlineR: return Convert.ToDouble(v);
            case OperandType.InlineString: return Values.ToText(v) ?? "";
            case OperandType.InlineBrTarget: case OperandType.ShortInlineBrTarget:
                return Target(body, (int)Num());
            case OperandType.InlineSwitch:
                return (Values.ToText(v) ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(x => Target(body, (int)Values.ParseLong(x)!.Value)).ToArray();
            case OperandType.InlineVar: case OperandType.ShortInlineVar:
                if (op.Code is Code.Ldarg or Code.Ldarg_S or Code.Ldarga or Code.Ldarga_S or Code.Starg or Code.Starg_S)
                {
                    var i = (int)Num();
                    if (i < 0 || i >= method.Parameters.Count) throw new SqlException($"argument index {i} out of range");
                    return method.Parameters[i];
                }
                else
                {
                    var i = (int)Num();
                    if (i < 0 || i >= body.Variables.Count) throw new SqlException($"local index {i} out of range (add locals first)");
                    return body.Variables[i];
                }
            case OperandType.InlineSig:
                {
                    var (_, it) = ws.Resolve(Num());
                    return it is StandAloneSig ss ? ss.MethodSig : throw new SqlException("calli needs a StandAloneSig token");
                }
            default:
                {
                    var h = ws.HandleArg(v) ?? throw new SqlException($"{op.Name} needs a metadata handle/token operand");
                    var (lm, it) = ws.Resolve(h);
                    bool same = ReferenceEquals(lm.Module, mod);
                    return op.OperandType switch
                    {
                        OperandType.InlineMethod => it is IMethod im ? (same ? im : importer.Import(im)) : throw new SqlException($"{op.Name} needs a method"),
                        OperandType.InlineField => it is IField f ? (same ? f : importer.Import(f)) : it is MemberRef { IsFieldRef: true } mr ? (same ? mr : importer.Import(mr)) : throw new SqlException($"{op.Name} needs a field"),
                        OperandType.InlineType => it is ITypeDefOrRef t ? (same ? t : importer.Import(t)) : throw new SqlException($"{op.Name} needs a type"),
                        OperandType.InlineTok => it switch
                        {
                            ITypeDefOrRef t => same ? t : importer.Import(t),
                            IMethod im => same ? im : importer.Import(im),
                            IField f => same ? f : importer.Import(f),
                            _ => throw new SqlException("ldtoken needs a type, method or field"),
                        },
                        _ => throw new SqlException($"unsupported operand type {op.OperandType}"),
                    };
                }
        }
    }

    static Instruction Target(CilBody body, int index)
    {
        if (index < 0 || index >= body.Instructions.Count) throw new SqlException($"branch target index {index} out of range (0..{body.Instructions.Count - 1})");
        return body.Instructions[index];
    }

    /// <summary>Renders an operand as text (ildasm-like).</summary>
    public static string OperandText(Instruction ins, CilBody? body) => ins.Operand switch
    {
        null => "",
        Instruction t => $"IL_{t.Offset:X4}",
        Instruction[] ts => "(" + string.Join(", ", ts.Select(t => $"IL_{t.Offset:X4}")) + ")",
        string s => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") + "\"",
        Local l => string.IsNullOrEmpty(l.Name) ? $"V_{l.Index}" : l.Name,
        Parameter p => p.IsHiddenThisParameter ? "this" : p.Name is { Length: > 0 } n ? n : $"A_{p.Index}",
        IFullName fn => fn.FullName,
        MethodSig ms => ms.ToString(),
        float f => f.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        double d => d.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
        var o => Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };
}

/// <summary>Builds custom attributes from a type name and JSON arguments.</summary>
public static class AttributeKit
{
    public static CustomAttribute Create(Workspace ws, ModuleDef module, string typeName, string? argsJson)
    {
        var tref = TypeSyntax.ParseTypeRef(ws, module, typeName);
        var td = tref.ResolveTypeDef() ?? throw new SqlException($"cannot resolve attribute type '{typeName}'");
        var args = new List<JsonElement>();
        var named = new List<(string name, JsonElement value)>();
        if (!string.IsNullOrWhiteSpace(argsJson))
        {
            using var doc = JsonDocument.Parse(argsJson);
            var root = doc.RootElement.Clone();
            if (root.ValueKind == JsonValueKind.Array) args.AddRange(root.EnumerateArray());
            else if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("args", out var a)) args.AddRange(a.EnumerateArray());
                if (root.TryGetProperty("named", out var n)) named.AddRange(n.EnumerateObject().Select(p => (p.Name, p.Value)));
            }
            else throw new SqlException("args_json must be a JSON array or {\"args\":[...],\"named\":{...}}");
        }
        var importer = new Importer(module, ImporterOptions.TryToUseDefs);
        foreach (var ctor in td.FindConstructors().Where(c => !c.IsStatic && c.MethodSig.Params.Count == args.Count))
        {
            var ps = ctor.MethodSig.Params;
            var converted = new List<CAArgument>();
            bool ok = true;
            for (int i = 0; i < ps.Count && ok; i++)
            {
                var sig = importer.Import(ps[i]);
                if (TryConvert(ws, module, sig, args[i], out var val)) converted.Add(new CAArgument(sig, val));
                else ok = false;
            }
            if (!ok) continue;
            ICustomAttributeType ctorRef = ReferenceEquals(ctor.Module, module) ? ctor : (ICustomAttributeType)importer.Import(ctor);
            var ca = new CustomAttribute(ctorRef, converted);
            foreach (var (name, value) in named)
            {
                var prop = FindProperty(td, name);
                var field = prop == null ? FindField(td, name) : null;
                var sig = importer.Import(prop?.PropertySig.RetType ?? field?.FieldType ?? throw new SqlException($"{td.FullName} has no property/field '{name}'"));
                if (!TryConvert(ws, module, sig, value, out var val)) throw new SqlException($"cannot convert named argument '{name}' to {sig.FullName}");
                ca.NamedArguments.Add(new CANamedArgument(prop == null, sig, name, new CAArgument(sig, val)));
            }
            return ca;
        }
        throw new SqlException($"no constructor of {td.FullName} accepts {args.Count} argument(s) of the given types");
    }

    static PropertyDef? FindProperty(TypeDef? t, string name)
    {
        for (; t != null; t = t.BaseType?.ResolveTypeDef())
            if (t.Properties.FirstOrDefault(p => p.Name == name) is { } p) return p;
        return null;
    }

    static FieldDef? FindField(TypeDef? t, string name)
    {
        for (; t != null; t = t.BaseType?.ResolveTypeDef())
            if (t.Fields.FirstOrDefault(p => p.Name == name) is { } f) return f;
        return null;
    }

    static bool TryConvert(Workspace ws, ModuleDef module, TypeSig sig, JsonElement e, out object? value)
    {
        value = null;
        var et = sig.ElementType;
        if (sig is ValueTypeSig vt && vt.TypeDefOrRef.ResolveTypeDef() is { IsEnum: true } en)
            et = en.GetEnumUnderlyingType()?.ElementType ?? ElementType.I4;
        try
        {
            switch (et)
            {
                case ElementType.Boolean: if (e.ValueKind is JsonValueKind.True or JsonValueKind.False) { value = e.GetBoolean(); return true; } return false;
                case ElementType.String: if (e.ValueKind == JsonValueKind.Null) { value = null; return true; } if (e.ValueKind == JsonValueKind.String) { value = new UTF8String(e.GetString()); return true; } return false;
                case ElementType.Char: if (e.ValueKind == JsonValueKind.String && e.GetString()!.Length == 1) { value = e.GetString()![0]; return true; } return false;
                case ElementType.I1: value = (sbyte)e.GetInt64(); return true;
                case ElementType.U1: value = (byte)e.GetInt64(); return true;
                case ElementType.I2: value = (short)e.GetInt64(); return true;
                case ElementType.U2: value = (ushort)e.GetInt64(); return true;
                case ElementType.I4: value = (int)e.GetInt64(); return true;
                case ElementType.U4: value = (uint)e.GetInt64(); return true;
                case ElementType.I8: value = e.GetInt64(); return true;
                case ElementType.U8: value = e.GetUInt64(); return true;
                case ElementType.R4: value = e.GetSingle(); return true;
                case ElementType.R8: value = e.GetDouble(); return true;
                case ElementType.Class when sig.FullName == "System.Type":
                    if (e.ValueKind != JsonValueKind.String) return false;
                    value = TypeSyntax.Parse(ws, module, e.GetString()!);
                    return true;
                case ElementType.SZArray:
                    {
                        if (e.ValueKind != JsonValueKind.Array) return false;
                        var next = ((SZArraySig)sig).Next;
                        var list = new List<CAArgument>();
                        foreach (var x in e.EnumerateArray())
                        {
                            if (!TryConvert(ws, module, next, x, out var xv)) return false;
                            list.Add(new CAArgument(next, xv));
                        }
                        value = list;
                        return true;
                    }
                case ElementType.Object:
                    {
                        TypeSig boxed = e.ValueKind switch
                        {
                            JsonValueKind.String => module.CorLibTypes.String,
                            JsonValueKind.True or JsonValueKind.False => module.CorLibTypes.Boolean,
                            JsonValueKind.Number when e.TryGetInt32(out _) => module.CorLibTypes.Int32,
                            JsonValueKind.Number => module.CorLibTypes.Double,
                            _ => module.CorLibTypes.Object,
                        };
                        if (boxed == module.CorLibTypes.Object) { value = null; return e.ValueKind == JsonValueKind.Null; }
                        TryConvert(ws, module, boxed, e, out var inner);
                        value = new CAArgument(boxed, inner);
                        return true;
                    }
                default: return false;
            }
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or OverflowException) { return false; }
    }
}
