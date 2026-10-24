// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Globalization;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

// IL-level body editing: replace, insert and remove single instructions in a
// method body. Built on dnlib. Operands are given as text and parsed against the
// opcode's operand type (see ParseOperand). Branch/switch targets are instruction
// indices into the same body; tokens are resolved in the method's module and
// imported so cross-module references stay valid after save().
static class IlEdit
{
    static readonly Dictionary<string, OpCode> OpCodesByName = BuildOpCodeMap();

    static Dictionary<string, OpCode> BuildOpCodeMap()
    {
        var map = new Dictionary<string, OpCode>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            if (f.GetValue(null) is OpCode oc && oc.Name is { } n)
                map[n] = oc;
        return map;
    }

    static MethodDef Method(LoadedModule m, uint token)
    {
        if (m.Module.ResolveToken(token) is not MethodDef md)
            throw new ArgumentException($"0x{token:X8} is not a method in module {m.Id}");
        if (!md.HasBody)
            throw new ArgumentException($"{md.FullName} has no IL body");
        return md;
    }

    static OpCode OpCode(object? name)
    {
        var s = name?.ToString() ?? throw new ArgumentException("opcode is NULL");
        return OpCodesByName.TryGetValue(s.Trim(), out var oc)
            ? oc : throw new ArgumentException($"unknown opcode '{s}'");
    }

    static int Index(IList<Instruction> list, object? idx, bool allowEnd)
    {
        int i = Convert.ToInt32(idx ?? throw new ArgumentException("index is NULL"));
        int max = allowEnd ? list.Count : list.Count - 1;
        if (i < 0 || i > max)
            throw new ArgumentException($"index {i} out of range (0..{max})");
        return i;
    }

    public static object Set(LoadedModule m, uint token, object? idxArg, object? opName, object? operand)
    {
        var md = Method(m, token);
        var list = md.Body.Instructions;
        int i = Index(list, idxArg, allowEnd: false);
        var insn = list[i];
        insn.OpCode = OpCode(opName);
        insn.Operand = ParseOperand(m, md, list, insn.OpCode, operand);
        Finish(m, md);
        return 1;
    }

    public static object Insert(LoadedModule m, uint token, object? idxArg, object? opName, object? operand)
    {
        var md = Method(m, token);
        var list = md.Body.Instructions;
        int i = Index(list, idxArg, allowEnd: true);
        var oc = OpCode(opName);
        var insn = new Instruction(oc) { Operand = ParseOperand(m, md, list, oc, operand) };
        list.Insert(i, insn);
        Finish(m, md);
        return 1;
    }

    public static object Remove(LoadedModule m, uint token, object? idxArg)
    {
        var md = Method(m, token);
        var list = md.Body.Instructions;
        int i = Index(list, idxArg, allowEnd: false);
        var gone = list[i];
        // Retarget branches/switches that pointed at the removed instruction to the
        // one that follows it (or the previous, if it was the last).
        var fallback = i + 1 < list.Count ? list[i + 1] : i > 0 ? list[i - 1] : null;
        list.RemoveAt(i);
        if (fallback != null) Retarget(md.Body, gone, fallback);
        Finish(m, md);
        return 1;
    }

    // Point every branch, switch case and exception-handler boundary that refers to
    // `from` at `to` instead.
    static void Retarget(CilBody body, Instruction from, Instruction to)
    {
        foreach (var ins in body.Instructions)
        {
            if (ReferenceEquals(ins.Operand, from)) ins.Operand = to;
            else if (ins.Operand is IList<Instruction> sw)
                for (int k = 0; k < sw.Count; k++)
                    if (ReferenceEquals(sw[k], from)) sw[k] = to;
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            if (eh.TryStart == from) eh.TryStart = to;
            if (eh.TryEnd == from) eh.TryEnd = to;
            if (eh.HandlerStart == from) eh.HandlerStart = to;
            if (eh.HandlerEnd == from) eh.HandlerEnd = to;
            if (eh.FilterStart == from) eh.FilterStart = to;
        }
    }

    // Insert `insn` so that it runs whenever control reaches `at`: everything that
    // targeted `at` (branches, switches, handler boundaries) now targets `insn`.
    public static void InsertBefore(CilBody body, Instruction at, Instruction insn)
    {
        body.Instructions.Insert(body.Instructions.IndexOf(at), insn);
        Retarget(body, at, insn);
    }

    static void Finish(LoadedModule m, MethodDef md)
    {
        md.Body.UpdateInstructionOffsets();
        md.Body.OptimizeBranches();
        m.Touch();
    }

    static object? ParseOperand(LoadedModule m, MethodDef md, IList<Instruction> list, OpCode oc, object? operand)
    {
        switch (oc.OperandType)
        {
            case OperandType.InlineNone:
                return null;

            case OperandType.ShortInlineI:
                return oc.Code == Code.Ldc_I4_S
                    ? (sbyte)Convert.ToInt32(Req(operand)) : (byte)Convert.ToInt32(Req(operand));
            case OperandType.InlineI:
                return Convert.ToInt32(Req(operand));
            case OperandType.InlineI8:
                return Convert.ToInt64(Req(operand));
            case OperandType.ShortInlineR:
                return Convert.ToSingle(Req(operand), CultureInfo.InvariantCulture);
            case OperandType.InlineR:
                return Convert.ToDouble(Req(operand), CultureInfo.InvariantCulture);

            case OperandType.InlineString:
                return Req(operand).ToString();

            case OperandType.ShortInlineBrTarget:
            case OperandType.InlineBrTarget:
                return list[Index(list, Req(operand), allowEnd: false)];

            case OperandType.InlineSwitch:
                return Req(operand).ToString()!
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(t => list[Index(list, int.Parse(t, CultureInfo.InvariantCulture), allowEnd: false)])
                    .ToArray();

            case OperandType.ShortInlineVar:
            case OperandType.InlineVar:
                return oc.Name.StartsWith("ldarg") || oc.Name.StartsWith("starg")
                    ? md.Parameters[Convert.ToInt32(Req(operand))]
                    : md.Body.Variables[Convert.ToInt32(Req(operand))];

            case OperandType.InlineMethod:
            case OperandType.InlineField:
            case OperandType.InlineType:
            case OperandType.InlineTok:
                return ImportToken(m, (uint)Convert.ToInt64(Req(operand)));

            default:
                throw new ArgumentException($"operand type {oc.OperandType} is not supported for {oc.Name}");
        }
    }

    static object Req(object? v) => v ?? throw new ArgumentException("this opcode requires an operand");

    static object ImportToken(LoadedModule m, uint token)
    {
        var resolved = m.Module.ResolveToken(token)
            ?? throw new ArgumentException($"0x{token:X8} does not resolve in module {m.Id}");
        var importer = new Importer(m.Module, ImporterOptions.TryToUseDefs);
        return resolved switch
        {
            TypeDef td => importer.Import(td),
            TypeRef tr => importer.Import(tr),
            TypeSpec ts => importer.Import(ts),
            MethodDef meth => importer.Import(meth),
            FieldDef fld => importer.Import(fld),
            MemberRef mr => importer.Import(mr),
            MethodSpec ms => importer.Import(ms),
            IField f => importer.Import(f),
            IMethod im => importer.Import(im),
            _ => throw new ArgumentException($"0x{token:X8} is not a usable IL operand"),
        };
    }
}
