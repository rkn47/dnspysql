// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

/// <summary>Exact snapshot of a method body (instruction objects, their opcodes/operands, handlers, locals).</summary>
public sealed class BodySnapshot
{
    readonly MethodDef _method;
    readonly CilBody? _body;
    readonly List<(Instruction ins, OpCode op, object? operand)> _ins = new();
    readonly List<(ExceptionHandler eh, ExceptionHandlerType kind, Instruction? ts, Instruction? te, Instruction? hs, Instruction? he, Instruction? fs, ITypeDefOrRef? ct)> _eh = new();
    // a local's name and type change in place (locals.name/type), so they are part of the snapshot
    readonly List<(Local l, string? name, TypeSig type)> _locals = new();
    readonly ushort _maxStack;
    readonly bool _initLocals, _keepOldMaxStack;
    readonly MethodImplAttributes _impl;
    readonly MethodAttributes _attrs;

    public BodySnapshot(MethodDef m)
    {
        _method = m;
        _body = m.Body;
        _impl = m.ImplAttributes;
        _attrs = m.Attributes;
        if (_body == null) return;
        foreach (var i in _body.Instructions) _ins.Add((i, i.OpCode, i.Operand is Instruction[] a ? a.ToArray() : i.Operand));
        foreach (var e in _body.ExceptionHandlers) _eh.Add((e, e.HandlerType, e.TryStart, e.TryEnd, e.HandlerStart, e.HandlerEnd, e.FilterStart, e.CatchType));
        foreach (var l in _body.Variables) _locals.Add((l, l.Name, l.Type));
        _maxStack = _body.MaxStack;
        _initLocals = _body.InitLocals;
        _keepOldMaxStack = _body.KeepOldMaxStack;
    }

    public void Restore()
    {
        _method.Body = _body;
        _method.ImplAttributes = _impl;
        _method.Attributes = _attrs;
        if (_body == null) return;
        _body.Instructions.Clear();
        foreach (var (ins, op, operand) in _ins) { ins.OpCode = op; ins.Operand = operand; _body.Instructions.Add(ins); }
        _body.ExceptionHandlers.Clear();
        foreach (var x in _eh)
        {
            x.eh.HandlerType = x.kind; x.eh.TryStart = x.ts; x.eh.TryEnd = x.te; x.eh.HandlerStart = x.hs; x.eh.HandlerEnd = x.he;
            x.eh.FilterStart = x.fs; x.eh.CatchType = x.ct;
            _body.ExceptionHandlers.Add(x.eh);
        }
        _body.Variables.Clear();
        foreach (var (l, name, type) in _locals) { l.Name = name; l.Type = type; _body.Variables.Add(l); }
        _body.MaxStack = _maxStack;
        _body.InitLocals = _initLocals;
        _body.KeepOldMaxStack = _keepOldMaxStack;
        _body.UpdateInstructionOffsets();
    }
}

public static class BodyEditor
{
    /// <summary>Runs a body mutation as one journaled, undoable step.</summary>
    public static void Edit(Session s, MethodDef m, string description, Action<CilBody> mutate)
    {
        var lm = s.Ws.ModuleOf(m);
        if (!m.HasBody) throw new SqlException($"{m.FullName} has no IL body (use set_body_stub() to create one)");
        var before = new BodySnapshot(m);
        try
        {
            mutate(m.Body);
            m.Body.KeepOldMaxStack = false;
            m.Body.UpdateInstructionOffsets();
        }
        catch
        {
            before.Restore();
            throw;
        }
        var after = new BodySnapshot(m);
        s.Ws.Touch(lm);
        s.Ws.Record("il", description, () => { before.Restore(); s.Ws.Touch(lm); }, () => { after.Restore(); s.Ws.Touch(lm); });
    }

    /// <summary>Replaces the whole body (or creates one) as one undoable step.</summary>
    public static void Replace(Session s, MethodDef m, string description, Func<CilBody> build)
    {
        var lm = s.Ws.ModuleOf(m);
        var before = new BodySnapshot(m);
        var newBody = build();
        m.Body = newBody;
        m.ImplAttributes = (m.ImplAttributes & ~(MethodImplAttributes.CodeTypeMask | MethodImplAttributes.InternalCall))
                           | MethodImplAttributes.IL | MethodImplAttributes.Managed;
        m.Attributes &= ~(MethodAttributes.Abstract | MethodAttributes.PinvokeImpl);
        if (m.ImplMap != null && !m.IsPinvokeImpl) m.ImplMap = null;
        var after = new BodySnapshot(m);
        s.Ws.Touch(lm);
        s.Ws.Record("il", description, () => { before.Restore(); s.Ws.Touch(lm); }, () => { after.Restore(); s.Ws.Touch(lm); });
    }

    /// <summary>Removes an instruction; branches/handlers pointing at it are retargeted to the next instruction.</summary>
    public static void RemoveAt(CilBody body, int index)
    {
        var ins = body.Instructions;
        if (index < 0 || index >= ins.Count) throw new SqlException($"instruction index {index} out of range");
        var victim = ins[index];
        var next = index + 1 < ins.Count ? ins[index + 1] : null;
        if (next == null && ins.Any(i => i != victim && (i.Operand == victim || i.Operand is Instruction[] a && a.Contains(victim))))
            throw new SqlException("cannot remove the last instruction while it is a branch target");
        foreach (var i in ins)
        {
            if (i.Operand == victim) i.Operand = next;
            else if (i.Operand is Instruction[] targets)
                for (int k = 0; k < targets.Length; k++) if (targets[k] == victim) targets[k] = next!;
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            if (eh.TryStart == victim) eh.TryStart = next;
            if (eh.TryEnd == victim) eh.TryEnd = next;
            if (eh.HandlerStart == victim) eh.HandlerStart = next;
            if (eh.HandlerEnd == victim) eh.HandlerEnd = next;
            if (eh.FilterStart == victim) eh.FilterStart = next;
        }
        ins.RemoveAt(index);
    }

    public static Instruction Make(OpCode op, object? operand) => new(op, operand);

    /// <summary>dnSpy "Invert branch".</summary>
    public static OpCode Invert(OpCode op) => op.Code switch
    {
        Code.Brtrue => OpCodes.Brfalse, Code.Brfalse => OpCodes.Brtrue,
        Code.Brtrue_S => OpCodes.Brfalse_S, Code.Brfalse_S => OpCodes.Brtrue_S,
        Code.Beq => OpCodes.Bne_Un, Code.Bne_Un => OpCodes.Beq,
        Code.Beq_S => OpCodes.Bne_Un_S, Code.Bne_Un_S => OpCodes.Beq_S,
        Code.Bge => OpCodes.Blt, Code.Blt => OpCodes.Bge, Code.Bge_S => OpCodes.Blt_S, Code.Blt_S => OpCodes.Bge_S,
        Code.Bgt => OpCodes.Ble, Code.Ble => OpCodes.Bgt, Code.Bgt_S => OpCodes.Ble_S, Code.Ble_S => OpCodes.Bgt_S,
        Code.Bge_Un => OpCodes.Blt_Un, Code.Blt_Un => OpCodes.Bge_Un, Code.Bge_Un_S => OpCodes.Blt_Un_S, Code.Blt_Un_S => OpCodes.Bge_Un_S,
        Code.Bgt_Un => OpCodes.Ble_Un, Code.Ble_Un => OpCodes.Bgt_Un, Code.Bgt_Un_S => OpCodes.Ble_Un_S, Code.Ble_Un_S => OpCodes.Bgt_Un_S,
        _ => throw new SqlException($"{op.Name} is not a conditional branch"),
    };
}
