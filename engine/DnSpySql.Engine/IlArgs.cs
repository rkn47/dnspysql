// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet.Emit;

namespace DnSpySql;

/// <summary>
/// A call's arguments as the IL before it computes them: where each argument's instructions start, found by walking
/// back over the stack effects of straight-line code (a nop, or a branch to the very next instruction, is filler
/// obfuscators insert), and the value of an argument whose instructions compute on constants only: a literal, or
/// arithmetic on literals (ldc 0x1234; ldc 0x5678; xor), folded with the interpreter's CLR semantics. Every reader of
/// call arguments (string_decryptors, decryptor_calls, inline_strings, call_edges.string_args, capabilities, field
/// values) goes through here, so they agree on what an argument is.
/// </summary>
public static class IlArgs
{
    /// <summary>How far back from a call the arguments are looked for, in instructions.</summary>
    public const int MaxBack = 64;

    public static bool IsFiller(IList<Instruction> ins, int i) =>
        ins[i].OpCode.Code == Code.Nop
        || ins[i].OpCode.Code is Code.Br or Code.Br_S && i + 1 < ins.Count && ReferenceEquals(ins[i].Operand, ins[i + 1]);

    /// <summary>
    /// The start of each of the last <paramref name="count"/> values on the stack at <paramref name="at"/> (a call's
    /// arguments, `this` first), with one more entry, <paramref name="at"/> itself: argument k is the instructions from
    /// starts[k] up to starts[k + 1]. Null when the code before is not one straight sequence (a branch, a return, an
    /// instruction that pushes for two arguments at once), or the arguments start further back than <see cref="MaxBack"/>.
    /// </summary>
    public static int[]? Starts(IList<Instruction> ins, int at, int count)
    {
        if (at < 0 || at > ins.Count) return null;
        var starts = new int[count + 1];
        starts[count] = at;
        int i = at - 1;
        for (int k = count - 1; k >= 0; k--)
        {
            int need = 1; // values this argument still needs from the instructions before
            for (; ; i--)
            {
                if (i < 0 || at - i > MaxBack) return null;
                if (IsFiller(ins, i)) continue;
                var x = ins[i];
                if (x.OpCode.FlowControl is not (FlowControl.Next or FlowControl.Call)) return null;
                x.CalculateStackUsage(false, out int push, out int pop);
                if (push > need) return null; // dup, or one instruction feeding two arguments
                need += pop - push;
                if (need == 0) { starts[k] = i--; break; }
            }
        }
        return starts;
    }

    /// <summary>
    /// The string literal (ldstr) each parameter of the call at <paramref name="call"/> is given, null where the argument is
    /// something else; null when the instruction is no call or none of its arguments is found. The later arguments are
    /// found even when an earlier one (often `this`) is not straight-line code.
    /// </summary>
    public static string?[]? StringLiterals(IList<Instruction> ins, int call)
    {
        if (call < 0 || call >= ins.Count || ins[call].Operand is not dnlib.DotNet.IMethod callee || callee.MethodSig is not { } sig) return null;
        int self = sig.HasThis && ins[call].OpCode.Code != Code.Newobj ? 1 : 0, total = sig.Params.Count + self;
        int m = total;
        int[]? starts = null;
        for (; m > 0 && (starts = Starts(ins, call, m)) == null; m--) { }
        if (starts == null) return null;
        int first = total - m; // the first argument whose instructions were found
        var values = new string?[sig.Params.Count];
        for (int k = 0; k < values.Length; k++)
            if (k + self >= first && Single(ins, starts[k + self - first], starts[k + self - first + 1]) is var one and >= 0 && ins[one].OpCode.Code == Code.Ldstr)
                values[k] = ins[one].Operand as string;
        return values;
    }

    /// <summary>The one instruction an argument consists of (fillers aside), or -1 when it is an expression.</summary>
    public static int Single(IList<Instruction> ins, int start, int end)
    {
        int found = -1;
        for (int i = start; i < end; i++)
        {
            if (IsFiller(ins, i)) continue;
            if (found >= 0) return -1;
            found = i;
        }
        return found;
    }

    /// <summary>
    /// The value of the instructions from <paramref name="start"/> to <paramref name="end"/> when they compute one value
    /// from constants only. <paramref name="leaf"/> gives the constant an instruction pushes (ldc, ldstr, ldnull, or a
    /// field or getter known to hold one), as the interpreter's stack holds it (int32 as int); null when it is none.
    /// Arithmetic, conversions, neg and not are folded; anything else, or a division by zero, gives false.
    /// </summary>
    public static bool TryFold(IList<Instruction> ins, int start, int end, Func<Instruction, (bool Ok, object? Value)> leaf, out object? value)
    {
        value = null;
        var stack = new Stack<object?>();
        try
        {
            for (int i = start; i < end; i++)
            {
                if (IsFiller(ins, i)) continue;
                var x = ins[i];
                var op = x.OpCode.Code;
                switch (op)
                {
                    case Code.Add: case Code.Sub: case Code.Mul: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
                    case Code.And: case Code.Or: case Code.Xor: case Code.Shl: case Code.Shr: case Code.Shr_Un:
                        if (stack.Count < 2) return false;
                        var b = stack.Pop();
                        stack.Push(Emulator.Arith(op, stack.Pop(), b));
                        break;
                    case Code.Neg:
                        if (stack.Count < 1) return false;
                        stack.Push(stack.Pop() switch { int v => unchecked(-v), long v => (object)unchecked(-v), double v => -v, _ => throw new InvalidOperationException() });
                        break;
                    case Code.Not:
                        if (stack.Count < 1) return false;
                        stack.Push(stack.Pop() switch { int v => ~v, long v => (object)~v, _ => throw new InvalidOperationException() });
                        break;
                    // (conv.i1 .. conv.u8 are 0x67..0x6E; conv.u2, conv.u1, conv.i and conv.u come later)
                    case >= Code.Conv_I1 and <= Code.Conv_U8 or Code.Conv_U2 or Code.Conv_U1 or Code.Conv_I or Code.Conv_U or Code.Conv_R_Un
                        or Code.Conv_Ovf_I1_Un or Code.Conv_Ovf_I2_Un
                        or Code.Conv_Ovf_I4_Un or Code.Conv_Ovf_I8_Un or Code.Conv_Ovf_U1_Un or Code.Conv_Ovf_U2_Un or Code.Conv_Ovf_U4_Un
                        or Code.Conv_Ovf_U8_Un or Code.Conv_Ovf_I_Un or Code.Conv_Ovf_U_Un or Code.Conv_Ovf_I1 or Code.Conv_Ovf_U1 or Code.Conv_Ovf_I2
                        or Code.Conv_Ovf_U2 or Code.Conv_Ovf_I4 or Code.Conv_Ovf_U4 or Code.Conv_Ovf_I8 or Code.Conv_Ovf_U8 or Code.Conv_Ovf_I or Code.Conv_Ovf_U:
                        if (stack.Count < 1) return false;
                        stack.Push(Emulator.Conv(op, stack.Pop()));
                        break;
                    default:
                        var (ok, v2) = leaf(x);
                        if (!ok) return false;
                        stack.Push(v2);
                        break;
                }
            }
        }
        catch (Exception e) when (e is Emulator.Failed or InvalidOperationException or DivideByZeroException or OverflowException) { return false; }
        if (stack.Count != 1) return false;
        value = stack.Pop();
        return true;
    }
}
