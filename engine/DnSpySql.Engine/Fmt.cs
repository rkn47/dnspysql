// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Globalization;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

static class Fmt
{
    public static string? Operand(object? op) => op switch
    {
        null => null,
        string s => Quote(s),
        Instruction i => Label(i),
        IList<Instruction> list => "(" + string.Join(", ", list.Select(Label)) + ")",
        Local l => string.IsNullOrEmpty(l.Name) ? $"V_{l.Index}" : l.Name,
        Parameter p => p.IsHiddenThisParameter ? "this" : string.IsNullOrEmpty(p.Name) ? $"A_{p.Index}" : p.Name,
        IFullName f => f.FullName,
        float f => f.ToString("R", CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        IFormattable n => n.ToString(null, CultureInfo.InvariantCulture),
        _ => op.ToString(),
    };

    public static string Label(Instruction i) => $"IL_{i.Offset:X4}";

    public static string Quote(string s) =>
        "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\0", "\\0") + "\"";

    public static string CaArg(CAArgument a) => a.Value switch
    {
        null => "null",
        UTF8String u => Quote(u.String),
        string s => Quote(s),
        TypeSig t => $"typeof({t.FullName})",
        IList<CAArgument> arr => "[" + string.Join(", ", arr.Select(CaArg)) + "]",
        CAArgument inner => CaArg(inner),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        var v => v.ToString() ?? "",
    };
}
