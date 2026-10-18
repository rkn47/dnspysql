// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnSpySql.Sql;

namespace DnSpySql;

/// <summary>Result rendering shared by the CLI, HTTP server and MCP server.</summary>
public static class Output
{
    public static string Cell(object? v, int max = int.MaxValue)
    {
        var s = v switch
        {
            null => "NULL",
            byte[] b => b.Length <= 64 ? "x'" + Convert.ToHexString(b).ToLowerInvariant() + "'" : $"x'{Convert.ToHexString(b, 0, 64).ToLowerInvariant()}...' ({b.Length} bytes)",
            double d => d.ToString("R", System.Globalization.CultureInfo.InvariantCulture),
            _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "",
        };
        if (s.Length > max) s = max <= 3 ? s[..Math.Max(0, max)] : s[..(max - 3)] + "...";
        return s;
    }

    /// <summary>
    /// Escapes characters that are invisible or reorder text on a terminal (bidi overrides, zero-width and odd spaces,
    /// controls, private-use, unassigned, lone surrogates) as \uXXXX, like the decompiler does. Obfuscators build names
    /// from them; printed raw they break alignment and can make output read differently from what it is.
    /// </summary>
    public static string Visible(string s)
    {
        if (s.All(ch => ch >= 0x20 && ch < 0x7F || ch is '\n' or '\t')) return s;
        var sb = new StringBuilder(s.Length + 16);
        for (int i = 0; i < s.Length; i++)
        {
            char ch = s[i];
            if (ch is '\n' or '\t' || ch >= 0x20 && ch < 0x7F) { sb.Append(ch); continue; }
            if (char.IsHighSurrogate(ch) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                var rune = new Rune(ch, s[++i]);
                if (Hidden(Rune.GetUnicodeCategory(rune))) sb.Append($"\\U{rune.Value:x8}"); else sb.Append(ch).Append(s[i]);
                continue;
            }
            if (char.IsSurrogate(ch) || Hidden(char.GetUnicodeCategory(ch))) sb.Append($"\\u{(int)ch:x4}");
            else sb.Append(ch);
        }
        return sb.ToString();

        static bool Hidden(System.Globalization.UnicodeCategory c) => c is System.Globalization.UnicodeCategory.Control
            or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.SpaceSeparator
            or System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator
            or System.Globalization.UnicodeCategory.PrivateUse or System.Globalization.UnicodeCategory.OtherNotAssigned
            or System.Globalization.UnicodeCategory.Surrogate;
    }

    public static JsonNode? Json(object? v) => v switch
    {
        null => null,
        long l => JsonValue.Create(l),
        double d when double.IsFinite(d) => JsonValue.Create(d),
        double d => JsonValue.Create(d.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        byte[] b => JsonValue.Create(Convert.ToHexString(b).ToLowerInvariant()),
        _ => JsonValue.Create(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)),
    };

}
