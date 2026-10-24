// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using DnSpySql.Sql;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Functions;

/// <summary>
/// SQL utilities for reading what the tables return: .NET regex, text encodings, and integers out of a blob. Decoding
/// and decryption (base64, xor, decompress, decrypt, hashes) are not dnSpy features; an agent does those in its own
/// code. Pure functions; NULL in, NULL out.
/// </summary>
public static class DataFunctions
{
    static readonly ConcurrentDictionary<string, Regex> Regexes = new();

    public static void Register(Session s)
    {
        // ---- regex ----
        s.Fn("regexp", 2, 2, a => a[0] == null || a[1] == null ? null : Rx(Str(a[0], "pattern")).IsMatch(Str(a[1], "value")) ? 1L : 0L,
            "regexp(pattern, value)", ".NET regex match (1/0); also enables `value REGEXP 'pattern'`. Use (?i) for case-insensitive", "data", deterministic: true);
        s.Fn("regexp_extract", 2, 3, a =>
        {
            if (a[0] == null || a[1] == null) return null;
            var m = Rx(Str(a[1], "pattern")).Match(Str(a[0], "value"));
            if (!m.Success) return null;
            var g = a.Arg(2) is string name && !long.TryParse(name, out _) ? m.Groups[name] : m.Groups[(int)(Values.ToLong(a.Arg(2)) ?? 0)];
            return g.Success ? g.Value : null;
        }, "regexp_extract(value, pattern [, group])", "first match (or capture group number/name) of a .NET regex, NULL when none", "data", deterministic: true);
        s.Fn("regexp_replace", 3, 3, a => a[0] == null || a[1] == null ? null : Rx(Str(a[1], "pattern")).Replace(Str(a[0], "value"), Values.ToText(a[2]) ?? ""),
            "regexp_replace(value, pattern, replacement)", "replace every .NET regex match ($1, ${name} substitutions)", "data", deterministic: true);

        // ---- text encodings ----
        s.Fn("text_decode", 1, 2, a => a[0] == null ? null : Enc(Values.ToText(a.Arg(1))).GetString(Bytes(a[0], "data")),
            "text_decode(blob [, encoding])", "bytes to text: utf-8 (default), utf-16le/unicode, utf-16be, utf-32, ascii, latin1", "data", deterministic: true);
        s.Fn("text_encode", 1, 2, a => a[0] == null ? null : Enc(Values.ToText(a.Arg(1))).GetBytes(Str(a[0], "text")),
            "text_encode(text [, encoding])", "text to bytes (encodings as text_decode)", "data", deterministic: true);

        // container formats (headers, tables) are length and offset fields: read them without hand arithmetic
        s.Fn("int_at", 3, 4, a =>
        {
            if (a[0] == null || a[1] == null) return null;
            var data = Bytes(a[0], "data");
            long off = Lng(a[1], "offset"), size = Lng(a[2], "size");
            if (size is not (1 or 2 or 4 or 8)) throw new SqlException("int_at: size must be 1, 2, 4 or 8");
            if (off < 0 || off + size > data.Length) return null;
            var big = (Values.ToText(a.Arg(3)) ?? "le").ToLowerInvariant() switch
            {
                "le" or "little" => false, "be" or "big" => true, var e => throw new SqlException($"int_at: endian must be 'le' or 'be', not '{e}'"),
            };
            var span = data.AsSpan((int)off, (int)size);
            return size switch
            {
                1 => (long)span[0],
                2 => big ? System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(span) : System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(span),
                4 => big ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(span) : System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(span),
                _ => big ? System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(span) : System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(span),
            };
        }, "int_at(data, offset, size [, 'le'|'be'])",
            "the unsigned integer of 1, 2 or 4 bytes (8: signed) at a byte offset of a blob, little-endian by default; NULL past the end", "data", deterministic: true);
    }

    // Patterns are usually literals, but a query can take them from a column: the cache is bounded.
    static Regex Rx(string pattern)
    {
        if (Regexes.Count > 1000) Regexes.Clear();
        return Regexes.GetOrAdd(pattern, p =>
        {
            try { return new Regex(p, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2)); }
            catch (ArgumentException e) { throw new SqlException($"bad regex: {e.Message}"); }
        });
    }

    static byte[] Bytes(object? v, string what) => v switch
    {
        byte[] b => b,
        string t => Encoding.UTF8.GetBytes(t),
        null => throw new SqlException($"{what} cannot be NULL"),
        _ => throw new SqlException($"{what} must be a blob or text (use unhex('..') for binary)"),
    };

    static Encoding Enc(string? name) => (name ?? "utf-8").ToLowerInvariant().Replace("_", "-") switch
    {
        "utf-8" or "utf8" => new UTF8Encoding(false),
        "utf-16" or "utf-16le" or "utf16" or "utf16le" or "unicode" => new UnicodeEncoding(false, false),
        "utf-16be" or "utf16be" or "bigendianunicode" => new UnicodeEncoding(true, false),
        "utf-32" or "utf32" or "utf-32le" => new UTF32Encoding(false, false),
        "ascii" or "us-ascii" => Encoding.ASCII,
        "latin1" or "iso-8859-1" => Encoding.Latin1,
        var n => throw new SqlException($"unknown encoding '{n}' (utf-8 | utf-16le | utf-16be | utf-32 | ascii | latin1)"),
    };
}
