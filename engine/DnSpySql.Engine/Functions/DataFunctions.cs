// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using DnSpySql.Sql;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Functions;

/// <summary>
/// Data helpers for decoding what assemblies carry (strings, resources, field RVA data): regex, base64, xor,
/// decompression, symmetric decryption, key derivation, hashing and text encodings. Pure functions; NULL in, NULL out.
/// </summary>
public static class DataFunctions
{
    /// <summary>Decompression output cap (guards against decompression bombs).</summary>
    const int MaxInflated = 256 << 20;

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

        // ---- encodings ----
        s.Fn("base64_decode", 1, 1, a => a[0] == null ? null : Base64(Str(a[0], "value")),
            "base64_decode(text)", "decode base64 (whitespace, missing padding and URL-safe -_ accepted) to a blob; NULL when not base64", "data", deterministic: true);
        s.Fn("base64_encode", 1, 1, a => a[0] == null ? null : Convert.ToBase64String(Bytes(a[0], "data")),
            "base64_encode(data)", "encode a blob (or UTF-8 text) as base64", "data", deterministic: true);
        s.Fn("text_decode", 1, 2, a => a[0] == null ? null : Enc(Values.ToText(a.Arg(1))).GetString(Bytes(a[0], "data")),
            "text_decode(blob [, encoding])", "bytes to text: utf-8 (default), utf-16le/unicode, utf-16be, utf-32, ascii, latin1", "data", deterministic: true);
        s.Fn("text_encode", 1, 2, a => a[0] == null ? null : Enc(Values.ToText(a.Arg(1))).GetBytes(Str(a[0], "text")),
            "text_encode(text [, encoding])", "text to bytes (encodings as text_decode)", "data", deterministic: true);

        // ---- transforms ----
        s.Fn("xor", 2, 2, a => a[0] == null || a[1] == null ? null : Xor(Bytes(a[0], "data"), XorKey(a[1])),
            "xor(data, key)", "XOR with a repeating key: blob, UTF-8 text, or a single byte as an integer 0..255", "data", deterministic: true);
        s.Fn("emulate", 1, 9, a =>
        {
            var h = s.Ws.Normalize(Lng(a[0], "method"));
            var lm = s.Ws.Get(Handle.Module(h));
            if (lm.Module.ResolveToken(Handle.Token(h)) is not dnlib.DotNet.MethodDef md) throw new SqlException($"{Handle.Hex(h)} is not a method");
            try { return Emulator.ToSql(Emulator.For(s).Call(md, a.Skip(1).ToList())); }
            catch (Emulator.Failed e) { throw new SqlException(e.Message); }
        }, "emulate(method [, arg, ...])",
            "the result of a static method on the given arguments, computed by interpreting its IL: the sample never runs. For string " +
            "decryptors and constant tables (arithmetic, arrays, strings, encodings, hashes, ciphers); an error says what it could not interpret",
            "data");
        // container formats (overlays, packed configs) are length and offset fields: read them without hand arithmetic
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
        // SQLite's || makes text of blobs, which breaks key derivations like md5(key) || md5(key)[..15]
        s.Fn("concat_bytes", 1, 16, a => a.Any(x => x == null) ? null : a.SelectMany(x => Bytes(x, "data")).ToArray(),
            "concat_bytes(a, b, ...)", "concatenate blobs (or UTF-8 text) into one blob; NULL if any part is NULL", "data", deterministic: true);
        s.Fn("decompress", 1, 2, a => a[0] == null ? null : Decompress(Bytes(a[0], "data"), (Values.ToText(a.Arg(1)) ?? "auto").ToLowerInvariant()),
            "decompress(data [, 'auto'|'gzip'|'zlib'|'deflate'|'brotli'|'lzma'])", "inflate compressed bytes; auto detects gzip (1F 8B) and zlib (78 xx), also after a 4-byte length, else raw deflate. NULL when the data does not inflate (raw deflate and brotli have no header to check: garbage can still inflate to something)", "data", deterministic: true);
        s.Fn("decrypt", 3, 6, a => a[0] == null ? null : Decrypt(Bytes(a[0], "data"), Str(a[1], "algorithm"), Bytes(a[2], "key"),
                a.Arg(3) == null ? null : Bytes(a[3], "iv"), Values.ToText(a.Arg(4)), Values.ToText(a.Arg(5))),
            "decrypt(data, algorithm, key [, iv [, mode [, padding]]])",
            "symmetric decryption: algorithm aes|des|3des|rc2|rc4; mode cbc (default with an iv) | ecb (default without) | cfb; padding pkcs7 (default) | none | zeros | ansix923 | iso10126. NULL when the padding does not check out (usually a wrong key, iv or mode); an error when the key or iv has the wrong size",
            "data", deterministic: true);
        s.Fn("aes_decrypt", 2, 4, a => a[0] == null ? null : Decrypt(Bytes(a[0], "data"), "aes", Bytes(a[1], "key"),
                a.Arg(2) == null ? null : Bytes(a[2], "iv"), Values.ToText(a.Arg(3)), null),
            "aes_decrypt(data, key [, iv [, mode]])", "AES decryption (PKCS7 padding); same as decrypt(data, 'aes', ...)", "data", deterministic: true);
        s.Fn("pbkdf2", 4, 5, a => Pbkdf2(Bytes(a[0], "password"), Bytes(a[1], "salt"), (int)Lng(a[2], "iterations"),
                (int)Lng(a[3], "length"), Hash(Values.ToText(a.Arg(4)) ?? "sha1"), s.Db.Cancellation),
            "pbkdf2(password, salt, iterations, length [, hash])", "PBKDF2 / Rfc2898DeriveBytes key derivation (hash sha1 (default) | sha256 | sha384 | sha512 | md5)", "data", deterministic: true);

        // ---- digests ----
        s.Fn("md5", 1, 1, a => a[0] == null ? null : Hex(MD5.HashData(Bytes(a[0], "data"))), "md5(data)", "MD5 of a blob or UTF-8 text, lowercase hex", "data", deterministic: true);
        s.Fn("sha1", 1, 1, a => a[0] == null ? null : Hex(SHA1.HashData(Bytes(a[0], "data"))), "sha1(data)", "SHA-1 of a blob or UTF-8 text, lowercase hex", "data", deterministic: true);
        s.Fn("sha256", 1, 1, a => a[0] == null ? null : Hex(SHA256.HashData(Bytes(a[0], "data"))), "sha256(data)", "SHA-256 of a blob or UTF-8 text, lowercase hex", "data", deterministic: true);
        s.Fn("entropy", 1, 1, a => a[0] == null ? null : Entropy(Bytes(a[0], "data")),
            "entropy(data)", "Shannon entropy in bits per byte (0..8); > 7.5 usually means compressed or encrypted", "data", deterministic: true);
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
        _ => throw new SqlException($"{what} must be a blob or text (use unhex('..') or base64_decode('..') for binary)"),
    };

    static byte[] XorKey(object? k) => k switch
    {
        long n when n is >= 0 and <= 255 => new[] { (byte)n },
        long => throw new SqlException("xor key as an integer must be a single byte 0..255"),
        _ => Bytes(k, "key") is { Length: > 0 } b ? b : throw new SqlException("xor key cannot be empty"),
    };

    static byte[] Xor(byte[] data, byte[] key)
    {
        var r = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key[i % key.Length]);
        return r;
    }

    static byte[]? Base64(string s)
    {
        var sb = new StringBuilder(s.Length + 3);
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c)) continue;
            sb.Append(c switch { '-' => '+', '_' => '/', _ => c });
        }
        while (sb.Length % 4 != 0) sb.Append('=');
        var buf = new byte[sb.Length * 3 / 4];
        return Convert.TryFromBase64String(sb.ToString(), buf, out var n) ? buf[..n] : null;
    }

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

    // NULL when the data does not inflate (like base64_decode on bad input), so SELECT decompress(data) FROM resources
    // gets a row per resource instead of stopping at the first one that is not compressed.
    static byte[]? Decompress(byte[] data, string format)
    {
        if (format == "lzma") return Lzma.TryDecode(data); // the .lzma "alone" layout: properties, size (8 or 4 bytes), stream
        if (format == "auto")
        {
            // a stream after a 4-byte length (BitConverter.GetBytes(size) + the compressed bytes, a common .NET layout)
            if (data.Length >= 6 && !Gzip(data, 0) && !Zlib(data, 0) && (Gzip(data, 4) || Zlib(data, 4)))
                return Decompress(data[4..], Gzip(data, 4) ? "gzip" : "zlib");
            format = Gzip(data, 0) ? "gzip" : Zlib(data, 0) ? "zlib" : "deflate";
        }
        using var input = new MemoryStream(data);
        using Stream z = format switch
        {
            "gzip" => new GZipStream(input, CompressionMode.Decompress),
            "zlib" => new ZLibStream(input, CompressionMode.Decompress),
            "deflate" or "inflate" => new DeflateStream(input, CompressionMode.Decompress),
            "brotli" => new BrotliStream(input, CompressionMode.Decompress),
            _ => throw new SqlException($"unknown compression '{format}' (auto | gzip | zlib | deflate | brotli | lzma)"),
        };
        using var output = new MemoryStream();
        var buf = new byte[81920];
        try
        {
            int n;
            while ((n = z.Read(buf, 0, buf.Length)) > 0)
            {
                if (output.Length + n > MaxInflated) throw new SqlException($"decompressed data exceeds {MaxInflated >> 20} MB");
                output.Write(buf, 0, n);
            }
        }
        catch (InvalidDataException) { return null; }
        return output.Length == 0 && data.Length > 0 ? null : output.ToArray();
    }

    static bool Gzip(byte[] d, int at) => d.Length >= at + 3 && d[at] == 0x1F && d[at + 1] == 0x8B && d[at + 2] == 8;
    static bool Zlib(byte[] d, int at) => d.Length >= at + 2 && d[at] == 0x78 && ((d[at] << 8) | d[at + 1]) % 31 == 0;

    static byte[]? Decrypt(byte[] data, string algorithm, byte[] key, byte[]? iv, string? mode, string? padding)
    {
        var alg = algorithm.ToLowerInvariant().Replace("-", "").Replace("_", "");
        if (alg is "rc4" or "arc4") return Rc4(data, key);
        using SymmetricAlgorithm c = alg switch
        {
            "aes" or "rijndael" => Aes.Create(),
            "des" => DES.Create(),
            "3des" or "tripledes" or "des3" => TripleDES.Create(),
            "rc2" => RC2.Create(),
            _ => throw new SqlException($"unknown algorithm '{algorithm}' (aes | des | 3des | rc2 | rc4)"),
        };
        var cipherMode = (mode ?? (iv == null ? "ecb" : "cbc")).ToLowerInvariant() switch
        {
            "cbc" => CipherMode.CBC,
            "ecb" => CipherMode.ECB,
            "cfb" => CipherMode.CFB,
            var m => throw new SqlException($"unknown mode '{m}' (cbc | ecb | cfb)"),
        };
        var pad = (padding ?? "pkcs7").ToLowerInvariant() switch
        {
            "pkcs7" or "pkcs5" => PaddingMode.PKCS7,
            "none" => PaddingMode.None,
            "zeros" or "zero" => PaddingMode.Zeros,
            "ansix923" => PaddingMode.ANSIX923,
            "iso10126" => PaddingMode.ISO10126,
            var p => throw new SqlException($"unknown padding '{p}' (pkcs7 | none | zeros | ansix923 | iso10126)"),
        };
        if (!c.ValidKeySize(key.Length * 8))
            throw new SqlException($"{algorithm}: a {key.Length}-byte key is not valid (sizes: {string.Join(", ", c.LegalKeySizes.Select(k => $"{k.MinSize / 8}..{k.MaxSize / 8}"))} bytes)");
        c.Key = key;
        int block = c.BlockSize / 8;
        if (cipherMode != CipherMode.ECB && (iv == null || iv.Length != block))
            throw new SqlException($"{algorithm} {cipherMode}: the iv must be {block} bytes");
        try
        {
            return cipherMode switch
            {
                CipherMode.ECB => c.DecryptEcb(data, pad),
                CipherMode.CBC => c.DecryptCbc(data, iv!, pad),
                _ => c.DecryptCfb(data, iv!, pad, feedbackSizeInBits: 8),
            };
        }
        catch (CryptographicException) { return null; } // a wrong key/iv/mode/padding: NULL, so a query can try several
    }

    static byte[] Rc4(byte[] data, byte[] key)
    {
        if (key.Length == 0) throw new SqlException("rc4 key cannot be empty");
        var S = new byte[256];
        for (int i = 0; i < 256; i++) S[i] = (byte)i;
        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) & 0xFF;
            (S[i], S[j]) = (S[j], S[i]);
        }
        var r = new byte[data.Length];
        for (int k = 0, i = 0, j = 0; k < data.Length; k++)
        {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            (S[i], S[j]) = (S[j], S[i]);
            r[k] = (byte)(data[k] ^ S[(S[i] + S[j]) & 0xFF]);
        }
        return r;
    }

    // Rfc2898DeriveBytes.Pbkdf2 takes only the SHA family; PBKDF2 with HMAC-MD5 (RFC 8018), which some malware configs
    // use, is derived here.
    // Rfc2898DeriveBytes in one call for the usual iteration counts; a huge count (a config can name one) or MD5 (which
    // it does not support) runs as an HMAC loop that the statement timeout can interrupt.
    static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations, int length, HashAlgorithmName hash, CancellationToken cancel)
    {
        if (iterations <= 0 || length <= 0) throw new SqlException("iterations and length must be positive");
        if (hash != HashAlgorithmName.MD5 && iterations <= 200_000) return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hash, length);
        using var hmac = IncrementalHash.CreateHMAC(hash, password);
        var output = new byte[length];
        for (int block = 1, o = 0; o < length; block++)
        {
            hmac.AppendData(salt);
            hmac.AppendData([(byte)(block >> 24), (byte)(block >> 16), (byte)(block >> 8), (byte)block]);
            var u = hmac.GetHashAndReset();
            var t = (byte[])u.Clone();
            for (int i = 1; i < iterations; i++)
            {
                if ((i & 0xFFF) == 0) cancel.ThrowIfCancellationRequested();
                hmac.AppendData(u);
                u = hmac.GetHashAndReset();
                for (int k = 0; k < t.Length; k++) t[k] ^= u[k];
            }
            Array.Copy(t, 0, output, o, Math.Min(t.Length, length - o));
            o += t.Length;
        }
        return output;
    }

    static HashAlgorithmName Hash(string name) => name.ToLowerInvariant().Replace("-", "") switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        "sha384" => HashAlgorithmName.SHA384,
        "sha512" => HashAlgorithmName.SHA512,
        "md5" => HashAlgorithmName.MD5,
        var n => throw new SqlException($"unknown hash '{n}' (sha1 | sha256 | sha384 | sha512 | md5)"),
    };

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    static double Entropy(byte[] b)
    {
        if (b.Length == 0) return 0;
        var counts = new int[256];
        foreach (var x in b) counts[x]++;
        double e = 0;
        foreach (var c in counts) if (c > 0) { var p = (double)c / b.Length; e -= p * Math.Log2(p); }
        return Math.Round(e, 3);
    }
}
