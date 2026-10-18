// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;

namespace DnSpySql;

/// <summary>
/// Rebuilds a destroyed CLI (COR20) header and metadata root. Some samples carry garbage where the header should be,
/// or wipe the "BSJB" signature and the stream names (a native stub restores them in memory before the runtime
/// starts), while the metadata itself is intact. A fresh header pointing at that root, with the streams named by
/// their content, makes the module readable.
/// </summary>
static class ClrHeaderRepair
{
    /// <summary>The repaired image, or null when the file has no CLR directory or no usable metadata root.</summary>
    public static byte[]? TryRepair(byte[] b, out string note)
    {
        note = "";
        try
        {
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe <= 0 || pe + 0x18 > b.Length || BitConverter.ToUInt32(b, pe) != 0x4550) return null;
            int sections = BitConverter.ToUInt16(b, pe + 6), optSize = BitConverter.ToUInt16(b, pe + 0x14), opt = pe + 0x18;
            int dirs = opt + (BitConverter.ToUInt16(b, opt) == 0x20B ? 0x70 : 0x60);
            uint cliRva = BitConverter.ToUInt32(b, dirs + 14 * 8);
            if (cliRva == 0) return null; // native image
            var secs = Enumerable.Range(0, sections).Select(i => opt + optSize + 40 * i).Select(o => (
                va: BitConverter.ToUInt32(b, o + 12), size: Math.Max(BitConverter.ToUInt32(b, o + 8), BitConverter.ToUInt32(b, o + 16)),
                raw: BitConverter.ToUInt32(b, o + 20), rawSize: BitConverter.ToUInt32(b, o + 16))).ToList();
            long cli = secs.Where(s => cliRva >= s.va && cliRva < (long)s.va + s.size).Select(s => (long)cliRva - s.va + s.raw).DefaultIfEmpty(-1).First();
            if (cli < 0 || cli + 72 > b.Length) return null;
            bool InImage(uint rva, uint size) => secs.Any(s => rva >= s.va && (ulong)rva + size <= (ulong)s.va + s.size);

            foreach (var m in Candidates(b))
            {
                var sec = secs.FirstOrDefault(s => m >= s.raw && m < (long)s.raw + s.rawSize);
                if (sec.rawSize == 0) continue;
                // A candidate that does not parse is skipped, not the end of the search: a decoy "BSJB" or "v4." can
                // come before the real root.
                (uint size, string? rebuilt, byte[]? patch)? root;
                try { root = Root(b, m); }
                catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException) { continue; }
                if (root is null) continue;
                var (size, rebuilt, patch) = root.Value;
                var r = (byte[])b.Clone();
                patch?.CopyTo(r, m);

                // A fresh header, keeping the old one's fields that still make sense: the entry point, the managed
                // resources (often the payload) and the other directories.
                var old = b.AsSpan((int)cli, 72).ToArray();
                var h = r.AsSpan((int)cli, 72);
                h.Clear();
                BitConverter.TryWriteBytes(h, 72);                                // cb
                BitConverter.TryWriteBytes(h[4..], (ushort)2);                    // runtime 2.5
                BitConverter.TryWriteBytes(h[6..], (ushort)5);
                BitConverter.TryWriteBytes(h[8..], (uint)(m - sec.raw + sec.va)); // metadata
                BitConverter.TryWriteBytes(h[12..], size);
                uint flags = BitConverter.ToUInt32(old, 16), entry = BitConverter.ToUInt32(old, 20);
                BitConverter.TryWriteBytes(h[16..], (flags & ~0x1001Bu) == 0 ? flags | 1 : 1u);
                bool entryKept = (flags & 0x10) == 0 && (entry >> 24) is 0x06 or 0x26 && (entry & 0xFFFFFF) != 0;
                if (entryKept) BitConverter.TryWriteBytes(h[20..], entry);
                for (int d = 24; d < 72; d += 8)
                {
                    uint rva = BitConverter.ToUInt32(old, d), sz = BitConverter.ToUInt32(old, d + 4);
                    if (rva != 0 && sz != 0 && InImage(rva, sz)) old.AsSpan(d, 8).CopyTo(h[d..]);
                }
                note = $"CLI header at RVA 0x{cliRva:X} is corrupt; metadata root found at file offset 0x{m:X}"
                     + (rebuilt is null ? "" : $" with {rebuilt}")
                     + $" and loaded with a rebuilt header{(entryKept ? "" : " (entry point unknown)")}";
                return r;
            }
        }
        catch (ArgumentException) { }
        catch (IndexOutOfRangeException) { }
        return null;
    }

    /// <summary>Offsets that may start a metadata root: its signature, or a runtime version string ("v4.0.30319")
    /// at the place a root with a wiped signature would hold it.</summary>
    static IEnumerable<int> Candidates(byte[] b)
    {
        var seen = new HashSet<int>();
        for (int i = 0; (i = IndexOf(b, "BSJB"u8, i)) >= 0; i++)
            if (seen.Add(i)) yield return i;
        for (int i = 16; (i = IndexOf(b, "v"u8, i)) >= 0; i++)
            if (i + 3 < b.Length && b[i + 1] is >= (byte)'1' and <= (byte)'9' && b[i + 2] == '.' && seen.Add(i - 16))
                yield return i - 16;
    }

    static int IndexOf(byte[] b, ReadOnlySpan<byte> what, int from)
    {
        if (from >= b.Length) return -1;
        int i = b.AsSpan(from).IndexOf(what);
        return i < 0 ? -1 : from + i;
    }

    /// <summary>
    /// Checks the metadata root at <paramref name="m"/>. Returns the size of the metadata (to the end of its last
    /// stream) and, when its signature or stream names are wiped, a description of what was rebuilt and the new root
    /// header to write at <paramref name="m"/>; null when this is not a usable root.
    /// </summary>
    static (uint size, string? rebuilt, byte[]? patch)? Root(byte[] b, int m)
    {
        int vlen = BitConverter.ToInt32(b, m + 12);
        if (vlen <= 0 || vlen > 255 || m + 20 + vlen > b.Length) return null;
        bool signed = BitConverter.ToUInt32(b, m) == 0x424A5342; // "BSJB"
        if (!signed && b[m + 16] != 'v') return null;
        int hdr = m + 16 + vlen;
        int count = BitConverter.ToUInt16(b, hdr + 2);
        if (count is < 2 or > 64) return null;

        var streams = new List<(uint off, uint size, string name)>();
        int p = hdr + 4;
        for (int i = 0; i < count; i++)
        {
            uint off = BitConverter.ToUInt32(b, p), size = BitConverter.ToUInt32(b, p + 4);
            int name = p += 8;
            if (b[name] == 0)
            {
                // A wiped name: zero dwords up to the next header (whose offset is never 0).
                do p += 4; while (i + 1 < count && p + 4 <= b.Length && BitConverter.ToUInt32(b, p) == 0 && p - name < 32);
                streams.Add((off, size, ""));
                continue;
            }
            while (b[p] != 0) if (++p - name > 32) return null;
            if (b[name] != '#') return null;
            streams.Add((off, size, Encoding.ASCII.GetString(b, name, p - name)));
            p = name + ((p - name + 4) & ~3); // name + NUL, padded to 4
        }
        long end = streams.Max(s => (long)s.off + s.size); // (uint sums wrap past a bounds check)
        if (m + end > b.Length || streams.Any(s => s.off < p - m)) return null;
        if (signed && streams.All(s => s.name != "")) return ((uint)end, null, null);

        var named = Name(b, m, streams);
        if (named is null) return null;

        // Rewrite the root header with the named streams; the streams themselves stay where they are.
        uint first = streams.Min(s => s.off);
        var w = new List<byte>();
        foreach (var (off, size, name) in named)
        {
            w.AddRange(BitConverter.GetBytes(off));
            w.AddRange(BitConverter.GetBytes(size));
            var n = Encoding.ASCII.GetBytes(name);
            w.AddRange(n);
            w.AddRange(new byte[((n.Length + 4) & ~3) - n.Length]);
        }
        if (hdr + 4 + w.Count > m + first) return null;
        var patch = b.AsSpan(m, (int)first).ToArray();
        int h = hdr - m;
        BitConverter.TryWriteBytes(patch, 0x424A5342u);
        BitConverter.TryWriteBytes(patch.AsSpan(4), (ushort)1);
        BitConverter.TryWriteBytes(patch.AsSpan(6), (ushort)1);
        BitConverter.TryWriteBytes(patch.AsSpan(8), 0u);
        BitConverter.TryWriteBytes(patch.AsSpan(h), (ushort)0);
        BitConverter.TryWriteBytes(patch.AsSpan(h + 2), (ushort)named.Count);
        patch.AsSpan(h + 4).Clear();
        w.ToArray().CopyTo(patch, h + 4);
        var what = new List<string>();
        if (!signed) what.Add("its signature");
        if (streams.Any(s => s.name == "")) what.Add($"{streams.Count(s => s.name == "")} unnamed stream(s) identified by content");
        if (named.Count < streams.Count) what.Add($"{streams.Count - named.Count} decoy stream(s) dropped");
        return ((uint)end, "a rebuilt root (" + string.Join(", ", what) + ")", patch);
    }

    /// <summary>Names the streams by their content (keeping names that are still there), or null when a
    /// required stream cannot be identified.</summary>
    static List<(uint off, uint size, string name)>? Name(byte[] b, int m, List<(uint off, uint size, string name)> streams)
    {
        var data = streams.Select(s => b.AsSpan(m + (int)s.off, (int)s.size).ToArray()).ToList();
        Dictionary<string, int> pick = new();
        for (int i = 0; i < streams.Count; i++)
            if (streams[i].name != "") pick.TryAdd(streams[i].name, i);
        bool Free(int i) => streams[i].name == "" && !pick.ContainsValue(i);
        int Best(Func<byte[], bool> ok) => Enumerable.Range(0, streams.Count).Where(i => Free(i) && ok(data[i]))
            .OrderByDescending(i => data[i].Length).DefaultIfEmpty(-1).First();
        void Take(string name, Func<byte[], bool> ok)
        {
            if (pick.ContainsKey(name) || (name == "#~" && pick.ContainsKey("#-"))) return;
            if (Best(ok) is int i and >= 0) pick[name] = i;
        }

        Take("#~", IsTables);
        Take("#Strings", IsStrings);
        Take("#Blob", d => IsHeap(d, us: false) && !IsHeap(d, us: true));
        Take("#Blob", d => IsHeap(d, us: false));
        Take("#US", d => IsHeap(d, us: true));
        if (!pick.ContainsKey("#GUID"))
            for (int i = 0; i < streams.Count; i++) // the first one listed, as the runtime reads it
                if (Free(i) && data[i].Length > 0 && data[i].Length % 16 == 0) { pick["#GUID"] = i; break; }

        if (!pick.ContainsKey("#~") && !pick.ContainsKey("#-") || !pick.ContainsKey("#Strings") || !pick.ContainsKey("#Blob")) return null;
        return pick.OrderBy(kv => streams[kv.Value].off).Select(kv => (streams[kv.Value].off, streams[kv.Value].size, kv.Key)).ToList();
    }

    // #~: reserved 0, schema 1.0 or 2.0, and a valid-table mask that includes Module.
    static bool IsTables(byte[] d) =>
        d.Length >= 24 && BitConverter.ToUInt32(d, 0) == 0 && d[4] is 1 or 2 && d[5] == 0 && (BitConverter.ToUInt64(d, 8) & 1) == 1;

    // #Strings: NUL-terminated UTF-8 identifiers, no control characters.
    static bool IsStrings(byte[] d)
    {
        if (d.Length < 2 || d[0] != 0 || d.Any(c => c is > 0 and < 0x20)) return false;
        try { new UTF8Encoding(false, true).GetString(d); return true; }
        catch (DecoderFallbackException) { return false; }
    }

    // #Blob / #US: a chain of length-prefixed entries that ends exactly at the end of the stream. A #US entry is
    // UTF-16 plus a flag byte (0 or 1), so its length is odd.
    static bool IsHeap(byte[] d, bool us)
    {
        if (d.Length == 0 || d[0] != 0) return false;
        int p = 0;
        while (p < d.Length)
        {
            int n, b0 = d[p];
            if ((b0 & 0x80) == 0) { n = b0; p += 1; }
            else if ((b0 & 0xC0) == 0x80 && p + 1 < d.Length) { n = (b0 & 0x3F) << 8 | d[p + 1]; p += 2; }
            else if ((b0 & 0xE0) == 0xC0 && p + 3 < d.Length) { n = (b0 & 0x1F) << 24 | d[p + 1] << 16 | d[p + 2] << 8 | d[p + 3]; p += 4; }
            else return false;
            if (p + n > d.Length) return false;
            if (us && n > 0 && (n % 2 == 0 || d[p + n - 1] > 1)) return false;
            p += n;
        }
        return true;
    }
}
