// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.IO.Compression;
using System.Text;

namespace DnSpySql;

/// <summary>A file embedded in a .NET single-file bundle.</summary>
/// <param name="Type">0 unknown, 1 assembly, 2 native binary, 3 deps.json, 4 runtimeconfig.json, 5 symbols.</param>
public sealed record BundleEntry(string Path, long Offset, long Size, long CompressedSize, int Type)
{
    public string Kind => Type switch
    {
        1 => "assembly", 2 => "native", 3 => "deps.json", 4 => "runtimeconfig.json", 5 => "symbols", _ => "unknown",
    };
}

/// <summary>The manifest of a single-file bundle: what the app host carries and where.</summary>
public sealed record BundleInfo(string HostPath, int Major, int Minor, string Id, IReadOnlyList<BundleEntry> Entries);

/// <summary>
/// .NET single-file bundles (PublishSingleFile): a native app host (PE on Windows, ELF on Linux, Mach-O on macOS) with
/// the app's assemblies, and for self-contained apps the runtime's, appended. The host carries a fixed signature
/// preceded by the offset of the bundle manifest; entries may be deflate-compressed (.NET 6+).
/// </summary>
public static class Bundle
{
    // SHA-256 of ".net core bundle", which the SDK writes into every bundled app host.
    static readonly byte[] Signature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    /// <summary>The bundle manifest, or null when the file is not a single-file bundle.</summary>
    public static BundleInfo? Read(string hostPath, byte[] b)
    {
        // A self-contained host also carries the runtime's bundle reader, whose copy of the signature is a constant
        // in its code; the marker is the occurrence preceded by a valid manifest offset.
        for (int from = 0; ;)
        {
            int at = b.AsSpan(from).IndexOf(Signature);
            if (at < 0) return null;
            if (ReadAt(hostPath, b, from + at) is { } info) return info;
            from += at + 1;
        }
    }

    static BundleInfo? ReadAt(string hostPath, byte[] b, int sig)
    {
        if (sig < 8) return null;
        long header = BitConverter.ToInt64(b, sig - 8);
        if (header <= 0 || header >= b.Length) return null; // an app host that was not bundled
        try
        {
            using var r = new BinaryReader(new MemoryStream(b, (int)header, b.Length - (int)header), Encoding.UTF8);
            int major = r.ReadInt32(), minor = r.ReadInt32(), count = r.ReadInt32();
            var id = r.ReadString();
            if (major >= 2)
            {
                r.ReadInt64(); r.ReadInt64(); // deps.json offset and size
                r.ReadInt64(); r.ReadInt64(); // runtimeconfig.json offset and size
                r.ReadUInt64();               // flags
            }
            if (count is < 0 or > 100_000) return null;
            var entries = new List<BundleEntry>(count);
            for (int i = 0; i < count; i++)
            {
                long offset = r.ReadInt64(), size = r.ReadInt64(), compressed = major >= 6 ? r.ReadInt64() : 0;
                int type = r.ReadByte();
                var path = r.ReadString();
                // (not offset + size > b.Length: a hostile size overflows that sum)
                if (offset < 0 || size < 0 || compressed < 0 || (compressed > 0 ? compressed : size) > b.Length - offset) return null;
                entries.Add(new BundleEntry(path, offset, size, compressed, type));
            }
            return new BundleInfo(hostPath, major, minor, id, entries);
        }
        // a stray copy of the signature before garbage: ReadString throws FormatException on a bad length prefix and
        // IOException on a negative one, EndOfStreamException (an IOException) past the end
        catch (Exception e) when (e is IOException or FormatException) { return null; }
    }

    /// <summary>The bytes of one entry, inflated when the bundle compressed it.</summary>
    public static byte[] Extract(byte[] b, BundleEntry e)
    {
        if (e.CompressedSize == 0) return b.AsSpan((int)e.Offset, (int)e.Size).ToArray();
        // Deflate expands at most about 1032:1: a larger size is a lie, and allocating it could take gigabytes.
        if (e.Size > Math.Min(Array.MaxLength, e.CompressedSize * 1032 + 1024))
            throw new InvalidDataException($"bundle entry {e.Path} claims {e.Size} bytes from {e.CompressedSize} compressed");
        using var input = new DeflateStream(new MemoryStream(b, (int)e.Offset, (int)e.CompressedSize), CompressionMode.Decompress);
        var output = new byte[e.Size];
        input.ReadExactly(output);
        return output;
    }

    /// <summary>The app's own assembly: the entry named after the host (App.exe / App -> App.dll), else the first assembly.</summary>
    public static BundleEntry? MainAssembly(BundleInfo info)
    {
        var name = System.IO.Path.GetFileNameWithoutExtension(info.HostPath);
        return info.Entries.FirstOrDefault(e => e.Type == 1 && string.Equals(System.IO.Path.GetFileNameWithoutExtension(e.Path), name, StringComparison.OrdinalIgnoreCase))
               ?? info.Entries.FirstOrDefault(e => e.Type == 1);
    }

    /// <summary>Framework assemblies a self-contained bundle carries; the shared framework resolves them anyway.</summary>
    public static bool IsFramework(BundleEntry e)
    {
        var n = System.IO.Path.GetFileName(e.Path);
        return n.StartsWith("System.", StringComparison.OrdinalIgnoreCase) || n.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
               || n is "mscorlib.dll" or "netstandard.dll" or "WindowsBase.dll";
    }
}
