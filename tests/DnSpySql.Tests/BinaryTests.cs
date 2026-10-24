// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection.PortableExecutable;

namespace DnSpySql.Tests;

public sealed class BinaryTests : SampleTest
{
    [Fact]
    public void Version_info_is_read_by_its_structure()
    {
        // the SDK's version resource, with CompanyName renamed (a key no list knows) and FileDescription's value blanked:
        // an empty value is left out instead of pairing its key with the next key's name
        var bytes = File.ReadAllBytes(Sample);
        static byte[] W(string s) => System.Text.Encoding.Unicode.GetBytes(s);
        int company = bytes.AsSpan().IndexOf(W("CompanyName"));
        W("VendorXName").CopyTo(bytes, company);
        int description = bytes.AsSpan().IndexOf(W("FileDescription\0"));
        int value = description + bytes.AsSpan(description).IndexOf(W("Sample\0"));
        Array.Clear(bytes, value, W("Sample").Length);
        var edited = PathIn("Versioned.dll");
        File.WriteAllBytes(edited, bytes);
        var text = Cli.Run(edited, "select text from win32_resources where type = 'VERSION'").Ok().Text();
        Assert.Contains("VendorXName=Sample", text);
        Assert.Contains("FileVersion=1.0.0.0", text);
        Assert.Contains("OriginalFilename=Sample.dll", text);
        Assert.DoesNotContain("FileDescription", text);
        Assert.DoesNotContain("=FileVersion", text);
    }

    [Fact]
    public void An_app_host_names_the_assembly_it_starts()
    {
        // the framework-dependent launcher the SDK builds beside Sample.dll: no .NET code, only the path of the app in a
        // 1025-byte buffer (the path, then zeros), where the SDK's template has a placeholder hash
        var bin = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../corpus/Sample/bin"));
        var built = Directory.GetDirectories(bin).Select(d => Path.Combine(d, "net8.0", OperatingSystem.IsWindows() ? "Sample.exe" : "Sample"))
            .Where(File.Exists).OrderByDescending(File.GetLastWriteTimeUtc).First();
        var bytes = File.ReadAllBytes(built);
        int at = bytes.AsSpan().IndexOf("Sample.dll\0"u8);
        Assert.True(at > 0);
        string Opened(string name, byte[] path)
        {
            var copy = (byte[])bytes.Clone();
            Array.Clear(copy, at, 1025);
            path.CopyTo(copy, at);
            File.WriteAllBytes(PathIn(name), copy);
            return Cli.Run(PathIn(name), "SELECT 1").Error;
        }
        Assert.Contains("it starts Sample.dll,", Opened("host.exe", "Sample.dll"u8.ToArray()));
        // a name that starts like a system DLL's is still the app's, and a path keeps its folders
        Assert.Contains("it starts VersionTool.dll,", Opened("v.exe", "VersionTool.dll"u8.ToArray()));
        Assert.Contains(@"it starts app\Main.dll,", Opened("sub.exe", @"app\Main.dll"u8.ToArray()));
        // the unbound template: no app to name
        Assert.Contains("it starts an assembly beside it", Opened("template.exe", "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"u8.ToArray()));
    }

    [Fact]
    public void A_reference_name_cannot_steer_the_resolver_out_of_its_search_paths()
    {
        // The resolver probes Path.Combine(dir, name + ".dll"): a reference named ..\Probe (or \\host\share\x) would reach
        // outside the search paths. A Probe.dll whose assembly is really named ..\Probe sits one level up, so the old
        // resolver found and accepted it.
        var probe = PathIn("Probe.dll");
        Cli.Run(Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll"), @"select set_assembly('..\Probe')", $"select save({Cli.Sql(probe)})").Ok();
        Directory.CreateDirectory(PathIn("sub"));
        var patched = PathIn(@"sub\Patched.dll");
        Run(@"update asmrefs set name = '..\Probe' where name = 'System.Console'", $"select save({Cli.Sql(patched)})");
        var r = Cli.Run(patched, @"select resolved_path from asmrefs where name = '..\Probe'", "select count(*) from asmrefs where resolved_path is not null").Ok();
        Assert.Equal(System.Text.Json.JsonValueKind.Null, r.Scalar(0).ValueKind);
        Assert.True(r.Long(1) > 0); // plain names still resolve
    }

    [Fact]
    public void A_decoded_blob_opens_as_a_module_of_its_own()
    {
        // an assembly stored gzip-compressed: decoded with SQL and opened from the blob
        using var ms = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll")));
        using var live = new Live(Sample, "--no-project");
        var id = live.Long($"select open_bytes(decompress(x'{Convert.ToHexString(ms.ToArray())}'), 'decoded.dll')");
        Assert.Equal(2, id);
        Assert.Equal("decoded.dll", live.Scalar("select path from modules where id = 2"));
        Assert.True(live.Long("select count(*) from types where module = 2") > 5);
        Assert.Contains("class MemberCard", (string)live.Scalar("select decompile(handle) from types where module = 2 and name = 'MemberCard'")!);
        Assert.Contains("not a .NET assembly", live.Error("select open_bytes(x'4D5A0000')"));
        Assert.Null(live.Scalar("select open_bytes(decompress(x'0102'))")); // the decode step failed: NULL, not an error
        Assert.Contains("already open with other bytes", live.Error($"select open_bytes(x'{Convert.ToHexString(File.ReadAllBytes(Sample))}', 'decoded.dll')"));
    }

    [Fact]
    public void A_renamed_sample_finds_the_pdb_its_debug_directory_names()
    {
        // Renamed.dll's debug directory still names Sample.pdb: it is found next to the file, not in the current directory.
        var renamed = PathIn("Renamed.dll");
        File.Copy(Sample, renamed);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample", "Sample.pdb"), PathIn("Sample.pdb"));
        var r = Cli.Run(renamed, "select has_pdb from modules", "select count(*) from pdb_documents").Ok();
        Assert.Equal(1, r.Long(0));
        Assert.True(r.Long(1) > 0);
    }

    [Fact]
    public void Reports_no_overlay_on_a_compiler_built_file()
    {
        var r = Run("select overlay, overlay_size, overlay_offset from modules").Rows()[0];
        Assert.Equal(System.Text.Json.JsonValueKind.Null, r.GetProperty("overlay").ValueKind);
        Assert.Equal(0, r.GetProperty("overlay_size").GetInt64());
    }

    [Fact]
    public void Reports_appended_data_and_reads_it_back()
    {
        // Data after the last section: random bytes, then a copy of the file.
        var bytes = File.ReadAllBytes(Sample);
        var junk = new byte[1000];
        new Random(1).NextBytes(junk);
        File.WriteAllBytes(Sample, [.. bytes, .. junk, .. bytes]);
        var r = Run("select overlay, overlay_offset, overlay_size, overlay_kind, overlay_pe_offset, overlay_padding from modules",
                    "select hex(read_bytes(overlay_pe_offset, 2)) from modules",
                    "select length(read_bytes(overlay_offset, overlay_size)) from modules");
        var o = r.Rows(0)[0];
        Assert.Equal(bytes.Length, o.GetProperty("overlay_offset").GetInt64());
        Assert.Equal(bytes.Length + junk.Length, o.GetProperty("overlay_size").GetInt64());
        Assert.Equal(bytes.Length + junk.Length, o.GetProperty("overlay_pe_offset").GetInt64());
        Assert.Equal("data", o.GetProperty("overlay_kind").GetString()); // random bytes, then a mostly-zero PE
        Assert.Contains("embedded PE at 0x", o.GetProperty("overlay").GetString());
        Assert.Equal("4D5A", r.Text(1));
        Assert.Equal(bytes.Length + junk.Length, r.Long(2));
    }

    [Fact]
    public void Classifies_high_entropy_appended_data()
    {
        var data = new byte[64 << 10];
        new Random(2).NextBytes(data);
        File.WriteAllBytes(Sample, [.. File.ReadAllBytes(Sample), .. data]);
        var o = Run("select overlay_kind, overlay_entropy, overlay_pe_offset from modules").Rows()[0];
        Assert.Equal("encrypted or compressed data", o.GetProperty("overlay_kind").GetString());
        Assert.True(o.GetProperty("overlay_entropy").GetDouble() > 7.9);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, o.GetProperty("overlay_pe_offset").ValueKind);
    }

    [Fact]
    public void Separates_trailing_zero_padding()
    {
        var bytes = File.ReadAllBytes(Sample);
        File.WriteAllBytes(Sample, [.. bytes, .. "appended text"u8.ToArray(), .. new byte[2 << 20]]);
        var o = Run("select overlay, overlay_kind, overlay_padding from modules").Rows()[0];
        Assert.Equal("text", o.GetProperty("overlay_kind").GetString());
        Assert.Equal(2 << 20, o.GetProperty("overlay_padding").GetInt64());
        Assert.Contains("of zero padding (inflates the file", o.GetProperty("overlay").GetString());
    }

    [Fact]
    public void Read_bytes_rejects_ranges_outside_the_file()
    {
        var r = Cli.Run(Sample, "select read_bytes(0, 999999999)");
        Assert.NotEqual(0, r.Exit);
        Assert.Contains("outside the file", r.Error);
        Assert.Equal("4D5A", Run("select hex(read_bytes(0, 2))").Text());
    }

    static int CliHeaderOffset(byte[] bytes)
    {
        using var pe = new PEReader(new MemoryStream(bytes));
        pe.PEHeaders.TryGetDirectoryOffset(pe.PEHeaders.PEHeader!.CorHeaderTableDirectory, out var at);
        return at;
    }

    [Fact]
    public void Rebuilds_a_destroyed_cli_header()
    {
        var bytes = File.ReadAllBytes(Sample);
        int at = CliHeaderOffset(bytes);
        for (int i = 0; i < 72; i++) bytes[at + i] = (byte)(0xA5 ^ i);
        File.WriteAllBytes(Sample, bytes);
        var r = Run("select repair from modules", "select decompile(token) from types where name = 'MemberCard'",
                    "select hex(read_bytes(" + at + ", 1)) from modules");
        Assert.Contains("CLI header", r.Text(0));
        Assert.Contains("class MemberCard", r.Text(1));
        Assert.Equal("A5", r.Text(2)); // read_bytes shows the file as it is on disk, not the repair
    }

    [Fact]
    public void Rebuilds_a_wiped_metadata_root()
    {
        File.WriteAllBytes(Sample, WipeRoot(File.ReadAllBytes(Sample)));
        var r = Run("select repair from modules", "select count(*) from methods where name = 'IsValid'");
        Assert.Contains("rebuilt root", r.Text(0));
        Assert.Equal(1, r.Long(1));
    }

    [Fact]
    public void A_bogus_metadata_root_does_not_stop_the_repair()
    {
        // A "BSJB" in a method body whose stream offset + size wraps around 4 GB and which has a stream without a name:
        // the repair reads past it and finds the real root.
        var body = Run("select file_offset from method_bodies where size >= 48 order by file_offset limit 1").Long();
        var bytes = WipeRoot(File.ReadAllBytes(Sample));
        byte[] bogus = [.. "BSJB"u8, 1, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, .. "v4.0"u8, 0, 0, 2, 0,
                        0x40, 0, 0, 0, 0xF0, 0xFF, 0xFF, 0xFF, .. "#~\0\0"u8,
                        0x40, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0];
        bogus.CopyTo(bytes, body);
        File.WriteAllBytes(Sample, bytes);
        var r = Run("select repair from modules", "select count(*) from methods where name = 'IsValid'");
        Assert.Contains("rebuilt root", r.Text(0));
        Assert.Equal(1, r.Long(1));
    }

    // The CLI header, the "BSJB" signature and every stream name zeroed in the file.
    static byte[] WipeRoot(byte[] bytes)
    {
        int at = CliHeaderOffset(bytes);
        int root;
        using (var pe = new PEReader(new MemoryStream(bytes)))
        {
            pe.PEHeaders.TryGetDirectoryOffset(pe.PEHeaders.CorHeader!.MetadataDirectory, out root);
        }
        Array.Clear(bytes, at, 72);
        Array.Clear(bytes, root, 4); // BSJB
        int versionLength = BitConverter.ToInt32(bytes, root + 12);
        int p = root + 16 + versionLength + 4; // stream headers
        int streams = BitConverter.ToUInt16(bytes, root + 16 + versionLength + 2);
        for (int i = 0; i < streams; i++)
        {
            p += 8;
            int name = p;
            while (bytes[p] != 0) p++;
            p = (p + 4) & ~3;
            Array.Clear(bytes, name, p - name);
        }
        return bytes;
    }

    [Fact]
    public void A_stray_bundle_marker_does_not_stop_the_load()
    {
        // The single-file bundle signature after a manifest that does not parse (a string length that never ends; an
        // entry with a negative size): the file is an assembly with an overlay, not a bundle.
        byte[] signature = [0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
                            0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae];
        var sample = File.ReadAllBytes(Sample);
        byte[][] manifests =
        [
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 1, (byte)'a'],
        ];
        for (int i = 0; i < manifests.Length; i++)
        {
            var path = PathIn($"Marked{i}.dll");
            File.WriteAllBytes(path, [.. sample, .. manifests[i], .. BitConverter.GetBytes((long)sample.Length), .. signature]);
            Assert.Equal(1, Cli.Run(path, "select count(*) from methods where name = 'IsValid'").Ok().Long());
        }
    }

    [Fact]
    public void Rva_to_offset_has_no_offset_for_zero_filled_memory()
    {
        // .reloc made larger in memory than in the file: the part past its raw data is zero-filled, not file bytes.
        var r = Run("select offset from pe_fields where field = '.reloc.VirtualSize'", "select virtual_address, raw_size from pe_sections where name = '.reloc'");
        var bytes = File.ReadAllBytes(Sample);
        BitConverter.GetBytes(0x2000).CopyTo(bytes, r.Long(0));
        File.WriteAllBytes(Sample, bytes);
        long va = r.Values(1)[0].GetInt64(), raw = r.Values(1)[1].GetInt64();
        var t = Run($"select rva_to_offset({va + raw - 1}) is not null, rva_to_offset({va + raw + 16}) is null").Values();
        Assert.Equal(new[] { 1L, 1L }, t.Select(v => v.GetInt64()));
    }

    [Fact]
    public void Pdb_path_ends_with_its_debug_entry()
    {
        var r = Run("select file_offset, size, pdb_path from debug_directories where pdb_path is not null").Values();
        long at = r[0].GetInt64(), size = r[1].GetInt64();
        var bytes = File.ReadAllBytes(Sample);
        bytes[at + size - 1] = (byte)'X'; // the path's NUL
        for (int i = 0; i < 4; i++) bytes[at + size + i] = (byte)'Y';
        File.WriteAllBytes(Sample, bytes);
        Assert.Equal(r[2].GetString() + "X", Run("select pdb_path from debug_directories where pdb_path is not null").Text());
    }

    [Fact]
    public void Throw_sites_survive_a_member_reference_without_a_parent()
    {
        var target = PathIn("SampleTarget.dll");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll"), target);
        var cell = Cli.Run(target, "select offset, size from md_rows where table_name = 'MemberRef' and column = 'Class' and rid = " +
            "(select i.operand_token & 0xFFFFFF from throw_sites t join il i on i.method = t.method and i.offset < t.offset where i.opcode = 'newobj')").Ok().Values();
        var bytes = File.ReadAllBytes(target);
        Array.Clear(bytes, (int)cell[0].GetInt64(), (int)cell[1].GetInt64()); // the exception constructor's parent: none
        File.WriteAllBytes(target, bytes);
        Assert.Equal("(unknown)", Cli.Run(target, "select exception_type from throw_sites").Ok().Text());
    }

    [Fact]
    public void Opens_a_single_file_bundle()
    {
        // dotnet publish -p:PublishSingleFile=true: a native app host (ELF here, PE on Windows) with the assemblies inside.
        var project = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../corpus/Sample/Sample.csproj"));
        var outDir = PathIn("single");
        var rid = (OperatingSystem.IsWindows() ? "win-" : OperatingSystem.IsMacOS() ? "osx-" : "linux-")
                  + (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64");
        var psi = new System.Diagnostics.ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "publish", project, "-c", "Release", "-r", rid, "--self-contained", "false", "-p:PublishSingleFile=true", "-o", outDir, "--nologo", "-v", "q" })
            psi.ArgumentList.Add(a);
        using (var p = System.Diagnostics.Process.Start(psi)!)
        {
            _ = p.StandardError.ReadToEndAsync();
            _ = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, "dotnet publish -p:PublishSingleFile=true failed");
        }
        var host = Path.Combine(outDir, OperatingSystem.IsWindows() ? "Sample.exe" : "Sample");
        var r = Cli.Run(host, "SELECT path FROM modules", "SELECT group_concat(kind) FROM bundle_entries",
                        "SELECT decompile(resolve('Sample.MemberCard::IsValid'))").Ok();
        Assert.EndsWith("!/Sample.dll", r.Text(0));
        Assert.Contains("deps.json", r.Text(1));
        Assert.Contains("MemberCard.Checksum", r.Text(2));
    }
}
