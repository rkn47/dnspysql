// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql.Tables;

/// <summary>
/// Which protector touched a module and with which techniques, and where its strings get decrypted: the first
/// questions an analyst asks of an obfuscated sample, which decide whether to read the code, trace it in dnSpy, or
/// look for the unpacked payload. Every finding carries its evidence; nothing here runs code.
/// </summary>
public static class ProtectionTables
{
    public sealed record Finding(LoadedModule M, string Name, string Kind, string Confidence, string Evidence, long? Handle = null);

    public sealed record Decryptor(LoadedModule M, MethodDef Method, int Sites, int Callers, int ConstantSites, IReadOnlyList<string> Samples)
    {
        public double ConstantRatio => Sites == 0 ? 0 : (double)ConstantSites / Sites;
        // Many call sites with literal arguments: the shape of a string decryptor (one encrypted literal per site).
        public double Score => Math.Round(ConstantSites * (0.5 + 0.5 * ConstantRatio), 1);
    }

    // Marker types protectors add (attribute or helper type): expected namespace, product, kind.
    static readonly (string Name, string? Namespace, string Product, string Kind)[] Markers =
    [
        ("ConfusedByAttribute", "", "ConfuserEx", "obfuscator"),
        ("PoweredByAttribute", "SmartAssembly.Attributes", "SmartAssembly", "obfuscator"),
        ("BabelAttribute", "", "Babel Obfuscator", "obfuscator"),
        ("BabelObfuscatorAttribute", "", "Babel Obfuscator", "obfuscator"),
        ("DotfuscatorAttribute", "", "Dotfuscator", "obfuscator"),
        ("ObfuscatedByGoliath", "", "Goliath .NET", "obfuscator"),
        ("CryptoObfuscatorAttribute", null, "Crypto Obfuscator", "obfuscator"),
        ("<AgileDotNetRT>", "", "Agile.NET (CliSecure)", "obfuscator"),
        ("AgileDotNetRT", null, "Agile.NET (CliSecure)", "obfuscator"),
        ("AssemblyLoader", "Costura", "Costura (Fody)", "embedded assemblies"),
    ];

    static readonly string[] AntiDebugImports = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess",
        "NtSetInformationThread", "ZwSetInformationThread", "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW"];
    static readonly string[] AntiVmStrings = ["vmware", "virtualbox", "vbox", "qemu", "sbiedll", "sandboxie", "wine_get_unix_file_name",
        "xen", "hyper-v", "win32_computersystem", "select * from win32_videocontroller", "cuckoo", "anyrun", "wireshark", "procmon", "dnspy", "x64dbg", "ollydbg"];

    public static void Register(Session s)
    {
        // ---- embedded_pes: every PE a module carries -----------------------------------------------------------------
        s.Db.Register(new Table<Carved>("embedded_pes",
                "PE files inside a module: anywhere in its file bytes (the overlay, uncompressed resources, a section) and in " +
                "resources or .resources entries, also behind gzip/zlib/deflate, and one stored in pieces across numbered resources " +
                "(part1..partN: joined in order or reversed, also as base64 text). Size from the PE headers; " +
                "SELECT open_bytes(data) FROM embedded_pes WHERE is_dotnet opens each next stage") { Domain = "triage" }
            .Source(c => s.Ws.Modules(c).SelectMany(Carve))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("location", r => r.Location, doc: "overlay | section .text (or another) | resource 'name' | element 'name' of resource 'name', with ' (gzip)' etc. when inflated")
            .Int("offset", r => r.Offset, doc: "file offset (file bytes), or offset in the resource or the inflated bytes")
            .Int("size", r => r.Size, doc: "from the section table (and the certificate), clipped to the bytes there are")
            .Bool("is_dotnet", r => Workspace.NotDotNet(r.Slice()[..Math.Min(r.Slice().Length, 4096)].ToArray()) == null) // the headers say
            .Text("machine", r => Enum.GetName(typeof(dnlib.PE.Machine), r.Machine) ?? $"0x{r.Machine:X}")
            .Text("kind", r => r.IsDll ? "dll" : "exe")
            .Text("sha256", r => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(r.Slice())).ToLowerInvariant())
            .Blob("data", r => r.Slice().ToArray(), doc: "the PE's bytes (open_bytes(data) opens a .NET one)")
            .Int("parent_offset", r => r.Parent,
                doc: "file offset of the row whose PE contains this one (a payload inside a payload, in the file bytes); NULL when not nested, " +
                     "so WHERE parent_offset IS NULL counts each top-level PE once")
            .Estimate(5, 50));

        // ---- carve_file: the same for a file that is not a module ------------------------------------------------------
        s.Db.Register(new Table<FileCarve>("carve_file",
                "PE files in any file's bytes, the file itself included: WHERE path = '...'. For a file open() refuses (a native " +
                "dropper or loader) that may carry an encrypted or plain .NET payload; SELECT open_bytes(data) FROM carve_file " +
                "WHERE path = '...' AND is_dotnet opens one. The file is only read") { Domain = "triage" }
            .Source(c => c.Text("path") is { } path ? CarveFile(path) : [])
            .Text("location", r => r.Location, doc: "the file (offset 0) | inside the file's image | overlay (after the image the headers describe) | file bytes")
            .Int("offset", r => r.Offset, doc: "file offset")
            .Int("size", r => r.Size, doc: "from the section table (and the certificate), clipped to the bytes there are")
            .Bool("is_dotnet", r => Workspace.NotDotNet(r.Slice()[..Math.Min(r.Slice().Length, 4096)].ToArray()) == null)
            .Text("machine", r => Enum.GetName(typeof(dnlib.PE.Machine), r.Machine) ?? $"0x{r.Machine:X}")
            .Text("kind", r => r.IsDll ? "dll" : "exe")
            .Text("sha256", r => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(r.Slice())).ToLowerInvariant())
            .Blob("data", r => r.Slice().ToArray(), doc: "the PE's bytes")
            .Int("parent_offset", r => r.Parent, doc: "offset of the row whose PE contains this one; NULL when none does")
            .Arg("path", SqlType.Text, r => r.Path, doc: "the file to read")
            .Estimate(5, 1));

        var ws = s.Ws;
        s.Db.Register(new Table<Finding>("protections",
                "Protectors, packers and protection techniques detected in each module, with the evidence: ConfuserEx, SmartAssembly, " +
                "Babel, Dotfuscator, Agile.NET, ... (decoy markers flagged), name obfuscation, anti-tamper, anti-debug, anti-VM, " +
                "string encryption, control-flow flattening, proxy calls, encrypted or embedded resources") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Detect(s, m)))
            .Int("module", f => f.M.Id, pushdown: Pushdown.Eq)
            .Text("name", f => f.Name, doc: "product (ConfuserEx, SmartAssembly, ...) or technique")
            .Text("kind", f => f.Kind, doc: "obfuscator | embedded assemblies | decoy marker | name obfuscation | anti-tamper | anti-debug | anti-vm | " +
                                          "string encryption | control flow | proxy calls | virtualization | constant obfuscation | encrypted resources | " +
                                          "embedded executable | stub assembly (no method body: the code is elsewhere) | mixed mode")
            .Text("confidence", f => f.Confidence, doc: "high | medium | low | decoy")
            .Text("evidence", f => f.Evidence)
            .Int("handle", f => f.Handle, doc: "the type or method the evidence points at, when there is one")
            .Estimate(20, 50));

        s.Db.Register(new Table<Decryptor>("string_decryptors",
                "Methods shaped like a string decryptor: static, return a string (or object, or a generic T), take literal arguments " +
                "(constants, strings, null, or calls to getters that return a constant) at many call sites. Ranked " +
                "by score; trace one in dnSpy (bp_trace on the callers' next instruction, or on its ret) to see the plaintext") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Decryptors(s, m, (int)(c.Long("min_sites") ?? 5),
                double.TryParse(c.Text("min_literal_share"), System.Globalization.CultureInfo.InvariantCulture, out var share) ? share : 0.5)))
            .Int("module", d => d.M.Id, pushdown: Pushdown.Eq)
            .Int("method", d => d.M.H(d.Method))
            .Text("method_name", d => d.Method.FullName)
            .Int("call_sites", d => d.Sites)
            .Int("callers", d => d.Callers, doc: "distinct calling methods")
            .Int("constant_sites", d => d.ConstantSites, doc: "call sites whose arguments are all literals")
            .Real("score", d => d.Score, doc: "literal call sites weighted by their share of all call sites")
            .Text("sample_args", d => string.Join("; ", d.Samples), doc: "a few literal arguments from call sites")
            .Bool("is_library", d => TriageTables.IsLibrary(d.Method), doc: "the method belongs to a well-known library namespace")
            .Arg("min_sites", SqlType.Integer, _ => null, required: false, doc: "minimum call sites (default 5)")
            .Arg("min_literal_share", SqlType.Real, _ => null, required: false, doc: "minimum share of call sites with literal arguments (default 0.5; 0 lists every candidate)")
            .Estimate(20, 50));

        s.Db.Register(new Table<DecryptorCall>("decryptor_calls",
                "Every call of a string decryptor (string_decryptors, or the method given as decryptor = handle) with literal " +
                "arguments, or static fields whose value is known: what each site decrypts, and where to break in dnSpy to see the " +
                "plaintext (bp_set(caller, offset))") { Domain = "triage" }
            .Source(c => ws.Modules(c).SelectMany(m => Calls(s, m, c.Long("decryptor"), (int)(c.Long("min_sites") ?? 5))))
            .Int("module", d => d.M.Id, pushdown: Pushdown.Eq)
            .Int("decryptor", d => d.M.H(d.Decryptor), pushdown: Pushdown.Eq, doc: "the decryptor method; WHERE decryptor = handle takes any method")
            .Text("decryptor_name", d => d.Decryptor.FullName)
            .Int("caller", d => d.Site.FromHandle)
            .Text("caller_name", d => d.Site.From.FullName)
            .Int("offset", d => d.Site.Offset, doc: "IL offset of the call")
            .Text("args", d => string.Join(", ", d.Args.Select(a => a.Text)))
            .Col("arg0", SqlType.Any, d => d.Args.Count > 0 ? d.Args[0].Value : null)
            .Col("arg1", SqlType.Any, d => d.Args.Count > 1 ? d.Args[1].Value : null)
            .Col("arg2", SqlType.Any, d => d.Args.Count > 2 ? d.Args[2].Value : null)
            .Col("arg3", SqlType.Any, d => d.Args.Count > 3 ? d.Args[3].Value : null)
            .Col("plaintext", SqlType.Any, d => d.Plain.Value.Value,
                doc: "what the call returns, computed by interpreting the decryptor's IL (the sample is never run); NULL when it cannot be")
            .Text("emulation", d => d.Plain.Value.Status, doc: "ok, or why the decryptor could not be interpreted")
            .Text("plaintext_kind", d => TriageTables.ValueKind(d.Plain.Value.Value),
                doc: "text | base64 text | ciphertext (base64 of bytes that are not text: a second layer, decrypted by another method) | binary")
            .Text("args_from", d => d.Args.Any(a => a.FromField) ? "field" : "literal",
                doc: "literal, or field: an argument is a static field's value (a literal it holds, a decoder's result from decoded_fields, " +
                     "or what a decryptor computed into it)")
            .Bool("is_library", d => TriageTables.IsLibrary(d.Decryptor), doc: "the decryptor belongs to a well-known library namespace")
            .Arg("min_sites", SqlType.Integer, _ => null, required: false, doc: "minimum call sites of a decryptor (default 5)")
            .Estimate(500, 50));
    }

    // ---- protections ---------------------------------------------------------------------------------------------------

    internal static IEnumerable<Finding> Detect(Session s, LoadedModule m)
    {
        var md = m.Module;
        var found = new List<Finding>();
        var types = md.GetTypes().ToList();

        // marker types, defined here or referenced
        var markerTypes = types.Select(t => (ns: t.Namespace.String, name: t.Name.String, h: (long?)m.H(t)))
            .Concat(md.GetTypeRefs().Select(t => (ns: t.Namespace.String, name: t.Name.String, h: (long?)null)));
        foreach (var (ns, name, h) in markerTypes)
            foreach (var mk in Markers.Where(x => x.Name == name))
            {
                bool expected = mk.Namespace == null || ns == mk.Namespace;
                found.Add(expected
                    ? new Finding(m, mk.Product, mk.Kind, "high", $"marker type {(ns.Length > 0 ? ns + "." : "")}{name}", h)
                    : new Finding(m, mk.Product, "decoy marker", "decoy",
                        $"{name} is defined in namespace '{ns}', not where {mk.Product} puts it: planted to mislead identification tools", h));
            }
        foreach (var t in types.Where(t => t.Namespace.StartsWith("SmartAssembly.", StringComparison.Ordinal) && t.Namespace != "SmartAssembly.Attributes"))
        {
            found.Add(new Finding(m, "SmartAssembly", "obfuscator", "high", $"SmartAssembly runtime type {t.FullName}", m.H(t)));
            break;
        }
        // Several products' markers in one module: at most one is real, and protectors plant the others to mislead
        // identification tools. The namespace the planted markers share often names the real one (SugarGuard does this).
        var products = found.Where(f => f.Kind == "obfuscator").Select(f => f.Name).Distinct().ToList();
        if (products.Count > 1)
        {
            found = found.Select(f => f.Kind == "obfuscator" ? f with { Confidence = "medium" } : f).ToList();
            found.Add(new Finding(m, "conflicting markers", "decoy marker", "medium",
                $"markers of {string.Join(", ", products)} in one module: stacked protectors, or decoys planted to mislead identification"));
        }
        // (not the application's own namespace: the one most of its types live in)
        var home = types.GroupBy(t => t.Namespace.String).MaxBy(g => g.Count())?.Key;
        foreach (var ns in markerTypes.Where(x => x.h != null && Markers.Any(mk => mk.Name == x.name && mk.Namespace != null && mk.Namespace != x.ns))
                     .Select(x => x.ns).Where(n => n.Length > 0 && n != home).Distinct())
            found.Add(new Finding(m, ns, "obfuscator", "low", $"the decoy markers are defined in namespace '{ns}', which may name the real protector"));

        // name obfuscation: invisible characters, letters from scripts C# identifiers are rarely written in (Georgian,
        // Hiragana, ...), or ASCII gibberish (xDWYusSMnb). Compiler-generated and special names are left out.
        var names = types.SelectMany(t => new[] { t.Name.String }.Concat(t.Methods.Where(x => !x.IsSpecialName && !x.IsConstructor).Select(x => x.Name.String))
                                                                 .Concat(t.Fields.Select(x => x.Name.String)))
            .Where(n => n.Length > 0 && !n.Contains('<')).ToList();
        int hidden = names.Count(n => Output.Visible(n) != n);
        int foreign = names.Count(n => Output.Visible(n) == n && n.Any(ch => ch > 0x7F && char.IsLetter(ch)));
        // zalgo: letters buried under combining marks
        int zalgo = names.Count(n => n.Count(ch => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) == System.Globalization.UnicodeCategory.NonSpacingMark) >= 3);
        int gibberish = names.Count(Gibberish);
        if (names.Count >= 10 && zalgo * 10 >= names.Count * 3)
            found.Add(new Finding(m, "name obfuscation", "name obfuscation", "high", $"{zalgo} of {names.Count} names are buried under combining marks (zalgo)"));
        else if (hidden >= 10)
            found.Add(new Finding(m, "name obfuscation", "name obfuscation", "high", $"{hidden} of {names.Count} names contain invisible, bidi or private-use characters"));
        else if (names.Count >= 10 && foreign * 10 >= names.Count * 3)
            // medium: an application written in another language has such names too
            found.Add(new Finding(m, "name obfuscation", "name obfuscation", "medium", $"{foreign} of {names.Count} names use letters outside ASCII"));
        else if (names.Count >= 20 && gibberish * 10 >= names.Count * 3)
            found.Add(new Finding(m, "name obfuscation", "name obfuscation", "medium", $"{gibberish} of {names.Count} names look random (no word structure)"));

        // anti-tamper: bodies decrypted at startup
        // (a C++/CLI method's native code is not an IL body)
        var bodies = HexTables.Bodies(m).Where(b => b.Format != "native").ToList();
        // bodies that are in the file and do not decode (one past the end of a truncated file is damage, not protection)
        var bad = bodies.Where(b => b.IlStatus != "ok" && b.FileOffset >= 0 && b.FileOffset < m.OriginalBytes.Length).ToList();
        int invalid = bad.Count;
        bool virtualProtect = md.GlobalType?.Methods.Any(x => x.ImplMap?.Name.String is "VirtualProtect") == true;
        if (virtualProtect || invalid >= 5)
        {
            // what to do about it depends on how the bodies are hidden: zeroed bytes are filled in at runtime, and
            // untamper() interprets one kind of startup routine only (GetHINSTANCE + VirtualProtect)
            int zeroed = bad.Count(b => Zeroed(m.OriginalBytes, b.FileOffset));
            var (needed, have) = PeTables.Truncated(m);
            string? advice = invalid == 0 ? null
                : m.Origin == "untamper" ? $"left encrypted by the routine untamper() ran on module {m.DerivedFrom}: another routine of that module " +
                                           $"(untamper({m.DerivedFrom}, name, initializer)) or a memory dump has them; running it again here would decrypt the decrypted ones twice"
                : needed > have ? $"the file is truncated ({have:N0} of {needed:N0} bytes): damage, not protection; a complete copy has them"
                : zeroed * 2 > invalid ? "zero-filled in the file: written at runtime, so only a memory dump of the running process has them (open it with open_bytes)"
                : Functions.CoreFunctions.AntiTamperInitializer(s, m) is { } init
                    ? $"encrypted until runtime: SELECT untamper() can decrypt them statically, by interpreting 0x{init.MDToken.Raw:X8}"
                    : "encrypted until runtime, by a scheme untamper() does not model (no static method uses GetHINSTANCE and VirtualProtect; a JIT hook, say): a memory dump has them";
            found.Add(new Finding(m, "anti-tamper", "anti-tamper", virtualProtect && invalid > 0 ? "high" : "medium",
                string.Join("; ", new[]
                {
                    virtualProtect ? "<Module> P/Invokes VirtualProtect" : null,
                    invalid > 0 ? $"{invalid} of {bodies.Count} method bodies do not parse as IL ({advice})"
                    : m.Origin == "untamper" ? $"this is the decrypted copy of module {m.DerivedFrom} (untamper()): every method body parses as IL"
                    : "every method body parses as IL: nothing is encrypted in the file, untamper() has nothing to do",
                }.Where(x => x != null))));
        }

        // anti-debug and anti-VM
        var ix = s.Index;
        // only P/Invokes something calls: a declared import nobody uses is dead code, often from a copied snippet
        var imports = types.SelectMany(t => t.Methods).Where(x => x.ImplMap != null && ix.To(m.H(x)).Any(r => r.IsCall))
            .Select(x => x.ImplMap!.Name.String).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var callees = ix.All.Where(x => x.M == m && x.IsCall).Select(x => x.ToName).ToHashSet(StringComparer.Ordinal);
        var debugSigns = AntiDebugImports.Where(imports.Contains)
            .Concat(callees.Where(n => n.Contains("System.Diagnostics.Debugger::get_IsAttached") || n.Contains("System.Diagnostics.Debugger::IsLogging")
                                       ).Select(n => n.Split("::")[^1].Split('(')[0]))
            .Distinct().ToList();
        if (debugSigns.Count > 0)
            found.Add(new Finding(m, "anti-debug", "anti-debug", debugSigns.Count > 1 ? "high" : "medium", "uses " + string.Join(", ", debugSigns) +
                " (dnSpy's anti-anti-debug options: dnspy_debugger_settings)"));
        // whole words in readable strings: "xen" inside base64 ciphertext is not a check for Xen
        var strings = ix.All.Where(x => x.M == m && x.StringValue != null).Select(x => x.StringValue!).Distinct()
            .Where(x => !LooksEncoded(x)).Select(x => x.ToLowerInvariant()).ToList();
        var vm = AntiVmStrings.Where(v => strings.Any(x => ContainsWord(x, v))).ToList();
        if (vm.Count >= 2)
            found.Add(new Finding(m, "anti-vm / anti-analysis", "anti-vm", vm.Count >= 4 ? "high" : "medium", "strings mention " + string.Join(", ", vm)));

        // string encryption
        var dec = Decryptors(s, m, 20).FirstOrDefault(d => !TriageTables.IsLibrary(d.Method));
        if (dec != null && dec.ConstantRatio >= 0.5)
            found.Add(new Finding(m, "string encryption", "string encryption", dec.Sites >= 50 ? "high" : "medium",
                $"{dec.Method.FullName} is called from {dec.Sites} sites, {dec.ConstantSites} with literal arguments (string_decryptors)", m.H(dec.Method)));

        // control-flow flattening (a switch dispatcher inside a loop) and proxy calls (tiny static thunks that only forward
        // to another method), both relative to the module: large libraries have dozens of legitimate loop-and-switch
        // parsers and forwarding overloads
        int flattened = 0, large = 0, thunks = 0, bodied = 0, folded = 0, foldedIn = 0;
        foreach (var meth in types.SelectMany(t => t.Methods))
        {
            if (!TryBody(meth, out var ins)) continue;
            bodied++;
            if (IsThunk(meth)) thunks++;
            if (ConstantArithmetic(ins) is var n and > 0) { folded += n; foldedIn++; }
            if (ins.Count < 20) continue;
            large++;
            if (Flattened(ins)) flattened++;
        }
        if (flattened >= 3 && flattened * 20 >= large)
            found.Add(new Finding(m, "control-flow flattening", "control flow", flattened * 8 >= large ? "high" : "medium",
                $"{flattened} of {large} methods (of 20+ instructions) dispatch through a switch inside a loop"));
        if (thunks >= 20 && thunks * 20 >= bodied)
            found.Add(new Finding(m, "proxy calls", "proxy calls", thunks * 5 >= bodied ? "high" : "medium",
                $"{thunks} of {bodied} methods are static thunks that only forward their arguments to another method"));
        // IL virtualization: methods whose whole body hands an id and its arguments to one dispatcher, which runs bytecode
        foreach (var virt in Virtualization(m))
            found.Add(new Finding(m, VmName(virt.Dispatcher), "virtualization", virt.HandlerLoop ? "high" : "medium",
                $"{virt.Stubs.Count} of {bodied} methods forward their arguments to {virt.Dispatcher.FullName} with an id: their code runs in an IL " +
                "virtual machine, and decompile() shows only the forwarding" + (virt.HandlerLoop ? " (it dispatches through a switch of 50 or more handlers in a loop)" : ""),
                m.H(virt.Dispatcher)));
        // a metadata shell: types and maybe resources, but no method body; the code is somewhere else (an encrypted
        // section, a carried assembly)
        if (bodies.Count == 0 && (md.Resources.Count > 0 || md.ManagedEntryPoint != null || HighEntropySection(m).Name != null))
        {
            var largest = Carve(m).Where(c => Workspace.NotDotNet(c.Slice()[..Math.Min(c.Slice().Length, 4096)].ToArray()) == null).MaxBy(c => c.Size);
            var section = HighEntropySection(m);
            found.Add(new Finding(m, "stub assembly", "stub assembly", "high", string.Join("; ", new[]
            {
                $"no code in this assembly ({types.Count} types, {md.Metadata.TablesStream.MethodTable.Rows} methods, none with a body): its code is elsewhere",
                largest != null ? $"the largest .NET PE it carries is in {largest.Location} ({largest.Size:N0} bytes)" : null,
                section is var (name, size, entropy) && name != null ? $"section {name} is {size:N0} bytes of entropy {entropy:F2}" : null,
            }.Where(x => x != null))));
        }
        // constants written as arithmetic on other constants ((14861 + 79295) ^ 94152): compilers fold those, so many
        // of them were put there; a few are hand-written bit masks
        if (folded >= 40)
            found.Add(new Finding(m, "constant obfuscation", "constant obfuscation", folded >= 200 ? "high" : "medium",
                $"{folded} arithmetic operations on two constants in {foldedIn} methods (a compiler folds them: an obfuscator wrote them)"));
        // resources kept in another assembly that the module does not ship: a resolve handler supplies it at runtime,
        // usually decrypted from a blob of its own
        var linked = md.Resources.OfType<AssemblyLinkedResource>().Where(r => !md.Resources.OfType<EmbeddedResource>().Any(e => e.Name == r.Name)).ToList();
        if (linked.Count > 0)
            found.Add(new Finding(m, "resources in another assembly", "encrypted resources", "medium",
                $"{linked.Count} resource(s) live in {string.Join(", ", linked.Select(r => r.Assembly.Name.String).Distinct().Take(3))}, " +
                "which the module does not contain: an AssemblyResolve or ResourceResolve handler supplies it at runtime"));

        // payloads: manifest resources, the byte[] and stream entries of .resources files, and the overlay
        foreach (var (where, data) in Blobs(m))
        {
            if (Payload(data) is { } what)
                found.Add(new Finding(m, "embedded executable", "embedded executable", "high", $"{where} is {what} ({data.Length} bytes)"));
            else if (data.Length >= 4096 && ImageTables.Info(data) == null && !Compressed(data)
                     && Overlay.Entropy(data.AsSpan(0, Math.Min(data.Length, 1 << 20))) is var e && e > 7.6)
                found.Add(new Finding(m, "encrypted resource", "encrypted resources", "medium", $"{where} ({data.Length} bytes) has entropy {e:F2}"));
        }
        if (m.Overlay is { EmbeddedPe: long pe })
            found.Add(new Finding(m, "embedded executable", "embedded executable", "high", $"the overlay holds a PE file at 0x{pe:X}"));

        if (!md.IsILOnly)
            found.Add(new Finding(m, "native code", "mixed mode", "high", "the module is not IL-only (C++/CLI, a native stub or ReadyToRun)"));
        // one row per product or technique: a marker attribute and the runtime types it ships with are the same finding
        return found.GroupBy(f => (f.Name, f.Kind, f.Confidence)).Select(g => g.Count() == 1 ? g.First() : g.First() with
        {
            Evidence = string.Join("; ", g.Select(f => f.Evidence).Distinct().Take(4)) + (g.Count() > 4 ? $"; ... ({g.Count()} in all)" : ""),
        });
    }

    // Compressed data is as dense as encrypted data; tell them apart by format. Costura and many loaders store raw
    // deflate, which has no header: it is compressed if the first few KB inflate (random bytes fail within a few symbols).
    static bool Compressed(byte[] d)
    {
        if (d.Length > 4 && (d[0] == 0x1F && d[1] == 0x8B || d[0] == 'P' && d[1] == 'K' || d[0] == 0x78 && (d[1] is 0x01 or 0x5E or 0x9C or 0xDA)
                             || d[0] == '7' && d[1] == 'z' || d[0] == 0x5D && d[1] == 0 && d[2] == 0))
            return true;
        try
        {
            using var z = new System.IO.Compression.DeflateStream(new MemoryStream(d, false), System.IO.Compression.CompressionMode.Decompress);
            var buf = new byte[4096];
            int total = 0, n;
            while (total < buf.Length && (n = z.Read(buf, total, buf.Length - total)) > 0) total += n;
            return total == buf.Length;
        }
        catch (Exception) { return false; }
    }

    // Every blob a loader could carry its next stage in. A .resources file is a container: its entries are looked at,
    // not the file itself.
    static IEnumerable<(string Where, byte[] Data)> Blobs(LoadedModule m)
    {
        foreach (var r in m.Module.Resources.OfType<EmbeddedResource>())
        {
            byte[] data;
            try { data = r.CreateReader().ToArray(); } catch (Exception) { continue; }
            if (data.Length >= 4 && BitConverter.ToUInt32(data, 0) == 0xBEEFCACE && ResourceTables.ReadSet(m, r) is { } set)
            {
                foreach (var e in set.ResourceElements)
                {
                    var where = $"element '{e.Name}' of resource '{r.Name}'";
                    if (e.ResourceData is dnlib.DotNet.Resources.BinaryResourceData bin)
                    {
                        // a serialized object (a form's Bitmap, say): the byte arrays inside it, not its serialization
                        foreach (var b in ImageTables.NrbfByteArrays(bin.Data))
                            if (ImageTables.Info(b) == null) yield return (where, b);
                    }
                    else if (ResourceTables.ElementValue(e) is byte[] b) yield return (where, b);
                }
            }
            else yield return ($"resource '{r.Name}'", data); // also a .resources file that does not parse: judged whole
        }
    }

    public sealed record Carved(LoadedModule M, string Location, long Offset, long Size, ushort Machine, bool IsDll, byte[] Source)
    {
        /// <summary>The file offset of the smallest other PE in the file bytes that contains this one; null when none does.</summary>
        public long? Parent { get; init; }
        public ReadOnlySpan<byte> Slice() => Source.AsSpan((int)Offset, (int)Math.Min(Size, Source.Length - Offset));
    }

    const int MaxCarved = 256 << 20;

    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, HashSet<string>> _carvedHashes = new();

    /// <summary>The SHA-256 (upper-case hex) of every PE carved from the module, worked out once: where a stage came from.</summary>
    internal static HashSet<string> CarvedHashes(LoadedModule m) => _carvedHashes.GetValue(m, lm =>
    {
        try { return Carve(lm).Select(c => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(c.Slice()))).ToHashSet(StringComparer.Ordinal); }
        catch (Exception) { return []; } // a module whose resources do not read carries nothing found here
    });

    internal static IEnumerable<Carved> Carve(LoadedModule m)
    {
        var seen = new HashSet<string>();
        string Key(byte[] b, long at, long size) => $"{size}:{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b.AsSpan((int)at, (int)Math.Min(size, Math.Min(4096, b.Length - at)))))}";
        // resources and .resources entries: a PE as it is, or behind compression
        foreach (var (where, data) in Blobs(m))
            if (PeIn(m, where, data) is { } c)
            {
                seen.Add(Key(c.Source, c.Offset, c.Size));
                yield return c;
            }
        // a PE stored in pieces, put back together (one row per payload, not per order tried)
        foreach (var (where, data) in SplitPayloads(m))
            if (PeIn(m, where, data) is { } c && seen.Add(Key(c.Source, c.Offset, c.Size)))
                yield return c;
        // the file bytes: an MZ with a valid PE header anywhere but at the start (the module itself)
        var file = m.DiskBytes;
        var sections = m.FileMetadata.PEImage.ImageSectionHeaders;
        long end = sections.Select(h => (long)h.PointerToRawData + h.SizeOfRawData).DefaultIfEmpty(0).Max();
        foreach (var (at, pe, parent) in PesIn(file, 1, (at, size) => seen.Add(Key(file, at, size))))
        {
            var section = sections.FirstOrDefault(h => at >= h.PointerToRawData && at < (long)h.PointerToRawData + h.SizeOfRawData);
            var where = at >= end ? "overlay" : section != null ? $"section {section.DisplayName}" : "headers";
            yield return new Carved(m, where, at, pe.Size, pe.Machine, pe.Dll, file) { Parent = parent };
        }
    }

    // Every PE in the bytes from `from` on whose headers hold up (and that `keep` takes), in offset order, with the offset
    // of the smallest earlier one that contains it. A PE that holds others (a dropper's payload with its own payloads)
    // comes first, so the containers still open at an offset are a stack, innermost on top.
    static IEnumerable<(int At, (long Size, ushort Machine, bool Dll) Pe, long? Parent)> PesIn(byte[] file, int from, Func<int, long, bool> keep)
    {
        var open = new Stack<(long Start, long End)>();
        int first = from >= file.Length ? -1 : file.AsSpan(from).IndexOf("MZ"u8);
        for (int at = first < 0 ? -1 : from + first; at >= 0; )
        {
            if (Header(file, at) is { } pe && keep(at, pe.Size))
            {
                long end = at + Math.Min(pe.Size, file.Length - at);
                while (open.Count > 0 && open.Peek().End < end) open.Pop(); // ends before this one does: does not contain it
                long? parent = open.Count > 0 ? open.Peek().Start : null;
                open.Push((at, end));
                yield return (at, pe, parent);
            }
            int next = file.AsSpan(at + 1).IndexOf("MZ"u8);
            at = next < 0 ? -1 : at + 1 + next;
        }
    }

    /// <summary>A PE found in a file carve_file reads (a file open() refuses: a native dropper, say).</summary>
    public sealed record FileCarve(string Path, string Location, long Offset, long Size, ushort Machine, bool IsDll, long? Parent, byte[] Source)
    {
        public ReadOnlySpan<byte> Slice() => Source.AsSpan((int)Offset, (int)Math.Min(Size, Source.Length - Offset));
    }

    // The PEs in a file's bytes, the file itself included (offset 0): what embedded_pes finds in a module's file bytes,
    // for a file that is no module. Read once, like open(); nothing is written.
    static IEnumerable<FileCarve> CarveFile(string path)
    {
        path = Path.GetFullPath(path);
        var info = new FileInfo(path);
        if (!info.Exists) throw new SqlException($"carve_file: no file {path}");
        if (info.Length > int.MaxValue) throw new SqlException($"carve_file: {path} is larger than 2 GB");
        var file = File.ReadAllBytes(path);
        long outer = Header(file, 0) is { } self ? self.Size : 0;
        foreach (var (at, pe, parent) in PesIn(file, 0, (_, _) => true))
            yield return new FileCarve(path, at == 0 ? "the file" : outer > 0 && at >= outer ? "overlay" : outer > 0 ? "inside the file's image" : "file bytes",
                at, pe.Size, pe.Machine, pe.Dll, parent, file);
    }

    // A blob that is a PE, as it is or behind gzip/zlib/deflate (at the start or after a 4-byte length); else null.
    static Carved? PeIn(LoadedModule m, string where, byte[] data)
    {
        if (Header(data, 0) is { } raw) return new Carved(m, where, 0, raw.Size, raw.Machine, raw.Dll, data);
        foreach (int skip in new[] { 0, 4 })
            foreach (var kind in new[] { "gzip", "zlib", "deflate" })
                if (Inflate(data, skip, kind) is [(byte)'M', (byte)'Z'] && InflateAll(data, skip, kind) is { } inflated && Header(inflated, 0) is { } pe)
                    return new Carved(m, $"{where} ({kind}{(skip > 0 ? " after a 4-byte length" : "")})", 0, pe.Size, pe.Machine, pe.Dll, inflated);
        return null;
    }

    // stem + index (+ extension): part1, Part_02, chunk-3.bin, data.004 ...
    static readonly System.Text.RegularExpressions.Regex Indexed = new(@"^(.*?)(\d{1,6})(\.[A-Za-z0-9]{1,8})?$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    const int MaxParts = 4096;

    /// <summary>
    /// A next stage stored in pieces: resources (or entries of one .resources file) named with a common stem and
    /// consecutive indexes, joined in index order and in reverse order; text pieces (or bytes that are base64 text) are
    /// also joined as text, reversed, and base64-decoded. Each candidate goes to the PE check (PeIn), so only one that
    /// is a PE, plain or compressed, is reported; the location says which pieces and how they were joined.
    /// </summary>
    static IEnumerable<(string Where, byte[] Data)> SplitPayloads(LoadedModule m)
    {
        var parts = new List<(string Container, string Name, byte[]? Bytes, string? Text)>();
        foreach (var r in m.Module.Resources.OfType<EmbeddedResource>())
        {
            byte[] data;
            try { data = r.CreateReader().ToArray(); } catch (Exception) { continue; }
            if (data.Length >= 4 && BitConverter.ToUInt32(data, 0) == 0xBEEFCACE && ResourceTables.ReadSet(m, r) is { } set)
            {
                foreach (var e in set.ResourceElements)
                    switch (ResourceTables.ElementValue(e))
                    {
                        case byte[] b: parts.Add((r.Name, e.Name, b, null)); break;
                        case string str: parts.Add((r.Name, e.Name, null, str)); break;
                    }
            }
            else parts.Add(("", r.Name, data, null));
        }

        var groups = parts.Select(p => (p, x: Indexed.Match(p.Name)))
            .Where(t => t.x.Success)
            .GroupBy(t => (t.p.Container, Stem: t.x.Groups[1].Value, Ext: t.x.Groups[3].Value, Text: t.p.Text != null));
        foreach (var g in groups)
        {
            var ordered = g.Select(t => (t.p, Index: int.Parse(t.x.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture)))
                .OrderBy(t => t.Index).ToList();
            // two or more pieces, numbered without a gap or a duplicate
            if (ordered.Count < 2 || ordered.Count > MaxParts) continue;
            if (ordered.Where((t, i) => t.Index != ordered[0].Index + i).Any()) continue;
            var first = ordered[0].p.Name;
            var last = ordered[^1].p.Name;
            var where = g.Key.Container.Length == 0 ? $"resources '{first}'..'{last}'" : $"elements '{first}'..'{last}' of resource '{g.Key.Container}'";

            if (!g.Key.Text)
            {
                long total = ordered.Sum(t => (long)t.p.Bytes!.Length);
                if (total > MaxCarved) continue;
                var asc = ordered.SelectMany(t => t.p.Bytes!).ToArray();
                yield return ($"{where} (joined)", asc);
                yield return ($"{where} (joined in reverse order)", ordered.AsEnumerable().Reverse().SelectMany(t => t.p.Bytes!).ToArray());
                yield return ($"{where} (joined, bytes reversed)", asc.Reverse().ToArray());
                // base64 text kept in binary resources
                if (asc.Length > 0 && asc.All(b => b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9'
                                                    or (byte)'+' or (byte)'/' or (byte)'=' or (byte)'-' or (byte)'_' or (byte)'\r' or (byte)'\n'))
                    foreach (var c in FromText(where, ordered.Select(t => System.Text.Encoding.ASCII.GetString(t.p.Bytes!)).ToList()))
                        yield return c;
            }
            else if (ordered.Sum(t => (long)t.p.Text!.Length) <= MaxCarved)
                foreach (var c in FromText(where, ordered.Select(t => t.p.Text!).ToList()))
                    yield return c;
        }
    }

    // Text pieces: base64 of the pieces joined, joined in reverse order, and of the joined text reversed.
    static IEnumerable<(string Where, byte[] Data)> FromText(string where, List<string> pieces)
    {
        var joined = string.Concat(pieces);
        foreach (var (how, text) in new[]
                 {
                     ("joined, base64", joined),
                     ("joined in reverse order, base64", string.Concat(pieces.AsEnumerable().Reverse())),
                     ("joined, text reversed, base64", new string(joined.Reverse().ToArray())),
                 })
            if (DnSpySql.Functions.DataFunctions.Base64(text) is { Length: > 0 } bytes)
                yield return ($"{where} ({how})", bytes);
    }

    // A PE header at the offset: its machine, whether it is a DLL, and its size on disk (the end of the furthest
    // section's raw data, or of the certificate), clipped to the bytes there are. Null when the header does not hold up.
    static (long Size, ushort Machine, bool Dll)? Header(byte[] b, int at)
    {
        if (at < 0 || b.Length - at < 0x200 || b[at] != 'M' || b[at + 1] != 'Z') return null;
        int pe = BitConverter.ToInt32(b, at + 0x3C);
        if (pe < 0x40 || pe > 0x1000 || at + pe + 0x18 > b.Length) return null;
        int h = at + pe;
        if (b[h] != 'P' || b[h + 1] != 'E' || b[h + 2] != 0 || b[h + 3] != 0) return null;
        ushort machine = BitConverter.ToUInt16(b, h + 4);
        if (machine is not (0x14C or 0x8664 or 0x1C0 or 0x1C4 or 0xAA64 or 0x200)) return null;
        int nsec = BitConverter.ToUInt16(b, h + 6), opt = h + 0x18, optSize = BitConverter.ToUInt16(b, h + 0x14);
        bool dll = (BitConverter.ToUInt16(b, h + 0x16) & 0x2000) != 0;
        int table = opt + optSize;
        if (nsec is 0 or > 96 || optSize < 0x60 || table + nsec * 40 > b.Length) return null;
        long size = opt + 0x40 <= b.Length ? BitConverter.ToUInt32(b, opt + 0x3C) : 0; // SizeOfHeaders
        for (int i = 0; i < nsec; i++)
        {
            long raw = BitConverter.ToUInt32(b, table + i * 40 + 0x14), len = BitConverter.ToUInt32(b, table + i * 40 + 0x10);
            if (len > 0) size = Math.Max(size, raw + len);
        }
        int dirs = opt + (BitConverter.ToUInt16(b, opt) == 0x20B ? 0x70 : 0x60);
        if (dirs + 5 * 8 <= b.Length && BitConverter.ToUInt32(b, dirs - 4) > 4)
        {
            long certAt = BitConverter.ToUInt32(b, dirs + 4 * 8), certLen = BitConverter.ToUInt32(b, dirs + 4 * 8 + 4);
            if (certAt > 0 && certLen > 0) size = Math.Max(size, certAt + certLen);
        }
        if (size <= 0) return null;
        return (Math.Min(size, b.Length - at), machine, dll);
    }

    static byte[]? InflateAll(byte[] d, int skip, string kind)
    {
        try
        {
            using var src = new MemoryStream(d, skip, d.Length - skip, false);
            using Stream z = kind switch
            {
                "gzip" => new System.IO.Compression.GZipStream(src, System.IO.Compression.CompressionMode.Decompress),
                "zlib" => new System.IO.Compression.ZLibStream(src, System.IO.Compression.CompressionMode.Decompress),
                _ => new System.IO.Compression.DeflateStream(src, System.IO.Compression.CompressionMode.Decompress),
            };
            using var output = new MemoryStream();
            var buf = new byte[81920];
            int n;
            while ((n = z.Read(buf, 0, buf.Length)) > 0)
            {
                if (output.Length + n > MaxCarved) return null;
                output.Write(buf, 0, n);
            }
            return output.ToArray();
        }
        catch (Exception) { return null; }
    }

    // A PE, or one behind compression: gzip, zlib or raw deflate, at the start or after a 4-byte length (a common
    // loader layout). Only the first bytes are inflated.
    static string? Payload(byte[] d)
    {
        if (d.Length >= 64 && d[0] == 'M' && d[1] == 'Z') return "a PE file";
        foreach (int skip in new[] { 0, 4 })
        {
            if (d.Length < skip + 16) continue;
            foreach (var kind in new[] { "gzip", "zlib", "deflate" })
                if (Inflate(d, skip, kind) is [(byte)'M', (byte)'Z'])
                    return $"a {kind}-compressed PE file{(skip > 0 ? " (after a 4-byte length)" : "")}";
        }
        return null;
    }

    /// <summary>gzip, zlib or deflate when the bytes inflate (at the start or after a 4-byte length) to 4 KB or to their end; else null.</summary>
    internal static string? Stream(byte[] d)
    {
        foreach (int skip in new[] { 0, 4 })
            foreach (var kind in new[] { "gzip", "zlib", "deflate" })
            {
                // raw deflate has no header: only at the start, and only when it inflates a full window (garbage rarely does)
                if (kind == "deflate" && skip > 0) continue;
                if (kind == "gzip" && !(d.Length > skip + 2 && d[skip] == 0x1F && d[skip + 1] == 0x8B)) continue;
                if (kind == "zlib" && !(d.Length > skip + 2 && d[skip] == 0x78 && ((d[skip] << 8) | d[skip + 1]) % 31 == 0)) continue;
                if (Inflated(d, skip, kind) >= Math.Min(4096, d.Length)) return kind;
            }
        return null;
    }

    static int Inflated(byte[] d, int skip, string kind)
    {
        try
        {
            using var src = new MemoryStream(d, skip, d.Length - skip, false);
            using Stream z = kind switch
            {
                "gzip" => new System.IO.Compression.GZipStream(src, System.IO.Compression.CompressionMode.Decompress),
                "zlib" => new System.IO.Compression.ZLibStream(src, System.IO.Compression.CompressionMode.Decompress),
                _ => new System.IO.Compression.DeflateStream(src, System.IO.Compression.CompressionMode.Decompress),
            };
            var buf = new byte[4096];
            int n = 0, r;
            while (n < buf.Length && (r = z.Read(buf, n, buf.Length - n)) > 0) n += r;
            return n;
        }
        catch (Exception) { return 0; }
    }

    static byte[]? Inflate(byte[] d, int skip, string kind)
    {
        try
        {
            using var src = new MemoryStream(d, skip, d.Length - skip, false);
            using Stream z = kind switch
            {
                "gzip" => new System.IO.Compression.GZipStream(src, System.IO.Compression.CompressionMode.Decompress),
                "zlib" => new System.IO.Compression.ZLibStream(src, System.IO.Compression.CompressionMode.Decompress),
                _ => new System.IO.Compression.DeflateStream(src, System.IO.Compression.CompressionMode.Decompress),
            };
            var buf = new byte[2];
            int n = 0, r;
            while (n < 2 && (r = z.Read(buf, n, 2 - n)) > 0) n += r;
            return n == 2 ? buf : null;
        }
        catch (Exception) { return null; }
    }

    // Base64 or hex runs of 16+ characters: ciphertext or encoded data, not words.
    static bool LooksEncoded(string x) =>
        x.Length >= 16 && !x.Contains(' ') && x.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '+' or '/' or '=' or '-' or '_');

    static bool ContainsWord(string text, string word)
    {
        for (int i = text.IndexOf(word, StringComparison.Ordinal); i >= 0; i = text.IndexOf(word, i + 1, StringComparison.Ordinal))
            if ((i == 0 || !char.IsLetterOrDigit(text[i - 1])) && (i + word.Length == text.Length || !char.IsLetterOrDigit(text[i + word.Length])))
                return true;
        return false;
    }

    // An identifier with no word structure: split at case changes, the pieces of a real name average three or more
    // letters (GetTypeName: Get Type Name), and a quarter or more of its letters are vowels. Random names fail one or the
    // other (xDWYusSMnb: x DW Yus S Mnb). Abbreviations (XmlHttp) can too, so only a share of a module's names counts.
    static readonly System.Text.RegularExpressions.Regex Pieces = new("[A-Z]+(?![a-z])|[A-Z]?[a-z]+", System.Text.RegularExpressions.RegexOptions.Compiled);

    static bool Gibberish(string name)
    {
        if (name.Length < 6 || !name.All(char.IsAsciiLetter)) return false;
        int pieces = Pieces.Matches(name).Count, vowels = name.Count(ch => "aeiouAEIOU".Contains(ch));
        return (double)name.Length / pieces < 2.6 || vowels * 4 < name.Length;
    }

    static bool TryBody(MethodDef m, out IList<Instruction> ins)
    {
        ins = Array.Empty<Instruction>();
        try
        {
            if (!m.HasBody || m.Body == null) return false;
            ins = m.Body.Instructions;
            return true;
        }
        catch (Exception) { return false; } // a body dnlib cannot read (anti-tamper) is not evidence of anything else
    }

    // A switch with several targets, and a branch from after it back to before it (the dispatcher loop).
    static bool Flattened(IList<Instruction> ins)
    {
        for (int i = 0; i < ins.Count; i++)
        {
            if (ins[i].OpCode.Code != Code.Switch || ins[i].Operand is not Instruction[] targets || targets.Length < 4) continue;
            for (int j = i + 1; j < ins.Count; j++)
                if (ins[j].Operand is Instruction t && ins[j].OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch && t.Offset <= ins[i].Offset)
                    return true;
        }
        return false;
    }

    // ---- IL virtualization ----------------------------------------------------------------------------------------------

    /// <summary>A dispatcher of an IL virtual machine and the methods virtualized into it (with the id each passes, when it is a constant).</summary>
    public sealed record Virtualized(MethodDef Dispatcher, IReadOnlyDictionary<MethodDef, int?> Stubs, bool HandlerLoop);

    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, Tuple<int, List<Virtualized>>> _vms = new();

    /// <summary>
    /// Dispatchers that ten or more methods (or a fifth of them, and three at least) are stubs into: a body of at most 40
    /// instructions whose one call into the module is to the dispatcher, after an object[] of the arguments and an integer
    /// id or a type token. That is what IL virtualizers leave of a method; the shape names no product.
    /// </summary>
    internal static List<Virtualized> Virtualization(LoadedModule m)
    {
        if (_vms.TryGetValue(m, out var hit) && hit.Item1 == m.Revision) return hit.Item2;
        var stubs = new Dictionary<MethodDef, Dictionary<MethodDef, int?>>();
        int bodied = 0;
        foreach (var meth in m.Module.GetTypes().SelectMany(t => t.Methods))
        {
            if (!TryBody(meth, out var ins)) continue;
            bodied++;
            if (Stub(meth, ins) is var (d, id)) (stubs.TryGetValue(d, out var list) ? list : stubs[d] = new())[meth] = id;
        }
        var result = stubs.Where(kv => kv.Value.Count >= 10 || kv.Value.Count >= 3 && kv.Value.Count * 5 >= bodied)
            .Select(kv => new Virtualized(kv.Key, kv.Value, HandlerLoop(kv.Key, 0))).ToList();
        _vms.AddOrUpdate(m, Tuple.Create(m.Revision, result));
        return result;
    }

    static (MethodDef Dispatcher, int? Id)? Stub(MethodDef meth, IList<Instruction> ins)
    {
        if (ins.Count > 40) return null;
        MethodDef? target = null;
        int array = -1;
        bool token = false;
        for (int i = 0; i < ins.Count; i++)
        {
            var x = ins[i];
            if (x.OpCode.Code == Code.Newarr && (x.Operand as ITypeDefOrRef)?.FullName == "System.Object") array = i;
            else if (x.OpCode.Code == Code.Ldtoken) token = true;
            else if (x.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj && x.Operand is IMethod im)
            {
                MethodDef? d;
                try { d = im.ResolveMethodDef(); } catch (Exception) { d = null; }
                if (d == null || d.Module != meth.Module) continue; // the framework: boxing helpers, GetTypeFromHandle
                if (target != null && target != d || d == meth) return null;
                target = d;
            }
        }
        if (target == null || array < 0 || target.MethodSig?.Params.Any(p => p is SZArraySig { Next.ElementType: ElementType.Object }) != true) return null;
        // the id: the constant pushed before the array's length (ldc id; ldc n; newarr object)
        int? id = array >= 2 && ins[array - 1].IsLdcI4() && ins[array - 2].IsLdcI4() ? ins[array - 2].GetLdcI4Value() : null;
        return id != null || token ? (target, id) : null;
    }

    // The VM's handler dispatch: a switch of 50 or more targets inside a loop, in the dispatcher or what it calls
    static bool HandlerLoop(MethodDef d, int depth)
    {
        if (!TryBody(d, out var ins)) return false;
        for (int i = 0; i < ins.Count; i++)
            if (ins[i].OpCode.Code == Code.Switch && ins[i].Operand is Instruction[] { Length: >= 50 }
                && ins.Skip(i + 1).Any(x => x.Operand is Instruction t && x.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch && t.Offset <= ins[i].Offset))
                return true;
        return depth < 2 && ins.Select(x => x.Operand).OfType<IMethod>().Select(im => { try { return im.ResolveMethodDef(); } catch (Exception) { return null; } })
            .OfType<MethodDef>().Where(c => c.Module == d.Module && c != d).Distinct().Take(50).Any(c => HandlerLoop(c, depth + 1));
    }

    // The dispatcher's namespace root when it is a readable name (KoiVM.Runtime -> KoiVM): identification, not a guess
    static string VmName(MethodDef d)
    {
        var t = d.DeclaringType;
        while (t?.DeclaringType != null) t = t.DeclaringType;
        var root = (t?.Namespace.String ?? "").Split('.')[0];
        return root.Length >= 3 && root.All(char.IsAsciiLetterOrDigit) && !Gibberish(root) ? root : "IL virtualization";
    }

    /// <summary>The note decompile() adds to a virtualized method's body, or null.</summary>
    internal static string? VirtualizedNote(LoadedModule m, MethodDef meth) =>
        Virtualization(m).FirstOrDefault(v => v.Stubs.ContainsKey(meth)) is { } vm
            ? $"// dnspysql: virtualized: this body only calls {vm.Dispatcher.FullName}{(vm.Stubs[meth] is int id ? $" with id {id}" : "")}; its real code " +
              "is bytecode of an IL virtual machine, which no decompiler shows."
            : null;

    // A section that is mostly random bytes (encrypted code), the largest one: its name, size and entropy
    static (string? Name, long Size, double Entropy) HighEntropySection(LoadedModule m)
    {
        var file = m.DiskBytes;
        foreach (var h in m.FileMetadata.PEImage.ImageSectionHeaders.OrderByDescending(h => h.SizeOfRawData))
        {
            long at = h.PointerToRawData, size = Math.Min(h.SizeOfRawData, file.Length - at);
            if (at <= 0 || size < 4096) continue;
            var e = Overlay.Entropy(file.AsSpan((int)at, (int)Math.Min(size, 1 << 20)));
            if (e > 7.5) return (h.DisplayName, size, e);
        }
        return default;
    }

    // ldc ldc op: a binary operation on two constants, which no compiler leaves unfolded
    static int ConstantArithmetic(IList<Instruction> ins)
    {
        int n = 0;
        for (int i = 2; i < ins.Count; i++)
            if (ins[i].OpCode.Code is Code.Add or Code.Sub or Code.Mul or Code.Xor or Code.Or or Code.And or Code.Shl or Code.Shr or Code.Shr_Un
                    or Code.Div or Code.Rem or Code.Div_Un or Code.Rem_Un
                && IsConstant(ins[i - 1]) && IsConstant(ins[i - 2]))
                n++;
        return n;
        static bool IsConstant(Instruction x) => x.IsLdcI4() || x.OpCode.Code is Code.Ldc_I8;
    }

    internal static bool IsThunk(MethodDef m)
    {
        if (!m.IsStatic || !TryBody(m, out var ins) || ins.Count < 2 || ins.Count > 8) return false;
        if (ins[^1].OpCode.Code != Code.Ret || ins[^2].OpCode.Code is not (Code.Call or Code.Callvirt or Code.Newobj)) return false;
        for (int i = 0; i < ins.Count - 2; i++)
            if (!ins[i].IsLdarg()) return false;
        return ins[^2].Operand is IMethod target && target.Name != m.Name;
    }

    // ---- string decryptors -------------------------------------------------------------------------------------------

    // Decryptor-shaped: static, returns a string (or object, or a generic T: T x<T>(int)), 1-4 parameters of
    // which at least one is an integer or a string (the key). A library helper taking only objects is not one.
    static bool Shaped(MethodDef meth)
    {
        var sig = meth.MethodSig;
        if (!meth.IsStatic || sig == null || sig.Params.Count is < 1 or > 4) return false;
        if (sig.RetType?.ElementType is not (ElementType.String or ElementType.Object or ElementType.MVar or ElementType.Var)) return false;
        return sig.Params.Any(p => p?.ElementType is ElementType.I4 or ElementType.U4 or ElementType.I8 or ElementType.U8 or ElementType.I2
                                   or ElementType.U2 or ElementType.I1 or ElementType.U1 or ElementType.String);
    }

    public static IEnumerable<Decryptor> Decryptors(Session s, LoadedModule m, int minSites, double minLiteralShare = 0.5)
    {
        var fold = new Fold(s);
        var result = new List<Decryptor>();
        foreach (var meth in m.Module.GetTypes().SelectMany(t => t.Methods).Where(Shaped))
            if (Candidate(s, m, meth, minSites, fold) is { } d && d.ConstantRatio >= minLiteralShare) result.Add(d);
        return result.OrderByDescending(d => d.Score).ThenByDescending(d => d.Sites);
    }

    static Decryptor? Candidate(Session s, LoadedModule m, MethodDef meth, int minSites, Fold fold)
    {
        var sites = s.Index.To(m.H(meth)).Where(x => x.IsCall).ToList();
        if (sites.Count < Math.Max(1, minSites)) return null;
        int n = meth.MethodSig?.Params.Count ?? 0, constant = 0;
        var samples = new List<string>();
        foreach (var x in sites)
        {
            if (Arguments(x, n, fold) is not { } args) continue;
            constant++;
            if (samples.Count < 3) samples.Add(string.Join(", ", args.Select(a => a.Text)));
        }
        return new Decryptor(m, meth, sites.Count, sites.Select(x => x.From).Distinct().Count(), constant, samples);
    }

    /// <summary>A call of a string decryptor with literal arguments: what to decrypt, and where to break to see it.</summary>
    public sealed record DecryptorCall(LoadedModule M, MethodDef Decryptor, XRef Site, IReadOnlyList<Lit> Args)
    {
        // computed only when the plaintext or emulation column is read
        public required Lazy<(object? Value, string Status)> Plain { get; init; }
    }

    static (object? Value, string Status) Emulate(Session s, MethodDef decryptor, XRef site, IReadOnlyList<Lit> args)
    {
        var generic = (site.Operand as MethodSpec)?.GenericInstMethodSig?.GenericArguments;
        var (value, error) = Emulator.For(s).Cached(decryptor, args.Select(a => a.Value).ToList(), generic);
        return (value, error ?? "ok");
    }

    internal static IEnumerable<DecryptorCall> Calls(Session s, LoadedModule m, long? decryptor, int minSites)
    {
        var fold = new Fold(s);
        IEnumerable<MethodDef> methods;
        if (decryptor is long h)
            // any method asked for by handle, candidate or not
            methods = Handle.Module(s.Ws.Normalize(h)) == m.Id && m.Module.ResolveToken(Handle.Token(s.Ws.Normalize(h))) is MethodDef md ? [md] : [];
        else
            methods = Decryptors(s, m, minSites).Select(d => d.Method);
        foreach (var meth in methods)
        {
            int n = meth.MethodSig?.Params.Count ?? 0;
            foreach (var x in s.Index.To(m.H(meth)).Where(x => x.IsCall))
                if (Arguments(x, n, fold) is { } args)
                    yield return new DecryptorCall(m, meth, x, args) { Plain = new(() => Emulate(s, meth, x, args)) };
        }
    }

    /// <summary>A literal argument: its text as the decompiler would print it, and its value; FromField when a static field held it.</summary>
    public sealed record Lit(string Text, object? Value, bool FromField = false);

    /// <summary>What folds to a literal: getters and static fields holding a constant, remembered per query.</summary>
    internal sealed class Fold(Session s)
    {
        public readonly Session S = s;
        public readonly Dictionary<IMethod, Lit?> Getters = new();
        public readonly Dictionary<FieldDef, Lit?> Fields = new();
    }

    // The n arguments pushed right before the call, all literals, or null. Steps back over nops and over a branch to the
    // very next instruction (obfuscators insert one between the ldc and the call). Only a call passes arguments: what
    // precedes an ldftn (a delegate's target object) is not one.
    static List<Lit>? Arguments(XRef x, int n, Fold fold) =>
        x.Kind is "call" or "callvirt" && TryBody(x.From, out var ins) && x.Index < ins.Count ? ArgumentsAt(ins, x.Index, n, fold) : null;

    internal static List<Lit>? ArgumentsAt(IList<Instruction> ins, int at, int n, Fold fold)
    {
        var args = new List<Lit>(n);
        for (int i = at - 1; args.Count < n; i--)
        {
            while (i >= 0 && (ins[i].OpCode.Code == Code.Nop
                              || ins[i].OpCode.Code is Code.Br or Code.Br_S && i + 1 < ins.Count && ReferenceEquals(ins[i].Operand, ins[i + 1])))
                i--;
            if (i < 0 || Literal(ins[i], fold) is not { } v) return null;
            args.Add(v);
        }
        args.Reverse();
        return args;
    }

    internal static Lit? Literal(Instruction i, Fold? fold = null) => i.OpCode.Code switch
    {
        Code.Ldsfld when fold != null && i.Operand is IField f => FieldConst(f, fold),
        Code.Ldstr => new Lit("\"" + (i.Operand as string ?? "") + "\"", i.Operand as string ?? ""),
        Code.Ldc_I8 => new Lit(Convert.ToString(i.Operand, System.Globalization.CultureInfo.InvariantCulture)!, i.Operand),
        Code.Ldnull => new Lit("null", null),
        Code.Call when fold != null && i.Operand is IMethod g => Getter(g, fold.Getters),
        _ when i.IsLdcI4() => new Lit(i.GetLdcI4Value().ToString(System.Globalization.CultureInfo.InvariantCulture), (long)i.GetLdcI4Value()),
        _ => null,
    };

    // A static field written once, with a literal (or a getter's constant): a settings field passed to its decryptor,
    // as in Decode(Config.Host). Shown as the field and its value.
    static Lit? FieldConst(IField f, Fold fold)
    {
        FieldDef? fd;
        try { fd = f.ResolveFieldDef(); } catch (Exception) { return null; }
        if (fd is not { IsStatic: true }) return null;
        if (fold.Fields.TryGetValue(fd, out var v)) return v;
        fold.Fields[fd] = null; // until known; also stops a cycle
        if (fold.S.Ws.Find(fd.Module) is { } lm)
        {
            // one write of a literal; any other write stores a value computed from the field itself (F = Decrypt(F), the
            // usual way a settings field is decrypted in place), which the call sites read after or before: the literal
            // is what the decryptor is given
            Lit? literal = null;
            bool other = false;
            foreach (var w in fold.S.Index.To(lm.H(fd)).Where(x => x.Kind == "write"))
            {
                if (!TryBody(w.From, out var ins) || w.Index >= ins.Count) { other = true; break; }
                int k = w.Index - 1;
                while (k >= 0 && ins[k].OpCode.Code == Code.Nop) k--;
                if (k >= 0 && ins[k].OpCode.Code != Code.Ldsfld && Literal(ins[k], fold) is { } lit)
                {
                    if (literal != null) { other = true; break; }
                    literal = lit;
                }
                else if (!ReadsItself(ins, k, fd)) { other = true; break; }
            }
            if (literal != null && !other) v = literal with { Text = $"{fd.Name} = {literal.Text}", FromField = true };
            // else the value the field has once the program started: a decoder's (decoded_fields) or what a decryptor
            // computed into it in the static constructor, so Decrypt2(Settings.Host) is a call with a known argument
            else if (TriageTables.KnownValue(fold.S, fd) is { Value: { } known })
                v = new Lit($"{fd.Name} = {Shown(known)}", known, FromField: true);
        }
        return fold.Fields[fd] = v;
    }

    static string Shown(object v) => v switch
    {
        string str => "\"" + (str.Length > 60 ? str[..60] + "…" : str) + "\"",
        byte[] b => $"x'{Convert.ToHexString(b.AsSpan(0, Math.Min(b.Length, 16)))}{(b.Length > 16 ? "…" : "")}'",
        _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };

    // The value stored at a write is a call's result whose arguments read the field itself (F = Decode(F)).
    static bool ReadsItself(IList<Instruction> ins, int call, FieldDef fd)
    {
        if (call < 0 || ins[call].OpCode.Code is not (Code.Call or Code.Callvirt)) return false;
        for (int k = call - 1; k >= 0 && k >= call - 8; k--)
            if (ins[k].OpCode.Code == Code.Ldsfld && ins[k].Operand is IField f && f.FullName == fd.FullName) return true;
        return false;
    }

    // Zero bytes where a body starts (a header byte is never 0; four, since tiny bodies are short and the next one may
    // follow at once): a body the runtime fills in, not one encrypted in place.
    static bool Zeroed(byte[] file, long offset) =>
        offset >= 0 && offset + 4 <= file.Length && file.AsSpan((int)offset, 4).IndexOfAnyExcept((byte)0) < 0;

    // A parameterless static method that only returns a literal, directly or through another such getter (up to three
    // deep): some obfuscators call one in place of each literal. A Debug build's "ldstr; stloc; br; ldloc; ret" counts too.
    internal static Lit? Getter(IMethod g, Dictionary<IMethod, Lit?> memo, int depth = 0)
    {
        if (memo.TryGetValue(g, out var v)) return v;
        memo[g] = null; // until known; also stops a cycle of getters
        try
        {
            if (depth < 3 && g.ResolveMethodDef() is { IsStatic: true } d && d.MethodSig?.Params.Count == 0 && TryBody(d, out var ins) && ins.Count <= 12)
            {
                var real = ins.Where(x => x.OpCode.Code != Code.Nop && !(x.OpCode.Code is Code.Br or Code.Br_S && x.Operand is Instruction t && ins.IndexOf(t) == ins.IndexOf(x) + 1)).ToList();
                if (real is [var a, var st, var ld, { OpCode.Code: Code.Ret }] && st.IsStloc() && ld.IsLdloc()) real = [a, real[3]];
                if (real is [var value, { OpCode.Code: Code.Ret }])
                    v = value.OpCode.Code == Code.Call && value.Operand is IMethod next ? Getter(next, memo, depth + 1) : Literal(value);
            }
        }
        catch (Exception) { v = null; } // an unresolvable reference is not a constant
        return memo[g] = v;
    }
}
