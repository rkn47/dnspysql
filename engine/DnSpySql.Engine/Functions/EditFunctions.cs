// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Tables;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Resources;

namespace DnSpySql.Functions;

/// <summary>dnSpy AsmEditor actions that are not plain column writes.</summary>
public static class EditFunctions
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        MethodDef M(object? a) => ws.Resolve<MethodDef>(a, "method");
        int I(object? a) => (int)TableKit.Lng(a, "index");

        // ---- bodies ----
        s.Fn("set_body_stub", 1, 2, a =>
        {
            var m = M(a[0]);
            if (m.DeclaringType.IsInterface && m.IsAbstract) throw new SqlException("abstract interface methods cannot have a body");
            BodyEditor.Replace(s, m, "set_body_stub", () => BodyKit.Stub(m, a.Arg(1), a.Length > 1));
            return (long)m.Body.Instructions.Count;
        }, "set_body_stub(method [, return_value])",
            "replace the body with a stub that returns return_value (or default) — dnSpy 'Replace Method Body with Stub' / hex 'return true|false'",
            "edit", mutates: true);

        s.Fn("il_insert", 3, 4, a =>
        {
            var m = M(a[0]);
            BodyEditor.Edit(s, m, "il_insert", b =>
            {
                var idx = I(a[1]);
                if (idx < 0 || idx > b.Instructions.Count) throw new SqlException($"index {idx} out of range 0..{b.Instructions.Count}");
                var op = BodyKit.ParseOpCode(TableKit.Str(a[2], "opcode"));
                b.Instructions.Insert(idx, new Instruction(op, BodyKit.ParseOperand(ws, m, op, a.Arg(3))));
            });
            return (long)m.Body.Instructions.Count;
        }, "il_insert(method, index, opcode [, operand])", "insert before index (index = count appends). Operands: literal, branch index, local/arg index, handle", "edit", mutates: true);

        s.Fn("il_set", 3, 4, a =>
        {
            var m = M(a[0]);
            BodyEditor.Edit(s, m, "il_set", b =>
            {
                var ins = Ins(b, I(a[1]));
                var op = BodyKit.ParseOpCode(TableKit.Str(a[2], "opcode"));
                var operand = BodyKit.ParseOperand(ws, m, op, a.Arg(3));
                ins.OpCode = op;
                ins.Operand = operand;
            });
            return 1L;
        }, "il_set(method, index, opcode [, operand])", "replace one instruction in place (references to it stay valid)", "edit", mutates: true);

        s.Fn("il_remove", 2, 3, a =>
        {
            var m = M(a[0]);
            int count = (int)(Values.ToLong(a.Arg(2)) ?? 1);
            BodyEditor.Edit(s, m, "il_remove", b => { for (int k = 0; k < count; k++) BodyEditor.RemoveAt(b, I(a[1])); });
            return (long)count;
        }, "il_remove(method, index [, count])", "remove instructions; branches/handlers to them are retargeted to the next instruction", "edit", mutates: true);

        s.Fn("il_nop", 2, 4, a =>
        {
            var m = M(a[0]);
            int count = (int)(Values.ToLong(a.Arg(2)) ?? 1);
            bool keepSize = Values.ToBool(a.Arg(3));
            BodyEditor.Edit(s, m, "il_nop", b =>
            {
                var start = I(a[1]);
                var targets = Enumerable.Range(start, count).Select(i => Ins(b, i)).ToList();
                foreach (var ins in targets)
                {
                    int size = ins.GetSize();
                    ins.OpCode = OpCodes.Nop; ins.Operand = null;
                    if (keepSize)
                    {
                        int at = b.Instructions.IndexOf(ins);
                        for (int k = 1; k < size; k++) b.Instructions.Insert(at + 1, OpCodes.Nop.ToInstruction());
                    }
                }
            });
            return (long)count;
        }, "il_nop(method, index [, count [, keep_size]])", "NOP-out instructions (keep_size=1: 'Replace with multiple NOPs' to preserve byte layout)", "edit", mutates: true);

        s.Fn("il_invert_branch", 2, 2, a =>
        {
            BodyEditor.Edit(s, M(a[0]), "il_invert_branch", b => { var ins = Ins(b, I(a[1])); ins.OpCode = BodyEditor.Invert(ins.OpCode); });
            return 1L;
        }, "il_invert_branch(method, index)", "beq<->bne.un, brtrue<->brfalse, blt<->bge ...", "edit", mutates: true);

        s.Fn("il_to_unconditional", 2, 2, a =>
        {
            BodyEditor.Edit(s, M(a[0]), "il_to_unconditional", b =>
            {
                var idx = I(a[1]);
                var ins = Ins(b, idx);
                if (ins.OpCode.FlowControl != FlowControl.Cond_Branch || ins.Operand is not Instruction target)
                    throw new SqlException($"{ins.OpCode.Name} is not a conditional branch");
                int pops = ins.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S ? 1 : 2;
                ins.OpCode = OpCodes.Pop; ins.Operand = null;
                if (pops == 2) b.Instructions.Insert(++idx, OpCodes.Pop.ToInstruction());
                b.Instructions.Insert(idx + 1, OpCodes.Br.ToInstruction(target));
            });
            return 1L;
        }, "il_to_unconditional(method, index)", "conditional branch -> pop(s) + br (always taken)", "edit", mutates: true);

        s.Fn("il_skip_branch", 2, 2, a =>
        {
            BodyEditor.Edit(s, M(a[0]), "il_skip_branch", b =>
            {
                var idx = I(a[1]);
                var ins = Ins(b, idx);
                if (ins.OpCode.FlowControl != FlowControl.Cond_Branch) throw new SqlException($"{ins.OpCode.Name} is not a conditional branch");
                int pops = ins.OpCode.Code is Code.Brtrue or Code.Brtrue_S or Code.Brfalse or Code.Brfalse_S ? 1 : 2;
                ins.OpCode = OpCodes.Pop; ins.Operand = null;
                if (pops == 2) b.Instructions.Insert(idx + 1, OpCodes.Pop.ToInstruction());
            });
            return 1L;
        }, "il_skip_branch(method, index)", "conditional branch -> pop(s) (never taken)", "edit", mutates: true);

        s.Fn("il_simplify", 1, 1, a => { BodyEditor.Edit(s, M(a[0]), "il_simplify", b => b.SimplifyMacros(M(a[0]).Parameters)); return 1L; },
            "il_simplify(method)", "SimplifyMacros: short forms -> long forms", "edit", mutates: true);
        s.Fn("il_optimize", 1, 1, a => { BodyEditor.Edit(s, M(a[0]), "il_optimize", b => b.OptimizeMacros()); return 1L; },
            "il_optimize(method)", "OptimizeMacros: long forms -> short forms", "edit", mutates: true);

        // ---- strings ----
        s.Fn("replace_string", 2, 3, a =>
        {
            var old = Values.ToText(a[0]) ?? ""; var nw = Values.ToText(a[1]) ?? "";
            long n = 0;
            var mods = a.Length > 2 ? new[] { ws.ModuleArg(a[2]) } : ws.Modules.ToArray();
            foreach (var lm in mods)
                foreach (var m in lm.Module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldstr && (string)i.Operand == old)).ToList())
                    BodyEditor.Edit(s, m, "replace_string", b =>
                    {
                        foreach (var i in b.Instructions) if (i.OpCode.Code == Code.Ldstr && (string)i.Operand == old) { i.Operand = nw; n++; }
                    });
            return n;
        }, "replace_string(old, new [, module])", "rewrite every ldstr equal to old; returns the number changed", "edit", mutates: true);

        s.Fn("inline_strings", 0, 3, a => InlineStrings(s, ws.ModuleArg(a.Arg(0)), ws.HandleArg(a.Arg(1)), (Values.ToText(a.Arg(2)) ?? "code").ToLowerInvariant()),
            "inline_strings([module [, decryptor [, mode]]])",
            "replace every string decryptor call that decryptor_calls interprets (emulation = 'ok', a string; library decryptors left " +
            "out) with ldstr of its plaintext, so decompile() and a save() for dnSpy show the strings; the literal arguments become " +
            "nops; a site code jumps into is left, with a note. decryptor = a method handle takes that method only (NULL: every one). " +
            "mode: code (default) | comment (no code change: the plaintext becomes a comment at each call, which save() writes for " +
            "dnSpy) | both (code where it can, a comment at the sites code jumps into, as in flattened control flow). One undoable step; " +
            "returns the number of call sites replaced or commented",
            "edit", mutates: true);

        // ---- namespaces (dnSpy Namespace commands) ----
        s.Fn("rename_namespace", 2, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var old = Values.ToText(a[0]) ?? ""; var nw = Values.ToText(a[1]) ?? "";
            var types = lm.Module.Types.Where(t => t.Namespace == old).ToList();
            void Apply(string from, string to) { foreach (var t in types) Fixups.RenameType(t, to, null); ws.Touch(lm); }
            Apply(old, nw);
            ws.Record("rename_namespace", $"rename namespace {old} -> {nw}", () => Apply(nw, old), () => Apply(old, nw));
            return (long)types.Count;
        }, "rename_namespace(old, new [, module])", "rename/move all top-level types of a namespace (with TypeRef fix-ups); '' = global namespace", "edit", mutates: true);

        s.Fn("delete_namespace", 1, 2, a =>
        {
            var lm = ws.ModuleArg(a.Arg(1));
            var ns = Values.ToText(a[0]) ?? "";
            var removed = lm.Module.Types.Select((t, i) => (t, i)).Where(x => x.t.Namespace == ns && !x.t.IsGlobalModuleType).ToList();
            foreach (var (t, _) in removed) lm.Module.Types.Remove(t);
            ws.Touch(lm);
            ws.Record("delete_namespace", $"delete namespace {ns}",
                () => { foreach (var (t, i) in removed) lm.Module.Types.Insert(Math.Min(i, lm.Module.Types.Count), t); ws.Touch(lm); },
                () => { foreach (var (t, _) in removed) lm.Module.Types.Remove(t); ws.Touch(lm); });
            return (long)removed.Count;
        }, "delete_namespace(ns [, module])", "delete every top-level type in a namespace", "edit", mutates: true);

        // ---- module / assembly ----
        s.Fn("strip_strong_name", 0, 1, a =>
        {
            var lm = ws.ModuleArg(a.Arg(0));
            var asm = lm.Module.Assembly;
            var oldKey = asm?.PublicKey; var oldAttrs = asm?.Attributes; var oldFlags = lm.Module.Cor20HeaderFlags;
            void Apply()
            {
                if (asm != null) { asm.PublicKey = new PublicKey(); asm.Attributes &= ~AssemblyAttributes.PublicKey; }
                lm.Module.Cor20HeaderFlags &= ~dnlib.DotNet.MD.ComImageFlags.StrongNameSigned;
                ws.Touch(lm);
            }
            Apply();
            ws.Record("strip_strong_name", "strip strong name", () =>
            {
                if (asm != null) { asm.PublicKey = oldKey; asm.Attributes = oldAttrs!.Value; }
                lm.Module.Cor20HeaderFlags = oldFlags;
                ws.Touch(lm);
            }, Apply);
            return 1L;
        }, "strip_strong_name([module])", "remove the public key and StrongNameSigned flag (so a patched assembly loads)", "edit", mutates: true);

        s.Fn("resource_set_empty", 0, 1, a =>
        {
            var lm = ws.ModuleArg(a.Arg(0));
            using var ms = new MemoryStream();
            ResourceWriter.Write(lm.Module, ms, ResourceElementSet.CreateForResourceReader(lm.Module));
            return ms.ToArray();
        }, "resource_set_empty([module])", "bytes of an empty .resources file (dnSpy 'Create Multi-File Resource')", "edit");

        s.Fn("add_reference_type", 2, 2, a =>
        {
            var lm = ws.ModuleArg(a[0]);
            var tr = TypeSyntax.ParseTypeRef(ws, lm.Module, TableKit.Str(a[1], "type"));
            return tr is IMDTokenProvider p && p.MDToken.Rid != 0 ? lm.H(p) : (object?)tr.FullName;
        }, "add_reference_type(module, 'Full.Type.Name')", "resolve/import a type into a module (helper for operands)", "edit");

        s.Fn("import_member", 2, 2, a =>
        {
            var lm = ws.ModuleArg(a[0]);
            var (src, item) = ws.Resolve(TableKit.Lng(a[1], "handle"));
            var imp = new Importer(lm.Module, ImporterOptions.TryToUseDefs);
            object r = item switch
            {
                IMethod m => imp.Import(m),
                IField f => imp.Import(f),
                ITypeDefOrRef t => imp.Import(t),
                _ => throw new SqlException("only types, methods and fields can be imported"),
            };
            var p = (IMDTokenProvider)r;
            if (p.MDToken.Rid == 0 && r is MemberRef mr) lm.Module.UpdateRowId(mr);
            if (p.MDToken.Rid == 0 && r is TypeRef trr) lm.Module.UpdateRowId(trr);
            ws.Touch(lm);
            return p.MDToken.Rid != 0 ? lm.H(p) : null;
        }, "import_member(target_module, handle)", "create a TypeRef/MemberRef in target_module for an entity of another module; returns the new handle", "edit", mutates: true);
    }

    // What decryptor_calls computed, put where the code asks for it: each call site that interprets to a string becomes
    // ldstr. Driven by the interpreter and the call shape only, so it is the same for every protector.
    static long InlineStrings(Session s, LoadedModule lm, long? decryptor, string mode)
    {
        if (mode is not ("code" or "comment" or "both")) throw new SqlException($"mode '{mode}' is not code, comment or both");
        var sites = new List<(MethodDef Caller, Instruction Call, int Args, string Text)>();
        int skipped = 0;
        // every plaintext first: the first edit starts the interpreter afresh
        foreach (var c in ProtectionTables.Calls(s, lm, decryptor, 5).Where(c => decryptor != null || !TriageTables.IsLibrary(c.Decryptor)).ToList())
        {
            var (value, status) = c.Plain.Value;
            var ins = c.Site.From.Body?.Instructions;
            if (status != "ok" || value is not string text || !ReturnsString(c) || ins == null || c.Site.Index >= ins.Count
                || !ReferenceEquals(ins[c.Site.Index].Operand, c.Site.Operand)) { skipped++; continue; }
            sites.Add((c.Site.From, ins[c.Site.Index], c.Args.Count, text));
        }
        if (mode == "comment") return Comment(s, lm, sites.Select(x => (x.Caller, x.Call.Offset, x.Text)).ToList());
        long done = 0;
        int shared = 0;
        var annotate = new List<(MethodDef Caller, Instruction Call, int Args, string Text)>(); // offsets read after the edits move them
        foreach (var g in sites.GroupBy(x => x.Caller))
        {
            var targets = Targets(g.Key.Body);
            var clean = g.Where(x => Clean(g.Key.Body, x.Call, x.Args, targets) is not null).ToList();
            shared += g.Count() - clean.Count;
            if (mode == "both") annotate.AddRange(g.Except(clean));
            if (clean.Count == 0) continue;
            BodyEditor.Edit(s, g.Key, "inline_strings", b =>
            {
                foreach (var (_, call, n, text) in clean)
                {
                    foreach (var x in Clean(b, call, n, targets)!) { x.OpCode = OpCodes.Nop; x.Operand = null; }
                    call.OpCode = OpCodes.Ldstr; call.Operand = text;
                    done++;
                }
            });
        }
        if (skipped > 0)
            s.Notices.Add($"inline_strings: {skipped} call site(s) left as they are (not interpreted, or not a string: see decryptor_calls.emulation)");
        if (annotate.Count > 0) done += Comment(s, lm, annotate.Select(x => (x.Caller, x.Call.Offset, x.Text)).ToList());
        else if (shared > 0)
            s.Notices.Add($"inline_strings: {shared} call site(s) left as they are: code jumps into their arguments, so other paths pass other " +
                          "values (flattened control flow); their plaintexts are in decryptor_calls, and inline_strings(module, decryptor, 'both') " +
                          "writes them as comments there");
        return done;
    }

    // The plaintext as a comment at each call (the comments table, which save() writes as XML documentation for dnSpy):
    // for code a rewrite would break, or when the code must stay as it is. One undoable step with the statement's edits.
    static long Comment(Session s, LoadedModule lm, List<(MethodDef Caller, uint Offset, string Text)> sites)
    {
        var added = new List<CommentRec>();
        var replaced = new List<CommentRec>();
        foreach (var (caller, offset, text) in sites)
        {
            var at = AnnotationTables.Loc(s, lm.H(caller), (long)offset);
            replaced.AddRange(s.Store.Comments.Where(c => c.At.Mvid == at.Mvid && c.At.Token == at.Token && c.At.Offset == at.Offset));
            s.Store.Comments.RemoveAll(c => c.At.Mvid == at.Mvid && c.At.Token == at.Token && c.At.Offset == at.Offset);
            var shown = text.Length > 500 ? text[..500] + "…" : text;
            var rec = new CommentRec { Id = s.Store.NewId(), At = at, Text = $"decrypted: \"{Output.Visible(shown)}\"" };
            s.Store.Comments.Add(rec);
            added.Add(rec);
        }
        s.Store.Changed();
        s.Ws.Record("comments", $"inline_strings: {added.Count} comment(s)",
            () => { foreach (var c in added) s.Store.Comments.Remove(c); s.Store.Comments.AddRange(replaced); s.Store.Changed(); },
            () => { foreach (var c in replaced) s.Store.Comments.Remove(c); s.Store.Comments.AddRange(added); s.Store.Changed(); });
        return added.Count;
    }

    // a string where the code expects one: string, object, or a generic T the call site instantiates with string
    static bool ReturnsString(ProtectionTables.DecryptorCall c) => c.Decryptor.MethodSig?.RetType?.ElementType switch
    {
        ElementType.String or ElementType.Object => true,
        ElementType.MVar => c.Site.Operand is MethodSpec { GenericInstMethodSig.GenericArguments: [{ ElementType: ElementType.String }] },
        _ => false,
    };

    // instructions something jumps to, or a handler starts or ends at
    static HashSet<Instruction> Targets(CilBody b)
    {
        var set = new HashSet<Instruction>();
        foreach (var i in b.Instructions)
            if (i.Operand is Instruction t) set.Add(t);
            else if (i.Operand is Instruction[] ts) set.UnionWith(ts);
        foreach (var eh in b.ExceptionHandlers)
            foreach (var x in new[] { eh.TryStart, eh.TryEnd, eh.HandlerStart, eh.HandlerEnd, eh.FilterStart })
                if (x != null) set.Add(x);
        return set;
    }

    // The argument pushes of a call, found the way decryptor_calls found them (over nops and a branch to the next
    // instruction), when the call and its arguments are one straight sequence; null when code jumps into it (past its
    // first push), since another path then arrives with other values, or a prefix (volatile.) stands in front of it.
    static List<Instruction>? Clean(CilBody b, Instruction call, int n, HashSet<Instruction> targets)
    {
        var ins = b.Instructions;
        int at = ins.IndexOf(call);
        if (at < 0 || targets.Contains(call)) return null;
        var args = new List<Instruction>();
        int i = at - 1;
        for (; args.Count < n && i >= 0; i--)
        {
            bool filler = ins[i].OpCode.Code == Code.Nop || ins[i].OpCode.Code is Code.Br or Code.Br_S && ReferenceEquals(ins[i].Operand, ins[i + 1]);
            if (!filler) args.Add(ins[i]);
            if (args.Count < n && targets.Contains(ins[i])) return null; // a jump lands after the first push
        }
        if (args.Count < n || i >= 0 && ins[i].OpCode.OpCodeType == OpCodeType.Prefix) return null;
        return args;
    }

    static Instruction Ins(CilBody b, int i) =>
        i >= 0 && i < b.Instructions.Count ? b.Instructions[i] : throw new SqlException($"instruction index {i} out of range 0..{b.Instructions.Count - 1}");
}
