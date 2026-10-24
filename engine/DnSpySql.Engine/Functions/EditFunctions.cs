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

    static Instruction Ins(CilBody b, int i) =>
        i >= 0 && i < b.Instructions.Count ? b.Instructions[i] : throw new SqlException($"instruction index {i} out of range 0..{b.Instructions.Count - 1}");
}
