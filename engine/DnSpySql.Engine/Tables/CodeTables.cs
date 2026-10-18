// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

public sealed record InsRow(LoadedModule M, MethodDef Method, Instruction Ins, int Index) : IHasModule;

/// <summary>Method bodies: IL instructions, locals, exception handlers, basic blocks, CFG, literals.</summary>
public static class CodeTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        // ================= il =================
        var il = new Table<InsRow>("il",
            "IL instructions (one row per instruction); WHERE method = <handle> reads one body, without it every body is scanned (e.g. WHERE opcode = 'callvirt'). UPDATE opcode/operand, INSERT before idx, DELETE") { Domain = "code" };
        il.Source(c =>
            {
                // idx = n / BETWEEN: only those instructions (a self-join on neighbours looks one up per row)
                var (lo, hi) = c.LongRange("idx", 0, int.MaxValue);
                return MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody).SelectMany(r =>
                {
                    var ins = r.Item.Body.Instructions;
                    int from = (int)Math.Max(lo, 0), to = (int)Math.Min(hi, ins.Count - 1L);
                    return Enumerable.Range(from, Math.Max(to - from + 1, 0)).Select(i => new InsRow(r.M, r.Item, ins[i], i));
                });
            })
            .Int("module", r => r.M.Id)
            .Int("method", r => r.M.H(r.Method), pushdown: Pushdown.Eq)
            .Int("idx", r => r.Index, pushdown: Pushdown.Range, doc: "instruction index (use for branch targets and il_* functions)")
            .Int("offset", r => r.Ins.Offset)
            .Text("opcode", r => r.Ins.OpCode.Name, pushdown: Pushdown.Eq, set: (r, v) => BodyEditor.Edit(s, r.Method, $"il[{r.Index}].opcode", _ =>
            {
                var op = BodyKit.ParseOpCode(Str(v, "opcode"));
                var keep = OperandCompatible(op, r.Ins.Operand);
                r.Ins.OpCode = op;
                if (!keep) r.Ins.Operand = op.OperandType == OperandType.InlineNone ? null : throw new SqlException($"{op.Name} needs a different operand; UPDATE opcode and operand together");
            }))
            .Col("operand", SqlType.Any, r => OperandValue(r.M, r.Method, r.Ins), (r, v) => BodyEditor.Edit(s, r.Method, $"il[{r.Index}].operand",
                _ => r.Ins.Operand = BodyKit.ParseOperand(ws, r.Method, r.Ins.OpCode, v)),
                doc: "literal, branch target index, local/arg index, or metadata handle")
            .Text("operand_text", r => BodyKit.OperandText(r.Ins, r.Method.Body))
            .Text("operand_kind", r => r.Ins.OpCode.OperandType.ToString())
            .Int("operand_def", r => r.Ins.Operand is IMemberRef mr ? MemberTables.DefHandle(ws, mr) : null,
                doc: "resolved definition handle of a metadata operand (if in a loaded module)")
            .Int("size", r => r.Ins.GetSize())
            .Text("flow", r => r.Ins.OpCode.FlowControl.ToString().ToLowerInvariant())
            .Int("stack_push", r => { r.Ins.CalculateStackUsage(r.Method.HasReturnType, out var push, out _); return push; })
            .Int("stack_pop", r => { r.Ins.CalculateStackUsage(r.Method.HasReturnType, out _, out var pop); return pop; })
            .Int("line", r => r.Ins.SequencePoint?.StartLine is int l && l != 0xFEEFEE ? l : null, doc: "source line from the PDB sequence point")
            .Text("text", r => $"IL_{r.Ins.Offset:X4}: {r.Ins.OpCode.Name}{(r.Ins.Operand == null ? "" : " " + BodyKit.OperandText(r.Ins, r.Method.Body))}");
        il.JournalUpdates = false;
        il.OnInsert(v =>
        {
            var m = ws.Resolve<MethodDef>(v.GetValueOrDefault("method"), "method");
            var op = BodyKit.ParseOpCode(Str(v.GetValueOrDefault("opcode"), "opcode"));
            BodyEditor.Edit(s, m, "INSERT INTO il", body =>
            {
                var idx = v.TryGetValue("idx", out var iv) && iv != null ? (int)Lng(iv, "idx") : body.Instructions.Count;
                if (idx < 0 || idx > body.Instructions.Count) throw new SqlException($"idx {idx} out of range 0..{body.Instructions.Count}");
                var operand = BodyKit.ParseOperand(ws, m, op, v.GetValueOrDefault("operand"));
                body.Instructions.Insert(idx, new Instruction(op, operand));
            });
            return (0, null, null);
        }).OnDelete(r =>
        {
            BodyEditor.Edit(s, r.Method, $"DELETE il[{r.Index}]", body => BodyEditor.RemoveAt(body, body.Instructions.IndexOf(r.Ins)));
            return (null, null);
        }).Estimate(1_000_000);
        db.Register(il);

        // ================= locals =================
        var locals = new Table<Row<(MethodDef m, Local l)>>("locals", "Local variables of a method body (names from the PDB). WHERE method = ... reads one body") { Domain = "code" };
        locals.Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody)
                .SelectMany(r => r.Item.Body.Variables.Select(l => new Row<(MethodDef, Local)>(r.M, (r.Item, l)))))
            .Int("module", r => r.M.Id)
            .Int("method", r => r.M.H(r.Item.m), pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.l.Index)
            .Text("name", r => r.Item.l.Name, (r, v) => BodyEditor.Edit(s, r.Item.Item1, "rename local", _ => r.Item.Item2.Name = Values.ToText(v)))
            .Text("type", r => r.Item.l.Type?.FullName, (r, v) => BodyEditor.Edit(s, r.Item.Item1, "retype local",
                _ => r.Item.Item2.Type = TypeSyntax.Parse(ws, r.M.Module, Str(v, "type"))))
            .Bool("is_pinned", r => r.Item.l.Type is PinnedSig);
        locals.JournalUpdates = false;
        locals.OnInsert(v =>
        {
            var m = ws.Resolve<MethodDef>(v.GetValueOrDefault("method"), "method");
            BodyEditor.Edit(s, m, "INSERT INTO locals", body =>
            {
                var t = TypeSyntax.Parse(ws, m.Module, Values.ToText(v.GetValueOrDefault("type")) ?? "object");
                body.Variables.Add(new Local(t, Values.ToText(v.GetValueOrDefault("name"))));
            });
            return (0, null, null);
        }).OnDelete(r =>
        {
            var (m, l) = r.Item;
            if (m.Body.Instructions.Any(i => i.Operand == l)) throw new SqlException($"local {l.Index} is still used by instructions");
            BodyEditor.Edit(s, m, "DELETE FROM locals", body => body.Variables.Remove(l));
            return (null, null);
        });
        db.Register(locals);

        // ================= exception handlers =================
        var ehs = new Table<Row<(MethodDef m, ExceptionHandler eh, int i)>>("exception_handlers",
            "try/catch/finally/fault/filter regions. Boundaries are instruction indexes (NULL end = end of method)") { Domain = "code" };
        int Idx(MethodDef m, Instruction? ins) => ins == null ? m.Body.Instructions.Count : m.Body.Instructions.IndexOf(ins);
        Instruction? At(MethodDef m, object? v) => v == null ? null : (int)Lng(v, "index") is var i && i >= m.Body.Instructions.Count ? null : m.Body.Instructions[i];
        ehs.Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody)
                .SelectMany(r => r.Item.Body.ExceptionHandlers.Select((eh, i) => new Row<(MethodDef, ExceptionHandler, int)>(r.M, (r.Item, eh, i)))))
            .Int("module", r => r.M.Id)
            .Int("method", r => r.M.H(r.Item.m), pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.i)
            .Text("kind", r => r.Item.eh.HandlerType.ToString().ToLowerInvariant())
            .Int("try_start", r => Idx(r.Item.m, r.Item.eh.TryStart))
            .Int("try_end", r => Idx(r.Item.m, r.Item.eh.TryEnd))
            .Int("handler_start", r => Idx(r.Item.m, r.Item.eh.HandlerStart))
            .Int("handler_end", r => Idx(r.Item.m, r.Item.eh.HandlerEnd))
            .Int("filter_start", r => r.Item.eh.FilterStart == null ? null : Idx(r.Item.m, r.Item.eh.FilterStart))
            .Int("try_start_offset", r => r.Item.eh.TryStart?.Offset)
            .Int("handler_start_offset", r => r.Item.eh.HandlerStart?.Offset)
            .Text("catch_type", r => r.Item.eh.CatchType?.FullName, (r, v) => BodyEditor.Edit(s, r.Item.Item1, "eh.catch_type",
                _ => r.Item.Item2.CatchType = v == null ? null : TypeSyntax.ParseTypeRef(ws, r.M.Module, Str(v, "catch_type"))));
        ehs.JournalUpdates = false;
        ehs.OnInsert(v =>
        {
            var m = ws.Resolve<MethodDef>(v.GetValueOrDefault("method"), "method");
            BodyEditor.Edit(s, m, "INSERT INTO exception_handlers", body =>
            {
                var kind = Enum.Parse<ExceptionHandlerType>(Str(v.GetValueOrDefault("kind"), "kind"), true);
                var eh = new ExceptionHandler(kind)
                {
                    TryStart = At(m, v.GetValueOrDefault("try_start")), TryEnd = At(m, v.GetValueOrDefault("try_end")),
                    HandlerStart = At(m, v.GetValueOrDefault("handler_start")), HandlerEnd = At(m, v.GetValueOrDefault("handler_end")),
                    FilterStart = At(m, v.GetValueOrDefault("filter_start")),
                    CatchType = Values.ToText(v.GetValueOrDefault("catch_type")) is string ct ? TypeSyntax.ParseTypeRef(ws, m.Module, ct)
                        : kind == ExceptionHandlerType.Catch ? m.Module.CorLibTypes.Object.TypeDefOrRef : null,
                };
                body.ExceptionHandlers.Add(eh);
            });
            return (0, null, null);
        }).OnDelete(r =>
        {
            BodyEditor.Edit(s, r.Item.m, "DELETE FROM exception_handlers", body => body.ExceptionHandlers.Remove(r.Item.eh));
            return (null, null);
        });
        db.Register(ehs);

        // ================= basic blocks and CFG =================
        db.Register(new Table<Row<(MethodDef m, Cfg.Block b)>>("blocks", "Basic blocks of a method's IL. WHERE method = ... reads one body") { Domain = "code" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody)
                .SelectMany(r => Cfg.Build(r.Item.Body).Blocks.Select(b => new Row<(MethodDef, Cfg.Block)>(r.M, (r.Item, b)))))
            .Int("module", r => r.M.Id)
            .Int("method", r => r.M.H(r.Item.m), pushdown: Pushdown.Eq)
            .Int("block_id", r => r.Item.b.Id)
            .Int("start_idx", r => r.Item.b.Start)
            .Int("end_idx", r => r.Item.b.End, doc: "inclusive")
            .Int("start_offset", r => r.Item.m.Body.Instructions[r.Item.b.Start].Offset)
            .Int("end_offset", r => { var i = r.Item.m.Body.Instructions[r.Item.b.End]; return i.Offset + i.GetSize(); })
            .Int("instr_count", r => r.Item.b.End - r.Item.b.Start + 1)
            .Int("in_degree", r => r.Item.b.Preds.Count)
            .Int("out_degree", r => r.Item.b.Succs.Count)
            .Bool("is_entry", r => r.Item.b.Start == 0)
            .Bool("is_exit", r => r.Item.b.Succs.Count == 0)
            .Text("region", r => r.Item.b.Region));

        db.Register(new Table<Row<(MethodDef m, Cfg.Edge e)>>("cfg_edges", "Control-flow edges between basic blocks. WHERE method = ... reads one body") { Domain = "code" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody)
                .SelectMany(r => Cfg.Build(r.Item.Body).Edges.Select(e => new Row<(MethodDef, Cfg.Edge)>(r.M, (r.Item, e)))))
            .Int("module", r => r.M.Id)
            .Int("method", r => r.M.H(r.Item.m), pushdown: Pushdown.Eq)
            .Int("from_block", r => r.Item.e.From)
            .Int("to_block", r => r.Item.e.To)
            .Text("kind", r => r.Item.e.Kind));

        // ================= literals (dnSpy 'Number/String literal' search) =================
        db.Register(new Table<InsRow>("literals", "Constant literals loaded by IL (ldc.*, ldstr): dnSpy literal search") { Domain = "code" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody)
                .SelectMany(r => r.Item.Body.Instructions.Select((ins, i) => new InsRow(r.M, r.Item, ins, i)).Where(x => IsLiteral(x.Ins))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.M.H(r.Method), pushdown: Pushdown.Eq)
            .Text("method_name", r => r.Method.FullName)
            .Int("idx", r => r.Index)
            .Int("offset", r => r.Ins.Offset)
            .Text("opcode", r => r.Ins.OpCode.Name)
            .Text("kind", r => r.Ins.OpCode.Code == Code.Ldstr ? "string" : r.Ins.OpCode.Code is Code.Ldc_R4 or Code.Ldc_R8 ? "real" : "int")
            .Col("value", SqlType.Any, r => r.Ins.OpCode.Code switch
            {
                Code.Ldstr => r.Ins.Operand as string,
                Code.Ldc_R4 or Code.Ldc_R8 => Convert.ToDouble(r.Ins.Operand),
                Code.Ldc_I8 => (long)r.Ins.Operand,
                _ => (object)(long)r.Ins.GetLdcI4Value(),
            }));
    }

    static bool IsLiteral(Instruction i) => i.OpCode.Code switch
    {
        Code.Ldstr or Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I8 or Code.Ldc_R4 or Code.Ldc_R8 => true,
        Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3 or Code.Ldc_I4_4 or Code.Ldc_I4_5
            or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I4_M1 => true,
        _ => false,
    };

    static bool OperandCompatible(OpCode op, object? operand) => op.OperandType switch
    {
        OperandType.InlineNone => operand == null,
        OperandType.InlineBrTarget or OperandType.ShortInlineBrTarget => operand is Instruction,
        OperandType.InlineSwitch => operand is Instruction[],
        OperandType.InlineMethod => operand is IMethod,
        OperandType.InlineField => operand is IField,
        OperandType.InlineType => operand is ITypeDefOrRef,
        OperandType.InlineString => operand is string,
        OperandType.InlineVar or OperandType.ShortInlineVar => operand is Local or Parameter,
        OperandType.InlineI => operand is int,
        OperandType.ShortInlineI => operand is sbyte or byte,
        OperandType.InlineI8 => operand is long,
        OperandType.ShortInlineR => operand is float,
        OperandType.InlineR => operand is double,
        OperandType.InlineTok => operand is IMDTokenProvider,
        _ => false,
    };

    /// <summary>SQL value of an operand: literal, index (branch/local/arg) or handle.</summary>
    public static object? OperandValue(LoadedModule lm, MethodDef m, Instruction ins) => ins.Operand switch
    {
        null => null,
        Instruction t => (long)m.Body.Instructions.IndexOf(t),
        Instruction[] ts => string.Join(",", ts.Select(t => m.Body.Instructions.IndexOf(t))),
        Local l => (long)l.Index,
        Parameter p => (long)p.Index,
        IMDTokenProvider tp when tp.MDToken.Raw != 0 && (tp.MDToken.Rid != 0) => lm.H(tp),
        IFullName fn => fn.FullName,
        sbyte sb => (long)sb,
        var o => TableKit.SqlValue(o),
    };
}

/// <summary>Basic block / CFG construction over CIL.</summary>
public static class Cfg
{
    public sealed class Block
    {
        public int Id, Start, End;
        public string Region = "";
        public List<int> Succs = new(), Preds = new();
    }

    public sealed record Edge(int From, int To, string Kind);

    public sealed class Graph
    {
        public List<Block> Blocks = new();
        public List<Edge> Edges = new();
    }

    public static Graph Build(CilBody body)
    {
        var ins = body.Instructions;
        var g = new Graph();
        if (ins.Count == 0) return g;
        var index = new Dictionary<Instruction, int>();
        for (int i = 0; i < ins.Count; i++) index[ins[i]] = i;
        var leaders = new SortedSet<int> { 0 };
        void Lead(Instruction? x) { if (x != null && index.TryGetValue(x, out var k)) leaders.Add(k); }
        for (int i = 0; i < ins.Count; i++)
        {
            var x = ins[i];
            if (x.Operand is Instruction t) Lead(t);
            if (x.Operand is Instruction[] ts) foreach (var tt in ts) Lead(tt);
            var fc = x.OpCode.FlowControl;
            if (fc is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw && i + 1 < ins.Count) leaders.Add(i + 1);
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            Lead(eh.TryStart); Lead(eh.TryEnd); Lead(eh.HandlerStart); Lead(eh.HandlerEnd); Lead(eh.FilterStart);
        }
        var starts = leaders.ToList();
        var blockOf = new int[ins.Count];
        for (int b = 0; b < starts.Count; b++)
        {
            int end = b + 1 < starts.Count ? starts[b + 1] - 1 : ins.Count - 1;
            g.Blocks.Add(new Block { Id = b, Start = starts[b], End = end, Region = Region(body, ins[starts[b]], index) });
            for (int i = starts[b]; i <= end; i++) blockOf[i] = b;
        }
        void AddEdge(int from, Instruction? to, string kind)
        {
            if (to == null || !index.TryGetValue(to, out var k)) return;
            AddEdgeTo(from, blockOf[k], kind);
        }
        void AddEdgeTo(int from, int to, string kind)
        {
            g.Edges.Add(new Edge(from, to, kind));
            g.Blocks[from].Succs.Add(to);
            g.Blocks[to].Preds.Add(from);
        }
        foreach (var b in g.Blocks)
        {
            var last = ins[b.End];
            switch (last.OpCode.FlowControl)
            {
                case FlowControl.Branch:
                    AddEdge(b.Id, last.Operand as Instruction, last.OpCode.Code is Code.Leave or Code.Leave_S ? "leave" : "jump");
                    break;
                case FlowControl.Cond_Branch:
                    if (last.Operand is Instruction[] cases)
                    {
                        foreach (var c in cases) AddEdge(b.Id, c, "switch_case");
                        if (b.End + 1 < ins.Count) AddEdgeTo(b.Id, blockOf[b.End + 1], "switch_default");
                    }
                    else
                    {
                        AddEdge(b.Id, last.Operand as Instruction, "true");
                        if (b.End + 1 < ins.Count) AddEdgeTo(b.Id, blockOf[b.End + 1], "false");
                    }
                    break;
                case FlowControl.Return:
                case FlowControl.Throw:
                    break;
                default:
                    if (b.End + 1 < ins.Count) AddEdgeTo(b.Id, blockOf[b.End + 1], "fallthrough");
                    break;
            }
        }
        foreach (var eh in body.ExceptionHandlers)
        {
            if (eh.TryStart == null || !index.TryGetValue(eh.TryStart, out var ts)) continue;
            AddEdge(blockOf[ts], eh.HandlerStart, eh.HandlerType.ToString().ToLowerInvariant());
            if (eh.FilterStart != null) AddEdge(blockOf[ts], eh.FilterStart, "filter");
        }
        return g;
    }

    static string Region(CilBody body, Instruction at, Dictionary<Instruction, int> index)
    {
        int pos = index[at];
        int Pos(Instruction? i) => i == null ? int.MaxValue : index.TryGetValue(i, out var k) ? k : int.MaxValue;
        foreach (var eh in body.ExceptionHandlers)
        {
            if (pos >= Pos(eh.HandlerStart) && pos < Pos(eh.HandlerEnd)) return eh.HandlerType.ToString().ToLowerInvariant();
            if (eh.FilterStart != null && pos >= Pos(eh.FilterStart) && pos < Pos(eh.HandlerStart)) return "filter";
        }
        foreach (var eh in body.ExceptionHandlers)
            if (pos >= Pos(eh.TryStart) && pos < Pos(eh.TryEnd)) return "try";
        return "";
    }
}
