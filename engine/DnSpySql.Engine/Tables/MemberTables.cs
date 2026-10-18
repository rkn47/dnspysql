// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>Types and their members: the dnSpy document tree as tables.</summary>
public static class MemberTables
{
    // dnlib prints "<<<NULL>>>" for a member whose signature (or name) is missing, as in a truncated file whose heaps end
    // early: the type, the name (or the token) and "(?)" say which member it is
    internal static string Readable(IMemberDef m)
    {
        var full = m.FullName;
        if (!full.Contains("<<<NULL>>>", StringComparison.Ordinal)) return full;
        var name = string.IsNullOrEmpty(m.Name?.String) ? $"<0x{m.MDToken.Raw:X8}>" : m.Name.String;
        return $"{m.DeclaringType?.FullName}::{name}(?)";
    }

    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        // ================= types =================
        var types = s.DefTable<TypeDef>("types", "metadata", "TypeDefs (including nested and <Module>); dnSpy 'Edit Type' surface",
            m => m.Module.GetTypes(), fast: (m, c) =>
            {
                if (c.Text("full_name") is string fn) return m.Module.Find(fn, false) is TypeDef t ? new[] { t } : Array.Empty<TypeDef>();
                if (c.Long("declaring_type") is long dt && Handle.Module(ws.Normalize(dt)) == m.Id)
                    return (m.Module.ResolveToken(Handle.Token(ws.Normalize(dt))) as TypeDef)?.NestedTypes ?? (IEnumerable<TypeDef>)Array.Empty<TypeDef>();
                return null;
            });
        types
            .Text("namespace", r => r.Item.Namespace.String, s.Setter<Row<TypeDef>>((r, v) => Fixups.RenameType(r.Item, Values.ToText(v) ?? "", null)))
            .Text("name", r => r.Item.Name.String, s.Setter<Row<TypeDef>>((r, v) => Fixups.RenameType(r.Item, null, Str(v, "name"))))
            .Text("full_name", r => r.Item.FullName, pushdown: Pushdown.Eq, doc: "Namespace.Name, nested types use '/'")
            .Text("kind", r => TypeKind(r.Item), s.Setter<Row<TypeDef>>((r, v) => SetTypeKind(ws, r.Item, Str(v, "kind"))),
                doc: "class | static class | interface | struct | enum | delegate | module (UPDATE applies dnSpy's kind presets)")
            .Text("visibility", r => Visibility(r.Item.Attributes),
                s.Setter<Row<TypeDef>>((r, v) => r.Item.Visibility = ParseTypeVisibility(Str(v, "visibility"), r.Item.IsNested)))
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<TypeDef>>((r, v) => r.Item.Attributes = (TypeAttributes)Lng(v, "flags")))
            .Text("flags_text", r => r.Item.Attributes.ToString())
            .Bool("is_abstract", r => r.Item.IsAbstract, s.Setter<Row<TypeDef>>((r, v) => r.Item.IsAbstract = Values.ToBool(v)))
            .Bool("is_sealed", r => r.Item.IsSealed, s.Setter<Row<TypeDef>>((r, v) => r.Item.IsSealed = Values.ToBool(v)))
            .Bool("is_interface", r => r.Item.IsInterface)
            .Bool("is_value_type", r => r.Item.IsValueType)
            .Bool("is_enum", r => r.Item.IsEnum)
            .Bool("is_delegate", r => r.Item.IsDelegate)
            .Bool("is_nested", r => r.Item.IsNested)
            .Bool("is_generic", r => r.Item.HasGenericParameters)
            .Bool("is_serializable", r => r.Item.IsSerializable, s.Setter<Row<TypeDef>>((r, v) => r.Item.IsSerializable = Values.ToBool(v)))
            .Bool("is_compiler_generated", r => IsCompilerGenerated(r.Item))
            .Bool("is_global", r => r.Item.IsGlobalModuleType)
            .Int("declaring_type", r => r.Item.DeclaringType is { } d ? r.M.H(d) : null, pushdown: Pushdown.Eq)
            .Text("declaring_type_name", r => r.Item.DeclaringType?.FullName)
            .Int("base_type", r => DefHandle(ws, r.Item.BaseType), doc: "handle of the base type when it is defined in a loaded module")
            .Text("base_type_name", r => r.Item.BaseType?.FullName,
                s.Setter<Row<TypeDef>>((r, v) => r.Item.BaseType = v == null ? null : TypeSyntax.ParseTypeRef(ws, r.M.Module, Str(v, "base_type_name"))))
            .Text("layout", r => (r.Item.Attributes & TypeAttributes.LayoutMask) switch
                { TypeAttributes.SequentialLayout => "sequential", TypeAttributes.ExplicitLayout => "explicit", _ => "auto" },
                s.Setter<Row<TypeDef>>((r, v) => r.Item.Layout = Str(v, "layout").ToLowerInvariant() switch
                {
                    "auto" => TypeAttributes.AutoLayout, "sequential" => TypeAttributes.SequentialLayout, "explicit" => TypeAttributes.ExplicitLayout,
                    var x => throw new SqlException($"unknown layout '{x}'"),
                }))
            .Text("charset", r => (r.Item.Attributes & TypeAttributes.StringFormatMask) switch
                {
                    TypeAttributes.UnicodeClass => "UnicodeClass", TypeAttributes.AutoClass => "AutoClass",
                    TypeAttributes.CustomFormatClass => "CustomFormatClass", _ => "AnsiClass",
                })
            .Int("packing_size", r => r.Item.ClassLayout?.PackingSize, s.Setter<Row<TypeDef>>((r, v) => SetLayout(r.Item, v, null)))
            .Int("class_size", r => r.Item.ClassLayout is { } cl ? (long)cl.ClassSize : null, s.Setter<Row<TypeDef>>((r, v) => SetLayout(r.Item, null, v)))
            .Text("enum_underlying_type", r => r.Item.IsEnum ? r.Item.GetEnumUnderlyingType()?.FullName : null)
            .Int("generic_param_count", r => r.Item.GenericParameters.Count)
            .Int("interface_count", r => r.Item.Interfaces.Count)
            .Int("method_count", r => r.Item.Methods.Count)
            .Int("field_count", r => r.Item.Fields.Count)
            .Int("property_count", r => r.Item.Properties.Count)
            .Int("event_count", r => r.Item.Events.Count)
            .Int("nested_count", r => r.Item.NestedTypes.Count)
            .Int("attribute_count", r => r.Item.CustomAttributes.Count);
        types.OnInsert(v => InsertType(s, v)).OnDelete(r => DeleteType(s, r)).Estimate(5_000);
        db.Register(types);

        // ================= interfaces =================
        var ifaces = new Table<Row<(TypeDef type, InterfaceImpl ii)>>("interfaces", "InterfaceImpl rows: interfaces implemented by each type") { Domain = "metadata" };
        ifaces.Source(c => TypeScope(ws, c, "type").SelectMany(r => r.Item.Interfaces.Select(ii => new Row<(TypeDef, InterfaceImpl)>(r.M, (r.Item, ii)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("handle", r => r.M.H(r.Item.ii))
            .Int("type", r => r.M.H(r.Item.type), pushdown: Pushdown.Eq)
            .Text("type_name", r => r.Item.type.FullName)
            .Int("interface", r => DefHandle(ws, r.Item.ii.Interface))
            .Text("interface_name", r => r.Item.ii.Interface?.FullName);
        ifaces.OnInsert(v =>
        {
            var type = ws.Resolve<TypeDef>(v.GetValueOrDefault("type"), "type");
            var lm = ws.ModuleOf(type);
            var iface = TypeSyntax.ParseTypeRef(ws, type.Module, Str(v.GetValueOrDefault("interface_name"), "interface_name"));
            var ii = new InterfaceImplUser(iface);
            type.Interfaces.Add(ii);
            ws.Touch(lm);
            return (0, () => { type.Interfaces.Remove(ii); ws.Touch(lm); }, () => { type.Interfaces.Add(ii); ws.Touch(lm); });
        }).OnDelete(r =>
        {
            var (type, ii) = r.Item;
            int idx = type.Interfaces.IndexOf(ii);
            type.Interfaces.RemoveAt(idx);
            ws.Touch(r.M);
            return (() => { type.Interfaces.Insert(idx, ii); ws.Touch(r.M); }, () => { type.Interfaces.Remove(ii); ws.Touch(r.M); });
        });
        db.Register(ifaces);

        // ================= methods =================
        var methods = s.DefTable<MethodDef>("methods", "metadata", "MethodDefs: signature, flags, body summary; dnSpy 'Edit Method' surface",
            m => m.Module.GetTypes().SelectMany(t => t.Methods), fast: (m, c) =>
            {
                if (c.Long("type") is long th && Handle.Module(ws.Normalize(th)) == m.Id)
                    return (m.Module.ResolveToken(Handle.Token(ws.Normalize(th))) as TypeDef)?.Methods ?? (IEnumerable<MethodDef>)Array.Empty<MethodDef>();
                if (c.Long("type") is long) return Array.Empty<MethodDef>();
                return null;
            });
        methods
            .Int("type", r => r.M.H(r.Item.DeclaringType), pushdown: Pushdown.Eq, doc: "declaring type handle")
            .Text("type_name", r => r.Item.DeclaringType?.FullName)
            .Text("name", r => r.Item.Name.String, s.Setter<Row<MethodDef>>((r, v) => Fixups.RenameMember(r.Item, Str(v, "name"))))
            .Text("full_name", r => Readable(r.Item))
            .Text("signature", r => Signature(r.Item), doc: "C#-like: ReturnType Name(T1, T2)")
            .Text("return_type", r => r.Item.ReturnType?.FullName, s.Setter<Row<MethodDef>>((r, v) =>
            {
                r.Item.MethodSig = r.Item.MethodSig.Clone();
                r.Item.MethodSig.RetType = TypeSyntax.Parse(ws, r.M.Module, Str(v, "return_type"));
            }))
            .Int("param_count", r => r.Item.MethodSig?.Params.Count ?? 0)
            .Int("generic_param_count", r => r.Item.GenericParameters.Count)
            .Text("visibility", r => Visibility(r.Item.Attributes), s.Setter<Row<MethodDef>>((r, v) => r.Item.Access = ParseMethodVisibility(Str(v, "visibility"))))
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<MethodDef>>((r, v) => r.Item.Attributes = (MethodAttributes)Lng(v, "flags")))
            .Text("flags_text", r => r.Item.Attributes.ToString())
            .Int("impl_flags", r => (long)r.Item.ImplAttributes, s.Setter<Row<MethodDef>>((r, v) => r.Item.ImplAttributes = (MethodImplAttributes)Lng(v, "impl_flags")))
            .Text("impl_flags_text", r => r.Item.ImplAttributes.ToString())
            .Bool("is_static", r => r.Item.IsStatic)
            .Bool("is_virtual", r => r.Item.IsVirtual)
            .Bool("is_abstract", r => r.Item.IsAbstract)
            .Bool("is_final", r => r.Item.IsFinal)
            .Bool("is_newslot", r => r.Item.IsNewSlot)
            .Bool("is_special_name", r => r.Item.IsSpecialName)
            .Bool("is_ctor", r => r.Item.IsInstanceConstructor)
            .Bool("is_cctor", r => r.Item.IsStaticConstructor)
            .Bool("is_pinvoke", r => r.Item.IsPinvokeImpl)
            .Bool("is_internal_call", r => r.Item.IsInternalCall)
            .Bool("is_runtime", r => r.Item.IsRuntime)
            .Bool("is_native", r => r.Item.IsNative)
            .Bool("is_extern", r => !r.Item.HasBody && !r.Item.IsAbstract)
            .Bool("is_compiler_generated", r => IsCompilerGenerated(r.Item) || IsCompilerGenerated(r.Item.DeclaringType))
            .Bool("is_entry_point", r => ReferenceEquals(r.M.Module.ManagedEntryPoint, r.Item))
            .Bool("has_body", r => r.Item.HasBody)
            .Int("rva", r => (long)PeTables.FileRva(r.M, r.Item))
            .Int("file_offset", r => PeTables.FileRva(r.M, r.Item) is var rva and not 0 ? PeTables.RvaToOffset(r.M, rva) : null)
            .Int("code_size", r => CodeSize(r.Item))
            .Int("instr_count", r => r.Item.HasBody ? r.Item.Body.Instructions.Count : null)
            .Int("local_count", r => r.Item.HasBody ? r.Item.Body.Variables.Count : null)
            .Int("eh_count", r => r.Item.HasBody ? r.Item.Body.ExceptionHandlers.Count : null)
            .Int("max_stack", r => r.Item.HasBody ? r.Item.Body.MaxStack : null, s.Setter<Row<MethodDef>>((r, v) =>
            {
                r.Item.Body.MaxStack = (ushort)Lng(v, "max_stack");
                r.Item.Body.KeepOldMaxStack = true;
            }))
            .Bool("init_locals", r => r.Item.HasBody && r.Item.Body.InitLocals, s.Setter<Row<MethodDef>>((r, v) => r.Item.Body.InitLocals = Values.ToBool(v)))
            .Text("semantics", r => r.Item.SemanticsAttributes == 0 ? null : r.Item.SemanticsAttributes.ToString().ToLowerInvariant(),
                doc: "getter | setter | addon | removeon | fire | other")
            .Int("owner", r => AccessorOwner(r) is { } o ? r.M.H(o) : null, doc: "property/event handle when this method is an accessor")
            .Int("override_count", r => r.Item.Overrides.Count)
            .Int("attribute_count", r => r.Item.CustomAttributes.Count);
        methods.OnInsert(v => InsertMethod(s, v)).OnDelete(r => DeleteMethod(s, r)).Estimate(50_000);
        db.Register(methods);

        // ================= params =================
        var pars = new Table<Row<(MethodDef method, Parameter p)>>("params",
            "Parameters (seq 0 = return value, -1 = hidden this). Filter by method for speed") { Domain = "metadata" };
        pars.Source(c => MethodScope(ws, c).SelectMany(r => Params(r.Item).Select(p => new Row<(MethodDef, Parameter)>(r.M, (r.Item, p)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.M.H(r.Item.method), pushdown: Pushdown.Eq)
            .Text("method_name", r => r.Item.method.FullName)
            .Int("seq", r => Seq(r.Item.p), doc: "ECMA sequence: 0 return, 1..n parameters, -1 this")
            .Int("arg_index", r => r.Item.p.IsReturnTypeParameter ? null : r.Item.p.Index, doc: "IL ldarg index")
            .Text("name", r => r.Item.p.IsHiddenThisParameter ? "this" : r.Item.p.Name, s.Setter<Row<(MethodDef, Parameter)>>((r, v) =>
            {
                if (r.Item.Item2.IsHiddenThisParameter) throw new SqlException("cannot rename 'this'");
                r.Item.Item2.Name = Values.ToText(v) ?? "";
            }))
            .Text("type", r => r.Item.p.Type?.FullName, s.Setter<Row<(MethodDef, Parameter)>>((r, v) => SetParamType(ws, r.M, r.Item.Item1, r.Item.Item2, Str(v, "type"))))
            .Int("flags", r => r.Item.p.ParamDef is { } pd ? (long)pd.Attributes : 0, s.Setter<Row<(MethodDef, Parameter)>>((r, v) =>
            {
                r.Item.Item2.CreateParamDef();
                r.Item.Item2.ParamDef!.Attributes = (ParamAttributes)Lng(v, "flags");
            }))
            .Bool("is_in", r => r.Item.p.ParamDef?.IsIn ?? false)
            .Bool("is_out", r => r.Item.p.ParamDef?.IsOut ?? false)
            .Bool("is_optional", r => r.Item.p.ParamDef?.IsOptional ?? false)
            .Bool("has_default", r => r.Item.p.ParamDef?.HasDefault ?? false)
            .Col("default_value", SqlType.Any, r => SqlValue(r.Item.p.ParamDef?.Constant?.Value), s.Setter<Row<(MethodDef, Parameter)>>((r, v) =>
            {
                var p = r.Item.Item2;
                p.CreateParamDef();
                if (v == null) { p.ParamDef!.Constant = null; p.ParamDef.HasDefault = false; return; }
                p.ParamDef!.Constant = new ConstantUser(CoerceConstant(v, p.Type));
                p.ParamDef.HasDefault = true;
                p.ParamDef.IsOptional = true;
            }))
            .Int("handle", r => r.Item.p.ParamDef is { } pd && pd.Rid != 0 ? r.M.H(pd) : null, doc: "ParamDef handle when a Param row exists");
        db.Register(pars);

        // ================= fields =================
        var fields = s.DefTable<FieldDef>("fields", "metadata", "FieldDefs: type, flags, constants, RVA data; dnSpy 'Edit Field' surface",
            m => m.Module.GetTypes().SelectMany(t => t.Fields), fast: (m, c) =>
            {
                if (c.Long("type") is long th && Handle.Module(ws.Normalize(th)) == m.Id)
                    return (m.Module.ResolveToken(Handle.Token(ws.Normalize(th))) as TypeDef)?.Fields ?? (IEnumerable<FieldDef>)Array.Empty<FieldDef>();
                if (c.Long("type") is long) return Array.Empty<FieldDef>();
                return null;
            });
        fields
            .Int("type", r => r.M.H(r.Item.DeclaringType), pushdown: Pushdown.Eq)
            .Text("type_name", r => r.Item.DeclaringType?.FullName)
            .Text("name", r => r.Item.Name.String, s.Setter<Row<FieldDef>>((r, v) => Fixups.RenameMember(r.Item, Str(v, "name"))))
            .Text("full_name", r => Readable(r.Item))
            .Text("field_type", r => r.Item.FieldType?.FullName,
                s.Setter<Row<FieldDef>>((r, v) => r.Item.FieldSig = new FieldSig(TypeSyntax.Parse(ws, r.M.Module, Str(v, "field_type")))))
            .Text("visibility", r => Visibility(r.Item.Attributes),
                s.Setter<Row<FieldDef>>((r, v) => r.Item.Access = (FieldAttributes)(ushort)ParseMethodVisibility(Str(v, "visibility"))))
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<FieldDef>>((r, v) => r.Item.Attributes = (FieldAttributes)Lng(v, "flags")))
            .Text("flags_text", r => r.Item.Attributes.ToString())
            .Bool("is_static", r => r.Item.IsStatic, s.Setter<Row<FieldDef>>((r, v) => r.Item.IsStatic = Values.ToBool(v)))
            .Bool("is_literal", r => r.Item.IsLiteral)
            .Bool("is_init_only", r => r.Item.IsInitOnly, s.Setter<Row<FieldDef>>((r, v) => r.Item.IsInitOnly = Values.ToBool(v)))
            .Bool("is_compiler_generated", r => IsCompilerGenerated(r.Item))
            .Bool("has_default", r => r.Item.HasDefault)
            .Col("constant", SqlType.Any, r => SqlValue(r.Item.Constant?.Value), s.Setter<Row<FieldDef>>((r, v) =>
            {
                if (v == null) { r.Item.Constant = null; r.Item.HasDefault = false; return; }
                r.Item.Constant = new ConstantUser(CoerceConstant(v, r.Item.FieldType));
                r.Item.HasDefault = true;
            }))
            .Int("rva", r => (long)(uint)r.Item.RVA)
            .Blob("initial_value", r => r.Item.InitialValue, s.Setter<Row<FieldDef>>((r, v) =>
            {
                r.Item.InitialValue = Values.ToBytes(v);
                r.Item.HasFieldRVA = v != null;
            }))
            .Int("field_offset", r => r.Item.FieldOffset is uint o ? o : null,
                s.Setter<Row<FieldDef>>((r, v) => r.Item.FieldOffset = v == null ? null : (uint)Lng(v, "field_offset")))
            .Text("marshal", r => r.Item.MarshalType?.ToString())
            .Int("attribute_count", r => r.Item.CustomAttributes.Count);
        fields.OnInsert(v => InsertField(s, v)).OnDelete(r => RemoveFrom(s, r.M, r.Item.DeclaringType.Fields, r.Item)).Estimate(30_000);
        db.Register(fields);

        // ================= properties / events =================
        var props = s.DefTable<PropertyDef>("properties", "metadata", "PropertyDefs with accessor handles",
            m => m.Module.GetTypes().SelectMany(t => t.Properties));
        props
            .Int("type", r => r.M.H(r.Item.DeclaringType), pushdown: Pushdown.Eq)
            .Text("type_name", r => r.Item.DeclaringType?.FullName)
            .Text("name", r => r.Item.Name.String, s.Setter<Row<PropertyDef>>((r, v) => r.Item.Name = Str(v, "name")))
            .Text("full_name", r => Readable(r.Item))
            .Text("property_type", r => r.Item.PropertySig?.RetType?.FullName)
            .Int("getter", r => r.Item.GetMethod is { } g ? r.M.H(g) : null, s.Setter<Row<PropertyDef>>((r, v) => SetAccessor(ws, r.Item.GetMethods, v, MethodSemanticsAttributes.Getter)))
            .Int("setter", r => r.Item.SetMethod is { } st ? r.M.H(st) : null, s.Setter<Row<PropertyDef>>((r, v) => SetAccessor(ws, r.Item.SetMethods, v, MethodSemanticsAttributes.Setter)))
            .Int("other_count", r => r.Item.OtherMethods.Count)
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<PropertyDef>>((r, v) => r.Item.Attributes = (PropertyAttributes)Lng(v, "flags")))
            .Bool("is_static", r => !(r.Item.PropertySig?.HasThis ?? true))
            .Bool("is_indexer", r => (r.Item.PropertySig?.Params.Count ?? 0) > 0)
            .Col("constant", SqlType.Any, r => SqlValue(r.Item.Constant?.Value))
            .Int("attribute_count", r => r.Item.CustomAttributes.Count);
        props.OnDelete(r => RemoveFrom(s, r.M, r.Item.DeclaringType.Properties, r.Item));
        db.Register(props);

        var events = s.DefTable<EventDef>("events", "metadata", "EventDefs with accessor handles",
            m => m.Module.GetTypes().SelectMany(t => t.Events));
        events
            .Int("type", r => r.M.H(r.Item.DeclaringType), pushdown: Pushdown.Eq)
            .Text("type_name", r => r.Item.DeclaringType?.FullName)
            .Text("name", r => r.Item.Name.String, s.Setter<Row<EventDef>>((r, v) => r.Item.Name = Str(v, "name")))
            .Text("full_name", r => Readable(r.Item))
            .Text("event_type", r => r.Item.EventType?.FullName,
                s.Setter<Row<EventDef>>((r, v) => r.Item.EventType = TypeSyntax.ParseTypeRef(ws, r.M.Module, Str(v, "event_type"))))
            .Int("adder", r => r.Item.AddMethod is { } a ? r.M.H(a) : null)
            .Int("remover", r => r.Item.RemoveMethod is { } a ? r.M.H(a) : null)
            .Int("raiser", r => r.Item.InvokeMethod is { } a ? r.M.H(a) : null)
            .Int("other_count", r => r.Item.OtherMethods.Count)
            .Int("flags", r => (long)r.Item.Attributes, s.Setter<Row<EventDef>>((r, v) => r.Item.Attributes = (EventAttributes)Lng(v, "flags")))
            .Int("attribute_count", r => r.Item.CustomAttributes.Count);
        events.OnDelete(r => RemoveFrom(s, r.M, r.Item.DeclaringType.Events, r.Item));
        db.Register(events);

        db.Register(new Table<Row<(IMemberDef owner, string role, MethodDef method)>>("accessors",
                "Property/event accessor methods (MethodSemantics)") { Domain = "metadata" }
            .Source(c => ws.Modules(c).SelectMany(m => m.Module.GetTypes().SelectMany(t =>
                t.Properties.SelectMany(p => p.GetMethods.Select(x => (p as IMemberDef, "get", x))
                        .Concat(p.SetMethods.Select(x => (p as IMemberDef, "set", x))).Concat(p.OtherMethods.Select(x => (p as IMemberDef, "other", x))))
                    .Concat(t.Events.SelectMany(e => new[] { ("add", e.AddMethod), ("remove", e.RemoveMethod), ("raise", e.InvokeMethod) }
                        .Where(x => x.Item2 != null).Select(x => (e as IMemberDef, x.Item1, x.Item2!))
                        .Concat(e.OtherMethods.Select(x => (e as IMemberDef, "other", x)))))
                .Select(x => new Row<(IMemberDef, string, MethodDef)>(m, x)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("owner", r => r.M.H(r.Item.owner))
            .Text("owner_kind", r => r.Item.owner is PropertyDef ? "property" : "event")
            .Text("owner_name", r => r.Item.owner.FullName)
            .Text("role", r => r.Item.role)
            .Int("method", r => r.M.H(r.Item.method))
            .Text("method_name", r => r.Item.method.FullName));

        // ================= generic params =================
        db.Register(s.DefTable<GenericParam>("generic_params", "metadata", "Generic parameters of types and methods",
                m => m.Module.GetTypes().SelectMany(t => t.GenericParameters.Concat(t.Methods.SelectMany(x => x.GenericParameters))))
            .Int("owner", r => r.Item.Owner is IMDTokenProvider o ? r.M.H(o) : null)
            .Text("owner_kind", r => r.Item.Owner is TypeDef ? "type" : "method")
            .Text("owner_name", r => (r.Item.Owner as IFullName)?.FullName)
            .Int("number", r => r.Item.Number)
            .Text("name", r => r.Item.Name.String, s.Setter<Row<GenericParam>>((r, v) => r.Item.Name = Str(v, "name")))
            .Int("flags", r => (long)r.Item.Flags, s.Setter<Row<GenericParam>>((r, v) => r.Item.Flags = (GenericParamAttributes)Lng(v, "flags")))
            .Text("variance", r => (r.Item.Flags & GenericParamAttributes.VarianceMask) switch
                { GenericParamAttributes.Covariant => "out", GenericParamAttributes.Contravariant => "in", _ => "" })
            .Text("constraints", r => string.Join(", ", ConstraintText(r.Item))));

        // ================= overrides (MethodImpl) =================
        db.Register(new Table<Row<(MethodDef body, MethodOverride ov)>>("method_overrides", "MethodImpl rows: explicit interface implementations / .override") { Domain = "metadata" }
            .Source(c => MethodScope(ws, c, "method").SelectMany(r => r.Item.Overrides.Select(o => new Row<(MethodDef, MethodOverride)>(r.M, (r.Item, o)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.M.H(r.Item.body), pushdown: Pushdown.Eq)
            .Text("method_name", r => r.Item.body.FullName)
            .Int("declaration", r => DefHandle(ws, r.Item.ov.MethodDeclaration))
            .Text("declaration_name", r => r.Item.ov.MethodDeclaration?.FullName));

        // ================= pinvokes (ImplMap) =================
        db.Register(new Table<Row<MethodDef>>("pinvokes", "P/Invoke imports (ImplMap): native DLL + entry point per method") { Domain = "metadata" }
            .Source(c => ws.Modules(c).SelectMany(m => m.Module.GetTypes().SelectMany(t => t.Methods).Where(x => x.ImplMap != null).Select(x => new Row<MethodDef>(m, x))))
            .Keyed(r => r.M.H(r.Item), h => ws.Resolve(h) is var (lm, it) && it is MethodDef md ? new Row<MethodDef>(lm, md) : null)
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.M.H(r.Item))
            .Text("method_name", r => r.Item.FullName)
            .Text("dll", r => r.Item.ImplMap!.Module?.Name.String, s.Setter<Row<MethodDef>>((r, v) => r.Item.ImplMap!.Module = new ModuleRefUser(r.M.Module, Str(v, "dll"))))
            .Text("entry", r => r.Item.ImplMap!.Name.String, s.Setter<Row<MethodDef>>((r, v) => r.Item.ImplMap!.Name = Str(v, "entry")))
            .Int("flags", r => (long)r.Item.ImplMap!.Attributes, s.Setter<Row<MethodDef>>((r, v) => r.Item.ImplMap!.Attributes = (PInvokeAttributes)Lng(v, "flags")))
            // Explicit names: these masks have several enum members per value, so ToString() picks an arbitrary alias.
            .Text("charset", r => ((int)r.Item.ImplMap!.Attributes & 0x6) switch
                { 2 => "CharSetAnsi", 4 => "CharSetUnicode", 6 => "CharSetAuto", _ => "CharSetNotSpec" })
            .Text("calling_convention", r => ((int)r.Item.ImplMap!.Attributes & 0x700) switch
            {
                0x100 => "CallConvWinapi", 0x200 => "CallConvCdecl", 0x300 => "CallConvStdcall", 0x400 => "CallConvThiscall",
                0x500 => "CallConvFastcall", 0 => "CallConvNotSpec", var x => $"0x{x:X}",
            })
            .Bool("supports_last_error", r => r.Item.ImplMap!.SupportsLastError)
            .Text("signature", r => Signature(r.Item)));

        // ================= custom attributes =================
        var cas = new Table<Row<(IHasCustomAttribute owner, CustomAttribute ca)>>("custom_attributes",
            "Custom attributes on every owner (assembly, module, type, member, param, generic param, ...)") { Domain = "metadata" };
        cas.Source(c =>
            {
                if (c.Long("owner") is long oh)
                {
                    var (lm, item) = ws.Resolve(oh);
                    return item is IHasCustomAttribute hca
                        ? hca.CustomAttributes.Select(ca => new Row<(IHasCustomAttribute, CustomAttribute)>(lm, (hca, ca)))
                        : Array.Empty<Row<(IHasCustomAttribute, CustomAttribute)>>();
                }
                return ws.Modules(c).SelectMany(m => AttributeOwners(m.Module).SelectMany(o => o.CustomAttributes.Select(ca => new Row<(IHasCustomAttribute, CustomAttribute)>(m, (o, ca)))));
            })
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("owner", r => r.M.H(r.Item.owner), pushdown: Pushdown.Eq)
            .Text("owner_kind", r => Handle.KindOf(r.Item.owner.MDToken.Raw))
            .Text("owner_name", r => (r.Item.owner as IFullName)?.FullName ?? r.Item.owner.ToString())
            .Text("attribute_type", r => r.Item.ca.AttributeType?.FullName)
            .Int("ctor", r => DefHandle(ws, r.Item.ca.Constructor as IMemberRef))
            .Text("ctor_name", r => r.Item.ca.Constructor?.FullName)
            .Text("args", r => CaArgs(r.Item.ca), doc: "C#-like rendering: (1, \"x\", Name = true)")
            .Text("args_json", r => CaJson(r.Item.ca))
            .Int("arg_count", r => r.Item.ca.ConstructorArguments.Count)
            .Int("named_count", r => r.Item.ca.NamedArguments.Count)
            .Bool("is_raw", r => r.Item.ca.IsRawBlob)
            .Blob("blob", r => r.Item.ca.RawData, doc: "raw blob (only for attributes that could not be parsed)");
        cas.OnInsert(v => InsertAttribute(s, v)).OnDelete(r =>
        {
            var (owner, ca) = r.Item;
            int idx = owner.CustomAttributes.IndexOf(ca);
            owner.CustomAttributes.RemoveAt(idx);
            ws.Touch(r.M);
            return (() => { owner.CustomAttributes.Insert(idx, ca); ws.Touch(r.M); }, () => { owner.CustomAttributes.Remove(ca); ws.Touch(r.M); });
        });
        db.Register(cas);

        // ================= declarative security =================
        db.Register(new Table<Row<(IHasDeclSecurity owner, DeclSecurity ds)>>("decl_security", "DeclSecurity rows (CAS permission sets)") { Domain = "metadata" }
            .Source(c => ws.Modules(c).SelectMany(m => SecurityOwners(m.Module).SelectMany(o => o.DeclSecurities.Select(d => new Row<(IHasDeclSecurity, DeclSecurity)>(m, (o, d))))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("owner", r => r.M.H(r.Item.owner))
            .Text("owner_name", r => (r.Item.owner as IFullName)?.FullName)
            .Text("action", r => r.Item.ds.Action.ToString())
            .Text("permissions", r => r.Item.ds.GetNet1xXmlString() ?? string.Join("; ", r.Item.ds.SecurityAttributes.Select(a => a.AttributeType?.FullName))));
    }

    // ---------------------------------------------------------------------------------------------------------

    static T? Try<T>(Func<T?> f) { try { return f(); } catch { return default; } }

    public static long? DefHandle(Workspace ws, IMemberRef? r)
    {
        IMemberDef? def = r switch
        {
            null => null,
            TypeDef td => td,
            ITypeDefOrRef tr => Try(() => tr.ResolveTypeDef()),
            MethodDef md => md,
            FieldDef fd => fd,
            MemberRef mr => Try(() => (IMemberDef?)mr.ResolveMethod() ?? mr.ResolveField()),
            MethodSpec ms => Try(() => ms.Method.ResolveMethodDef()),
            _ => null,
        };
        if (def == null) return null;
        var lm = ws.Find(def.Module);
        return lm == null ? null : lm.H(def);
    }

    static IEnumerable<Row<TypeDef>> TypeScope(Workspace ws, Constraints c, string col)
    {
        if (c.Long(col) is long h && ws.Resolve(h) is var (lm, it) && it is TypeDef td) return new[] { new Row<TypeDef>(lm, td) };
        return ws.Modules(c).SelectMany(m => m.Module.GetTypes().Select(t => new Row<TypeDef>(m, t)));
    }

    public static IEnumerable<Row<MethodDef>> MethodScope(Workspace ws, Constraints c, string col = "method")
    {
        if (c.Long(col) is long h)
        {
            var (lm, it) = ws.Resolve(h);
            return it is MethodDef md ? new[] { new Row<MethodDef>(lm, md) } : Array.Empty<Row<MethodDef>>();
        }
        return ws.Modules(c).SelectMany(m => m.Module.GetTypes().SelectMany(t => t.Methods).Select(x => new Row<MethodDef>(m, x)));
    }

    static IEnumerable<Parameter> Params(MethodDef m)
    {
        if (m.Parameters.ReturnParameter is { } rp) yield return rp;
        foreach (var p in m.Parameters) yield return p;
    }

    static long Seq(Parameter p) => p.IsReturnTypeParameter ? 0 : p.IsHiddenThisParameter ? -1 : p.MethodSigIndex + 1;

    static void SetParamType(Workspace ws, LoadedModule lm, MethodDef m, Parameter p, string type)
    {
        var sig = TypeSyntax.Parse(ws, lm.Module, type);
        if (p.IsHiddenThisParameter) throw new SqlException("cannot change the type of 'this'");
        m.MethodSig = m.MethodSig.Clone();
        if (p.IsReturnTypeParameter) m.MethodSig.RetType = sig;
        else m.MethodSig.Params[p.MethodSigIndex] = sig;
        m.Parameters.UpdateParameterTypes();
    }

    public static string Signature(MethodDef m)
    {
        var ps = m.Parameters.Where(p => p.IsNormalMethodParameter).Select(p => $"{p.Type?.TypeName ?? "?"} {p.Name}".Trim());
        var gen = m.HasGenericParameters ? "<" + string.Join(", ", m.GenericParameters.Select(g => g.Name)) + ">" : "";
        return $"{(m.IsStatic ? "static " : "")}{m.ReturnType?.TypeName} {m.Name}{gen}({string.Join(", ", ps)})";
    }

    public static long? CodeSize(MethodDef m)
    {
        if (!m.HasBody || m.Body.Instructions.Count == 0) return m.HasBody ? 0 : null;
        var last = m.Body.Instructions[^1];
        return last.Offset + last.GetSize();
    }

    static IMemberDef? AccessorOwner(Row<MethodDef> r)
    {
        var m = r.Item;
        if (m.SemanticsAttributes == 0 || m.DeclaringType == null) return null;
        foreach (var p in m.DeclaringType.Properties)
            if (p.GetMethods.Contains(m) || p.SetMethods.Contains(m) || p.OtherMethods.Contains(m)) return p;
        foreach (var e in m.DeclaringType.Events)
            if (e.AddMethod == m || e.RemoveMethod == m || e.InvokeMethod == m || e.OtherMethods.Contains(m)) return e;
        return null;
    }

    static void SetAccessor(Workspace ws, IList<MethodDef> list, object? v, MethodSemanticsAttributes sem)
    {
        foreach (var old in list) old.SemanticsAttributes &= ~sem;
        list.Clear();
        if (v == null) return;
        var m = ws.Resolve<MethodDef>(v, "method");
        m.SemanticsAttributes |= sem;
        list.Add(m);
    }

    static IEnumerable<string> ConstraintText(GenericParam g)
    {
        if ((g.Flags & GenericParamAttributes.ReferenceTypeConstraint) != 0) yield return "class";
        if ((g.Flags & GenericParamAttributes.NotNullableValueTypeConstraint) != 0) yield return "struct";
        foreach (var c in g.GenericParamConstraints) yield return c.Constraint?.FullName ?? "?";
        if ((g.Flags & GenericParamAttributes.DefaultConstructorConstraint) != 0) yield return "new()";
    }

    static void SetLayout(TypeDef t, object? pack, object? size)
    {
        var p = pack != null ? (ushort)Values.ToLong(pack)! : t.ClassLayout?.PackingSize ?? 0;
        var s = size != null ? (uint)Values.ToLong(size)! : t.ClassLayout?.ClassSize ?? 0;
        t.ClassLayout = new ClassLayoutUser(p, s);
    }

    static void SetTypeKind(Workspace ws, TypeDef t, string kind)
    {
        var corlib = t.Module.CorLibTypes;
        ITypeDefOrRef Sys(string name) => TypeSyntax.ParseTypeRef(ws, t.Module, "System." + name);
        switch (kind.ToLowerInvariant())
        {
            case "class":
                if (t.BaseType == null || t.IsValueType || t.IsEnum || t.IsDelegate) t.BaseType = corlib.Object.TypeDefOrRef;
                t.Attributes &= ~TypeAttributes.Interface;
                break;
            case "static class":
                t.BaseType = corlib.Object.TypeDefOrRef; t.Layout = TypeAttributes.AutoLayout;
                t.Attributes &= ~TypeAttributes.Interface; t.IsAbstract = true; t.IsSealed = true; break;
            case "interface":
                t.BaseType = null; t.Layout = TypeAttributes.AutoLayout; t.Attributes |= TypeAttributes.Interface; t.IsAbstract = true; t.IsSealed = false; break;
            case "struct":
                t.BaseType = Sys("ValueType"); t.Attributes &= ~TypeAttributes.Interface; t.IsAbstract = false; t.IsSealed = true; break;
            case "enum":
                t.BaseType = Sys("Enum"); t.Layout = TypeAttributes.AutoLayout; t.Attributes &= ~TypeAttributes.Interface; t.IsAbstract = false; t.IsSealed = true; break;
            case "delegate":
                t.BaseType = Sys("MulticastDelegate"); t.Layout = TypeAttributes.AutoLayout; t.Attributes &= ~TypeAttributes.Interface; t.IsAbstract = false; t.IsSealed = true; break;
            default: throw new SqlException($"unknown type kind '{kind}'");
        }
    }

    static (long, Action, Action) InsertType(Session s, IReadOnlyDictionary<string, object?> v)
    {
        var ws = s.Ws;
        TypeDef? declaring = v.TryGetValue("declaring_type", out var dt) && dt != null ? ws.Resolve<TypeDef>(dt, "declaring_type") : null;
        var lm = declaring != null ? ws.ModuleOf(declaring) : ws.ModuleArg(v.GetValueOrDefault("module"));
        var name = Str(v.GetValueOrDefault("name"), "name");
        var ns = declaring != null ? "" : Values.ToText(v.GetValueOrDefault("namespace")) ?? "";
        var vis = Values.ToText(v.GetValueOrDefault("visibility")) ?? "public";
        var attrs = ParseTypeVisibility(vis, declaring != null) | TypeAttributes.AutoLayout | TypeAttributes.Class | TypeAttributes.AnsiClass;
        var t = new TypeDefUser(ns, name, lm.Module.CorLibTypes.Object.TypeDefOrRef) { Attributes = attrs };
        if (Values.ToText(v.GetValueOrDefault("kind")) is string kind) SetTypeKind(ws, t, kind);
        if (Values.ToText(v.GetValueOrDefault("base_type_name")) is string bt) t.BaseType = TypeSyntax.ParseTypeRef(ws, lm.Module, bt);
        lm.Module.UpdateRowId(t);
        void Add() { if (declaring != null) declaring.NestedTypes.Add(t); else lm.Module.Types.Add(t); ws.Touch(lm); }
        void Remove() { if (declaring != null) declaring.NestedTypes.Remove(t); else lm.Module.Types.Remove(t); ws.Touch(lm); }
        Add();
        return (lm.H(t), Remove, Add);
    }

    static (Action, Action) DeleteType(Session s, Row<TypeDef> r)
    {
        var t = r.Item;
        if (t.IsGlobalModuleType) throw new SqlException("cannot delete <Module>");
        IList<TypeDef> list = t.DeclaringType != null ? t.DeclaringType.NestedTypes : r.M.Module.Types;
        return RemoveFrom(s, r.M, list, t);
    }

    static (Action, Action) RemoveFrom<T>(Session s, LoadedModule lm, IList<T> list, T item)
    {
        int idx = list.IndexOf(item);
        if (idx < 0) throw new SqlException("item is no longer attached");
        list.RemoveAt(idx);
        s.Ws.Touch(lm);
        return (() => { list.Insert(Math.Min(idx, list.Count), item); s.Ws.Touch(lm); }, () => { list.Remove(item); s.Ws.Touch(lm); });
    }

    static (long, Action, Action) InsertMethod(Session s, IReadOnlyDictionary<string, object?> v)
    {
        var ws = s.Ws;
        var type = ws.Resolve<TypeDef>(v.GetValueOrDefault("type"), "type");
        var lm = ws.ModuleOf(type);
        var name = Str(v.GetValueOrDefault("name"), "name");
        var ret = Values.ToText(v.GetValueOrDefault("return_type")) is string rt ? TypeSyntax.Parse(ws, lm.Module, rt) : lm.Module.CorLibTypes.Void;
        bool isStatic = v.TryGetValue("is_static", out var st) ? Values.ToBool(st) : type.IsAbstract && type.IsSealed;
        var sig = isStatic ? MethodSig.CreateStatic(ret) : MethodSig.CreateInstance(ret);
        var vis = Values.ToText(v.GetValueOrDefault("visibility")) is string vs ? ParseMethodVisibility(vs) : MethodAttributes.Public;
        var attrs = vis | MethodAttributes.HideBySig | (isStatic ? MethodAttributes.Static : 0);
        if (type.IsInterface) attrs |= MethodAttributes.Abstract | MethodAttributes.Virtual | MethodAttributes.NewSlot;
        var m = new MethodDefUser(name, sig, MethodImplAttributes.IL | MethodImplAttributes.Managed, attrs);
        if (v.TryGetValue("flags", out var fl) && fl != null) m.Attributes = (MethodAttributes)Lng(fl, "flags");
        if (!m.IsAbstract) m.Body = BodyKit.Stub(m, null);
        lm.Module.UpdateRowId(m);
        type.Methods.Add(m);
        ws.Touch(lm);
        return (lm.H(m), () => { type.Methods.Remove(m); ws.Touch(lm); }, () => { type.Methods.Add(m); ws.Touch(lm); });
    }

    static (Action, Action) DeleteMethod(Session s, Row<MethodDef> r)
    {
        var m = r.Item;
        var t = m.DeclaringType;
        // dnSpy detaches the method from property/event semantics too.
        var detach = new List<(Action undo, Action redo)>();
        foreach (var p in t.Properties)
            foreach (var list in new[] { p.GetMethods, p.SetMethods, p.OtherMethods })
            {
                int i = list.IndexOf(m);
                if (i >= 0) { var l = list; list.RemoveAt(i); detach.Add((() => l.Insert(i, m), () => l.Remove(m))); }
            }
        foreach (var e in t.Events)
        {
            var ev = e;
            if (e.AddMethod == m) { e.AddMethod = null; detach.Add((() => ev.AddMethod = m, () => ev.AddMethod = null)); }
            if (e.RemoveMethod == m) { e.RemoveMethod = null; detach.Add((() => ev.RemoveMethod = m, () => ev.RemoveMethod = null)); }
            if (e.InvokeMethod == m) { e.InvokeMethod = null; detach.Add((() => ev.InvokeMethod = m, () => ev.InvokeMethod = null)); }
        }
        var (undo, redo) = RemoveFrom(s, r.M, t.Methods, m);
        return (() => { undo(); foreach (var d in detach) d.undo(); }, () => { redo(); foreach (var d in detach) d.redo(); });
    }

    static (long, Action, Action) InsertField(Session s, IReadOnlyDictionary<string, object?> v)
    {
        var ws = s.Ws;
        var type = ws.Resolve<TypeDef>(v.GetValueOrDefault("type"), "type");
        var lm = ws.ModuleOf(type);
        var name = Str(v.GetValueOrDefault("name"), "name");
        var ft = TypeSyntax.Parse(ws, lm.Module, Values.ToText(v.GetValueOrDefault("field_type")) ?? "int");
        var vis = Values.ToText(v.GetValueOrDefault("visibility")) is string vs ? (FieldAttributes)(ushort)ParseMethodVisibility(vs) : FieldAttributes.Public;
        bool isStatic = v.TryGetValue("is_static", out var st) && Values.ToBool(st);
        var f = new FieldDefUser(name, new FieldSig(ft), vis | (isStatic ? FieldAttributes.Static : 0));
        if (v.TryGetValue("flags", out var fl) && fl != null) f.Attributes = (FieldAttributes)Lng(fl, "flags");
        if (v.TryGetValue("constant", out var cv) && cv != null)
        {
            f.Constant = new ConstantUser(CoerceConstant(cv, ft));
            f.HasDefault = true;
            f.IsLiteral = true;
            f.IsStatic = true;
        }
        lm.Module.UpdateRowId(f);
        type.Fields.Add(f);
        ws.Touch(lm);
        return (lm.H(f), () => { type.Fields.Remove(f); ws.Touch(lm); }, () => { type.Fields.Add(f); ws.Touch(lm); });
    }

    public static IEnumerable<IHasCustomAttribute> AttributeOwners(ModuleDef m)
    {
        if (m.Assembly != null && ReferenceEquals(m.Assembly.ManifestModule, m)) yield return m.Assembly;
        yield return m;
        foreach (var t in m.GetTypes())
        {
            yield return t;
            foreach (var gp in t.GenericParameters) yield return gp;
            foreach (var ii in t.Interfaces) yield return ii;
            foreach (var f in t.Fields) yield return f;
            foreach (var p in t.Properties) yield return p;
            foreach (var e in t.Events) yield return e;
            foreach (var md in t.Methods)
            {
                yield return md;
                foreach (var gp in md.GenericParameters) yield return gp;
                foreach (var pd in md.ParamDefs) yield return pd;
            }
        }
        foreach (var r in m.Resources) yield return r;
    }

    static IEnumerable<IHasDeclSecurity> SecurityOwners(ModuleDef m)
    {
        if (m.Assembly != null && ReferenceEquals(m.Assembly.ManifestModule, m)) yield return m.Assembly;
        foreach (var t in m.GetTypes())
        {
            yield return t;
            foreach (var md in t.Methods) yield return md;
        }
    }

    public static string CaArgs(CustomAttribute ca)
    {
        if (ca.IsRawBlob) return "<raw blob>";
        var parts = ca.ConstructorArguments.Select(a => Fmt(a.Value))
            .Concat(ca.NamedArguments.Select(n => $"{n.Name} = {Fmt(n.Argument.Value)}"));
        return "(" + string.Join(", ", parts) + ")";
    }

    static string CaJson(CustomAttribute ca)
    {
        if (ca.IsRawBlob) return "null";
        object? J(object? v) => v switch
        {
            UTF8String u => u.String,
            IList<CAArgument> l => l.Select(x => J(x.Value)).ToList(),
            CAArgument a => J(a.Value),
            TypeSig t => "typeof(" + t.FullName + ")",
            _ => v,
        };
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            args = ca.ConstructorArguments.Select(a => J(a.Value)).ToList(),
            named = ca.NamedArguments.ToDictionary(n => n.Name.String, n => J(n.Argument.Value)),
        });
    }

    /// <summary>INSERT INTO custom_attributes(owner, attribute_type, args_json); args_json is a JSON array of ctor arguments.</summary>
    static (long, Action, Action) InsertAttribute(Session s, IReadOnlyDictionary<string, object?> v)
    {
        var ws = s.Ws;
        var oh = ws.HandleArg(v.GetValueOrDefault("owner")) ?? throw new SqlException("owner is required");
        var (lm, item) = ws.Resolve(oh);
        if (item is not IHasCustomAttribute owner) throw new SqlException($"{Handle.Hex(oh)} cannot carry attributes");
        var ca = AttributeKit.Create(ws, lm.Module, Str(v.GetValueOrDefault("attribute_type"), "attribute_type"), Values.ToText(v.GetValueOrDefault("args_json")));
        owner.CustomAttributes.Add(ca);
        ws.Touch(lm);
        return (0, () => { owner.CustomAttributes.Remove(ca); ws.Touch(lm); }, () => { owner.CustomAttributes.Add(ca); ws.Touch(lm); });
    }
}
