// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using DnSpySql.Tables;
using dnlib.DotNet;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Functions;

/// <summary>
/// Functions DnSpySql had before its current schema, kept under their names: the older calling convention
/// (token plus an optional module id, where the current functions take a handle) and the edits built on the type splicer.
/// </summary>
public static class DnSpyFunctions
{
    public static void Register(Session s)
    {
        var ws = s.Ws;

        // A token plus an optional module id (older form) or a handle.
        long H(object? token, object? module) => module == null
            ? ws.HandleArg(token) ?? throw new SqlException("a handle or token is required")
            : Handle.Make(ws.ModuleArg(module).Id, (uint)Lng(token, "token"));

        s.Fn("token_name", 1, 2, a =>
        {
            try { var (_, it) = ws.Resolve(H(a[0], a.Arg(1))); return (it as IFullName)?.FullName ?? it.ToString(); }
            catch (SqlException) { return null; }
        }, "token_name(token [, module])", "full name of the entity (same as name_of(handle))", "core");

        s.Fn("stub_return", 1, 3, a =>
        {
            var m = ws.Resolve<MethodDef>(H(a[0], a.Arg(2)), "method");
            if (m.DeclaringType.IsInterface && m.IsAbstract) throw new SqlException("abstract interface methods cannot have a body");
            BodyEditor.Replace(s, m, "stub_return", () => BodyKit.Stub(m, a.Arg(1), a.Length > 1));
            return (long)m.Body.Instructions.Count;
        }, "stub_return(method [, value [, module]])", "replace a method body with `return value;` (same as set_body_stub)", "edit", mutates: true);

        s.Fn("edit_type", 2, 3, a =>
        {
            var h = H(a[0], a.Arg(2));
            var lm = ws.Get(Handle.Module(h));
            var source = Str(a[1], "source");
            return ws.SnapshotEdit(lm, "edit_type", () => (long)TypeSplice.EditType(s, lm, Handle.Token(h), source));
        }, "edit_type(type, 'C# type definition' [, module])",
            "dnSpy 'Edit Class (C#)': recompile a full C# type definition and splice the new method bodies and members into the existing type; " +
            "closures, iterators, async state machines and <PrivateImplementationDetails> data are merged", "compile", mutates: true);

        s.Fn("add_type", 1, 2, a =>
        {
            var lm = ws.ModuleArg(a.Arg(1));
            var source = Str(a[0], "source");
            return ws.SnapshotEdit(lm, "add_type", () => (long)TypeSplice.AddType(s, lm, source));
        }, "add_type('C# source' [, module])",
            "dnSpy 'Add Class (C#)': compile namespace/type declarations (against the SDK reference pack) and add them to the module; returns the number of types added",
            "compile", mutates: true);

        s.Fn("add_resource", 2, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var name = Str(a[0], "name");
            if (lm.Module.Resources.Any(r => r.Name == name)) throw new SqlException($"a resource named '{name}' already exists");
            var er = new EmbeddedResource(name, Values.ToBytes(a[1]) ?? throw new SqlException("data cannot be NULL"), ManifestResourceAttributes.Public);
            lm.Module.Resources.Add(er);
            ws.Touch(lm);
            ws.Record("resources", $"add_resource {name}", () => { lm.Module.Resources.Remove(er); ws.Touch(lm); }, () => { lm.Module.Resources.Add(er); ws.Touch(lm); });
            return 1L;
        }, "add_resource(name, data [, module])", "add an embedded resource (data is a blob or text); same as INSERT INTO resources", "resources", mutates: true);

        s.Fn("set_resource_data", 2, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var name = Str(a[0], "name");
            int idx = lm.Module.Resources.ToList().FindIndex(r => r.Name == name);
            if (idx < 0) throw new SqlException($"no resource named '{name}'");
            var old = lm.Module.Resources[idx];
            var er = new EmbeddedResource(old.Name, Values.ToBytes(a[1]) ?? throw new SqlException("data cannot be NULL"), old.Attributes);
            lm.Module.Resources[idx] = er;
            ws.Touch(lm);
            ws.Record("resources", $"set_resource_data {name}", () => { lm.Module.Resources[idx] = old; ws.Touch(lm); }, () => { lm.Module.Resources[idx] = er; ws.Touch(lm); });
            return 1L;
        }, "set_resource_data(name, data [, module])", "replace an embedded resource's bytes; same as UPDATE resources SET data", "resources", mutates: true);

        s.Fn("set_assembly", 1, 3, a =>
        {
            var lm = ws.ModuleArg(a.Arg(2));
            var asm = lm.Module.Assembly ?? throw new SqlException($"module {lm.Id} has no assembly manifest");
            var (oldName, oldVersion) = (asm.Name, asm.Version);
            UTF8String newName = a[0] == null ? oldName : Str(a[0], "name");
            var newVersion = oldVersion;
            if (a.Arg(1) is { } v && !Version.TryParse(Values.ToText(v), out newVersion!))
                throw new SqlException($"'{Values.ToText(v)}' is not a valid version (expected e.g. 2.0.1.0)");
            void Set(UTF8String n, Version ver) { asm.Name = n; asm.Version = ver; ws.Touch(lm); }
            Set(newName, newVersion);
            ws.Record("assemblies", "set_assembly", () => Set(oldName, oldVersion), () => Set(newName, newVersion));
            return asm.FullName;
        }, "set_assembly(name [, version [, module]])", "set the assembly name and/or version (NULL leaves one unchanged); same as UPDATE assemblies", "meta", mutates: true);
    }
}
