// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace DnSpySql;

/// <summary>
/// Universal entity key: (module id &lt;&lt; 32) | metadata token. Readable in hex: 0x1_06000005 is MethodDef #5 of module 1.
/// Plain tokens (&lt; 2^32) are accepted everywhere and resolved against the current module.
/// </summary>
public static class Handle
{
    public static long Make(int module, uint token) => ((long)module << 32) | token;
    public static long Make(int module, IMDTokenProvider p) => Make(module, p.MDToken.Raw);
    public static int Module(long handle) => (int)(handle >> 32);
    public static uint Token(long handle) => (uint)(handle & 0xFFFFFFFF);
    public static Table Table(long handle) => (Table)(Token(handle) >> 24);
    public static uint Rid(long handle) => Token(handle) & 0x00FFFFFF;
    public static string Hex(long handle) => Module(handle) == 0 ? $"0x{Token(handle):X8}" : $"0x{Module(handle):X}_{Token(handle):X8}";

    public static string KindOf(uint token) => (Table)(token >> 24) switch
    {
        dnlib.DotNet.MD.Table.Module => "module",
        dnlib.DotNet.MD.Table.TypeRef => "typeref",
        dnlib.DotNet.MD.Table.TypeDef => "type",
        dnlib.DotNet.MD.Table.Field => "field",
        dnlib.DotNet.MD.Table.Method => "method",
        dnlib.DotNet.MD.Table.Param => "param",
        dnlib.DotNet.MD.Table.InterfaceImpl => "interfaceimpl",
        dnlib.DotNet.MD.Table.MemberRef => "memberref",
        dnlib.DotNet.MD.Table.CustomAttribute => "attribute",
        dnlib.DotNet.MD.Table.DeclSecurity => "declsecurity",
        dnlib.DotNet.MD.Table.StandAloneSig => "standalonesig",
        dnlib.DotNet.MD.Table.Event => "event",
        dnlib.DotNet.MD.Table.Property => "property",
        dnlib.DotNet.MD.Table.ModuleRef => "moduleref",
        dnlib.DotNet.MD.Table.TypeSpec => "typespec",
        dnlib.DotNet.MD.Table.Assembly => "assembly",
        dnlib.DotNet.MD.Table.AssemblyRef => "asmref",
        dnlib.DotNet.MD.Table.File => "file",
        dnlib.DotNet.MD.Table.ExportedType => "exportedtype",
        dnlib.DotNet.MD.Table.ManifestResource => "resource",
        dnlib.DotNet.MD.Table.GenericParam => "genericparam",
        dnlib.DotNet.MD.Table.MethodSpec => "methodspec",
        dnlib.DotNet.MD.Table.GenericParamConstraint => "genericparamconstraint",
        _ when (token >> 24) == 0x70 => "string",
        _ => $"table{token >> 24:X2}",
    };
}
