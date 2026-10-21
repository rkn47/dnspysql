# Vendored dnSpyEx decompiler

These projects compile dnSpyEx's decompiler, from the `external/dnSpyEx` submodule, for `net8.0`.
The submodule is **unmodified**; everything DnSpySql adds lives here.

## Why dnSpyEx and not the ILSpy NuGet package

dnSpy's decompiler is a fork of ILSpy that reads the **live dnlib model** (52 of its 72 source files
use dnlib; none use `System.Reflection.Metadata`). That matters here because DnSpySql already holds
every assembly as a dnlib `ModuleDefMD`:

- one parse per assembly instead of two;
- no re-serialization of the dnlib model after an edit, so renames, stubs and IL patches are visible
  to `decompile()` immediately;
- dnlib's tolerance of malformed metadata. Measured on 25 real protected assemblies, the upstream
  `System.Reflection.Metadata` reader failed on 2 of 24 modules — on one of them, every single type
  and even IL disassembly failed. The dnSpyEx fork decompiled 421/421 and 242/242 types of those two.

The cost is that this fork is ILSpy v2-era, so it lags upstream on newer C# constructs, and it is
GPL-3.0-or-later (see `THIRD_PARTY_NOTICES.md`).

## Why one project per assembly

The obvious approach — glob every source file into a single assembly — does not compile. The fork
overrides NRefactory members declared `protected internal`, and such an override must be `protected`
when it crosses an assembly boundary. Collapsing the boundary makes those overrides illegal
(`CS0507`). So each project here mirrors one dnSpyEx assembly, keeps its original `AssemblyName`, and
reproduces its upstream `ProjectReference` set:

| project | assembly | references |
|---|---|---|
| `ContractsLogic` | `dnSpy.Contracts.Logic` | dnlib |
| `NRefactory` | `ICSharpCode.NRefactory` | dnlib |
| `NRefactory.CSharp` | `ICSharpCode.NRefactory.CSharp` | ContractsLogic, NRefactory |
| `NRefactory.VB` | `ICSharpCode.NRefactory.VB` (from the ILSpy fork's submodule, `ICSharpCode.Decompiler/NRefactory.VB`) | ContractsLogic, NRefactory, NRefactory.CSharp, Decompiler |
| `Decompiler` | `ICSharpCode.Decompiler` (the fork) | ContractsLogic, NRefactory, NRefactory.CSharp |
| `DnSpyDecompiler` | `dnSpy.Decompiler` | ContractsLogic |
| `ILSpyCore` | `dnSpy.Decompiler.ILSpy.Core`, with its `VisualBasic/` decompiler | all of the above |
| `BamlDecompiler` | `dnSpy.BamlDecompiler` (`Extensions/dnSpy.BamlDecompiler`, without WPF: BAML to XAML for the `baml` table) | ContractsLogic, DnSpyDecompiler, Decompiler |
| `ResXShim` | `System.Windows.Forms` (ResX names only; see below) | — |

`EmbeddedResource` logical names are set explicitly so the generated `*.Resources.Designer.cs` files
find their `.resources` at runtime.

## The project exporter

`dnSpy.Decompiler/MSBuild/` (dnSpy's File > Export to Project) is compiled into `DnSpyDecompiler` and
drives `export_project()`. It needs two things that are not in .NET 8 on Linux:

- `System.Configuration.ConfigurationManager` (NuGet) for `SettingsManageability` and `SpecialSetting`.
- The Windows Forms ResX names: `ResXResourceFileWriter.cs` writes `.resx` files itself but takes the
  header constants, the schema and the reader/writer type names from `ResXResourceWriter`,
  `ResXResourceReader`, `ResXDataNode` and `ResXNullRef`. `ResXShim` supplies those members only. It is
  an assembly named `System.Windows.Forms`, version 4.0.0.0, public-signed with the ECMA key, so the
  type names written into each `.resx` are the ones Visual Studio and dnSpy write
  (`System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089`). Its
  schema text is copied from a Visual Studio generated `.resx`.

The exporter's types are `internal`; `DnSpyDecompiler/VendorInternalsVisibleTo.cs` grants the engine
access, as `ILSpyCore` does for the decompilers.

## Not vendored

- `ILAst` — dnSpy gates `ILAstDecompiler` behind `#if DEBUG` and its constructor is private, so it
  does not exist in a Release build.
- `dnSpy.Contracts.Logic/Utilities/NuGetPackageLocator.cs` — needs `NuGet.Configuration`.

## Updating the submodule

```
git -C external/dnSpyEx fetch --depth 1 origin <commit>
git -C external/dnSpyEx checkout <commit>
git -C external/dnSpyEx submodule update --init --depth 1 \
    Extensions/ILSpy.Decompiler/ICSharpCode.Decompiler Extensions/ILSpy.Decompiler/NRefactory
```

Then rebuild. If upstream adds a source file that needs a package these projects do not reference,
the glob will surface it as a missing-type error; add the package or exclude the file here. Update the
pinned commit in `THIRD_PARTY_NOTICES.md`.
