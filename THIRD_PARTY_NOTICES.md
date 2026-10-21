# Third-party notices

| component | use | license | source |
|---|---|---|---|
| libxsql (Elias Bachaalany) | unmodified static library dependency (git submodule `external/libxsql`) | Human-Origin Source License v1.0 — full text in `external/libxsql/LICENSE` | https://github.com/0xeb/libxsql |
| SQLite (via libxsql) | SQL engine | Public domain | https://sqlite.org |
| nlohmann/json (via libxsql) | JSON | MIT | https://github.com/nlohmann/json |
| cpp-httplib (via libxsql) | the `--http` server and the `--remote` client | MIT | https://github.com/yhirose/cpp-httplib |
| dnlib | .NET metadata reading/writing | MIT | https://github.com/0xd4d/dnlib |
| dnSpyEx (dnSpy.Contracts.Logic, dnSpy.Decompiler, dnSpy.Decompiler.ILSpy.Core, dnSpy.BamlDecompiler) | C# and VB decompilation and IL disassembly, on the live dnlib model; project export (`export_project`); BAML to XAML (`baml`) | **GPL-3.0-or-later** — full text in `external/dnSpyEx/LICENSE.txt` | https://github.com/dnSpyEx/dnSpy |
| dnSpyEx's ILSpy fork (ICSharpCode.Decompiler, branch `ilspyv2`) | decompiler engine used by the above | MIT | https://github.com/dnSpyEx/ILSpy |
| NRefactory (ICSharpCode.NRefactory, .CSharp) | C# AST used by the decompiler | MIT | https://github.com/dnSpyEx/nrefactory |
| NRefactory.VB (ICSharpCode.NRefactory.VB, in the ILSpy fork) | VB AST and output for the VB decompiler | MIT | https://github.com/dnSpyEx/ILSpy |
| Microsoft.CodeAnalysis.CSharp (Roslyn) | compiling edited C# back to IL | MIT | https://github.com/dotnet/roslyn |
| System.Configuration.ConfigurationManager | settings types used by dnSpy's project exporter | MIT | https://github.com/dotnet/runtime |
| .NET hosting (nethost) | runtime hosting | MIT | https://github.com/dotnet/runtime |

## LZMA algorithm

`engine/DnSpySql.Engine/Lzma.cs` implements the LZMA decoding algorithm as published in Igor Pavlov's LZMA SDK, which
is in the public domain. No SDK source is included.

## dnSpyEx attribution and licence consequence

DnSpySql vendors dnSpyEx's decompiler rather than the upstream `ICSharpCode.Decompiler` NuGet
package because dnSpyEx's fork of ILSpy reads the **live dnlib model** (the measurements are in
`engine/vendor/README.md`).

The source is a git submodule, `external/dnSpyEx`, pinned at commit `1f920a80` and **used
unmodified**. Only these parts are compiled, by the projects under `engine/vendor/`:

- `dnSpy/dnSpy.Contracts.Logic` (minus `Utilities/NuGetPackageLocator.cs`)
- `dnSpy/dnSpy.Decompiler`, including `MSBuild/`, the project exporter
- `Extensions/ILSpy.Decompiler/ICSharpCode.Decompiler` (the ILSpy fork, and its `NRefactory.VB`) and `NRefactory`
- `Extensions/ILSpy.Decompiler/dnSpy.Decompiler.ILSpy.Core`
- `Extensions/dnSpy.BamlDecompiler` (its BAML reader and XAML rewriter, without the WPF UI)

They are compiled into assemblies of their own, mirroring dnSpyEx's own assembly boundaries, because
the fork overrides NRefactory members declared `protected internal` — legal only across an assembly
boundary. `engine/vendor/ILSpyCore/VendorInternalsVisibleTo.cs` and
`engine/vendor/DnSpyDecompiler/VendorInternalsVisibleTo.cs` are DnSpySql's own files, added so the
engine can reach dnSpy's `internal` decompiler and exporter types without patching the submodule.
`engine/vendor/ResXShim` is also DnSpySql's own: the few Windows Forms ResX names the exporter writes
into `.resx` files (see `engine/vendor/README.md`).

**dnSpyEx is GPL-3.0-or-later**, so DnSpySql, which links it, is GPL-licensed too: GPL-3.0-only (`LICENSE`) with
the section 7 additional terms in `NOTICE`. "Version 3 or any later version" is compatible with GPL-3.0-only.
Distributing binaries is a separate question (see [Binaries](#binaries)).

## libxsql, idasql and ghidrasql attribution

This project includes code or implementation work derived from or substantially informed by libxsql by
Elias Bachaalany: https://github.com/0xeb/libxsql

- **libxsql** is used unmodified as a dependency (its license's "Unmodified Dependency Use"): the native host
  calls its public API, and its source is available at the URL above at the commit pinned by the
  `external/libxsql` submodule. DnSpySql does not copy, adapt or port libxsql code. DnSpySql was developed with
  AI assistance. To call libxsql's API, the AI read its public headers and examples (including, in the
  header-only `vtable.hpp`, how its planner chooses among constraint filters) and, to diagnose a crash, the part
  of `src/database.cpp` showing that `Database`'s constructor opens a connection. To answer licensing questions it
  also read the license texts of libxsql, idasql and ghidrasql and one of their READMEs; no code or documentation
  was copied or written from them.
- **idasql and ghidrasql**, by the same author, are where the idea of querying a reverse-engineering database
  with SQL comes from, and DnSpySql follows several of their public conventions: table names such as `xrefs`,
  `callers` and `binary`, the JSON result envelope and HTTP endpoints, the REPL dot commands and a single MCP
  query tool (`docs/DNSPY_MAPPING.md` lists them). DnSpySql copies no code from them; its implementation, for
  .NET and on dnSpy's engine, is its own, written with AI assistance.

DnSpySql is not affiliated with, endorsed by or maintained with their author.

## Binaries

This repository distributes **source code**. A build combines, in one process, code under the GPL (dnSpyEx's
decompiler, in the engine) with libxsql, whose license is not the GPL and adds restrictions the GPL does not
allow. DnSpySql's own code permits that combination (`NOTICE`, "Additional permission"), but dnSpyEx's license
has no such permission, so conveying a **binary** of the combination to others (release archives, packages,
container images) is not covered by the licenses as they stand. Building and running DnSpySql for your own use
is unaffected: the GPL does not restrict private use, and libxsql's license allows unmodified dependency use.

Before distributing binaries, resolve that combination, for example with written permission from libxsql's author
to convey libxsql under terms compatible with the GPL as part of DnSpySql. Until then this project publishes no
binaries; the `Dockerfile` and `dpq` build an image locally, for local use.
