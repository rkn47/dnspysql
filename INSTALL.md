# Installing DnSpySql

**If you are an AI agent:** this file is everything you need to install DnSpySql and connect it to your harness.
Follow the steps in order and run each step's **Check** before moving on. If a check fails, use the troubleshooting
table at the end, and stop and report if it doesn't cover the case. Don't install anything that needs administrator
rights, and don't change user-level configuration, without asking the user first; each place where that can happen
is marked **ask**. What DnSpySql can do once installed: [README.md](README.md).

DnSpySql only parses the assemblies it loads; it never runs them. Don't run a sample to "test" the installation
either: the checks below use DnSpySql's own engine DLL, and the tests use the benign assemblies in `tests/corpus`.

## 0. Choose a path

| host | path |
|---|---|
| Windows x64 | native build: steps 1–5 |
| Linux x64 | native build: steps 1–5, or [Docker](#alternative-docker) without a toolchain on the host |
| macOS, ARM64 | not supported; use Docker on an x64 host |

The first build needs network access (submodules and NuGet packages). This repository ships source only; there are
no prebuilt binaries to download.

In the commands below, Windows examples are for `cmd` or PowerShell. From a POSIX shell on Windows (Git Bash, the
shell some agent harnesses use), run `cmd //c build.cmd` and use forward slashes in paths.

## 1. Prerequisites

| | Windows x64 | Linux x64 |
|---|---|---|
| C++ compiler | Visual Studio 2022 or later (Build Tools are enough) with the C++ workload (`Microsoft.VisualStudio.Component.VC.Tools.x86.x64`) | gcc or clang (`build-essential`) |
| CMake | 3.20 or later | 3.20 or later |
| Ninja | any | any |
| .NET | **SDK** 8.0 (a runtime alone can't build) | **SDK** 8.0 |
| git | with submodule support | same |

Check what is there:

```
# Windows
cmake --version
ninja --version
dotnet --list-sdks            # needs an 8.0.x line; also try %USERPROFILE%\.dotnet\dotnet.exe --list-sdks
"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

# Linux
cmake --version; ninja --version; g++ --version
dotnet --list-sdks || ~/.dotnet/dotnet --list-sdks
```

On Windows, `build.cmd` runs `vcvars64.bat` before CMake, so if Visual Studio's "C++ CMake tools for Windows"
component is installed, its bundled `cmake` and `ninja` are used even when the first two checks fail.

Installing what is missing:

- **.NET 8 SDK, per user (no admin):**
  - Windows (PowerShell; `-ExecutionPolicy Bypass` applies to this one process only):
    `iwr https://dot.net/v1/dotnet-install.ps1 -OutFile $env:TEMP\di.ps1; powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\di.ps1 -Channel 8.0 -InstallDir $env:USERPROFILE\.dotnet -NoPath`
  - Linux: `curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0` (installs to `~/.dotnet`)

  DnSpySql finds a per-user .NET by itself at run time (`%USERPROFILE%\.dotnet`, `%LOCALAPPDATA%\Microsoft\dotnet`,
  `~/.dotnet`), and `build.sh` does too. For `build.cmd` and `dotnet test`, put it on `PATH` for the session only:
  `$env:PATH = "$env:USERPROFILE\.dotnet;$env:PATH"` (PowerShell), `set PATH=%USERPROFILE%\.dotnet;%PATH%` (cmd),
  `export PATH="$HOME/.dotnet:$PATH"` (bash).
- **NuGet package source:** run `dotnet nuget list source`. If it says `No sources found`, the build can't restore
  packages. **Ask**, then run `dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org`. This
  edits the user's NuGet config.
- **Visual Studio Build Tools** (Windows): needs admin. **Ask** the user to install it with the C++ workload, or to
  run `winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"`.
- **CMake / Ninja:** `winget install Kitware.CMake Ninja-build.Ninja` (Windows; open a new shell afterwards so they
  are on `PATH`) or `sudo apt install build-essential cmake ninja-build git curl` (Linux, **ask**: needs sudo).

## 2. Source and submodules

```
git clone <repository URL> dnspysql
cd dnspysql
git submodule update --init
git -C external/dnSpyEx submodule update --init --depth 1 Extensions/ILSpy.Decompiler/ICSharpCode.Decompiler Extensions/ILSpy.Decompiler/NRefactory
```

Only those two nested dnSpyEx submodules are needed; `--recursive` would fetch many more. A source archive without
`.git` has no submodules: clone the repository instead.

**Check:** `external/libxsql/CMakeLists.txt`,
`external/dnSpyEx/Extensions/ILSpy.Decompiler/ICSharpCode.Decompiler/ICSharpCode.Decompiler` and
`external/dnSpyEx/Extensions/ILSpy.Decompiler/NRefactory/ICSharpCode.NRefactory` all exist.

## 3. Build

```
build.cmd        # Windows: finds MSVC through vswhere, then CMake + Ninja (Release)
./build.sh       # Linux; also fetches .NET Framework reference assemblies (NO_REFS=1 to skip)
```

The build publishes the engine, links `build/dnspysql` (`build\dnspysql.exe`) and regenerates `docs/SCHEMA.md`. On
Windows, `'vswhere.exe' is not recognized` printed by `vcvars64.bat` is harmless. If `build/` already exists and came
from another machine or OS, move it aside first, e.g. to `build-old`.

The result is `build/dnspysql` plus `build/engine/` (the managed engine). Keep them together: to install elsewhere,
copy both, or point `--engine DIR` at the engine folder. Running it needs the .NET 8 runtime or newer (the SDK
includes it).

**Check** (on Linux, `build/dnspysql` with forward slashes):

```
build\dnspysql.exe --version
build\dnspysql.exe build\engine\DnSpySql.Engine.dll --no-project --dnspy-xml off -c "SELECT count(*) FROM types"
```

The first prints `dnspysql <version> (sqlite <version>)` followed by the copyright, license and credits lines. The
second prints the load line on stderr and a count of several hundred types.

### When `build\` is locked (rebuilding while DnSpySql runs)

A running DnSpySql, typically an MCP server started by an agent harness, locks `build\engine\DnSpySql.Engine.dll` on
Windows, and the build fails with MSB3027/MSB3021 ("being used by another process"). Don't kill that process, since
it belongs to someone's session. Either close the client that started it, or build into another folder from a
shell where `vcvars64.bat` has run (on Linux, the same without it):

```
cmake -S . -B build-dev -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-dev
build-dev\dnspysql.exe --schema-md > docs\SCHEMA.md
```

`build-*/` is git-ignored. Test that build with `DNSPYSQL=build-dev\dnspysql.exe` (step 4), and point the MCP
registration at it, or copy it over `build\` once nothing runs from there.

## 4. Tests (recommended)

```
dotnet test tests/DnSpySql.Tests
```

**Check:** `Passed!` with `Failed: 0`. The tests run the built binary (`build/dnspysql`, or the one in the
`DNSPYSQL` environment variable) end to end on the benign assemblies in `tests/corpus`, and never write the user's
`dnSpy.xml`.

## 5. Connect to an agent harness (MCP)

DnSpySql serves the Model Context Protocol over stdio with `--mcp`. Use one server for all samples: start it without
an assembly, and the agent loads samples with `SELECT open('path')`. Always register the **absolute** path of the
binary; clients start it with their own working directory.

Registering the server changes the client's configuration: **ask** first.

**Claude Code:**

```
claude mcp add --scope user dnspysql -- <absolute path>\build\dnspysql.exe --mcp
claude mcp get dnspysql          # check: Status: Connected
```

`--scope user` makes it available in every project; leave it out for the current project only. For one sample per
server, put the assembly before `--mcp`.

**Clients with an `mcpServers` JSON file** (Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json`; Cursor:
`~/.cursor/mcp.json`; Gemini CLI: `~/.gemini/settings.json`; Windsurf: `~/.codeium/windsurf/mcp_config.json`). Merge
this into the file rather than replacing it:

```json
{ "mcpServers": { "dnspysql": { "command": "C:/path/to/dnspysql/build/dnspysql.exe", "args": ["--mcp"] } } }
```

**VS Code** (`.vscode/mcp.json` in a workspace, or the user configuration through "MCP: Add Server"):

```json
{ "servers": { "dnspysql": { "type": "stdio", "command": "C:/path/to/dnspysql/build/dnspysql.exe", "args": ["--mcp"] } } }
```

**Codex CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.dnspysql]
command = "/path/to/dnspysql/build/dnspysql"
args = ["--mcp"]
```

In JSON, write Windows paths with forward slashes or doubled backslashes. If .NET is in a non-standard place, add
`"env": { "DOTNET_ROOT": "<.NET folder>" }` to the server entry.

The server offers `dnspysql_query` (SQL), `dnspysql_schema` and `dnspysql_guide` (how-to guides for each workflow,
also offered as MCP prompts: basics, explore, triage, unpack, dnspy), and its instructions describe the analysis workflow.
Useful extra arguments, placed before `--mcp`:

- `--dnspy-xml off|auto|PATH`: on Windows, DnSpySql keeps dnSpy's settings file in step with the breakpoints and
  bookmarks it sets (default `auto`: `%APPDATA%\dnSpy\dnSpy.xml`, or the `bin\dnSpy.xml` of a running portable dnSpy).
  That edits the user's dnSpy configuration: **ask** whether they want it, and pass `--dnspy-xml off` if not.
- `--readonly` for analysis that must not change anything;
- `--ref DIR` for directories with referenced assemblies;
- `--timeout MS` for a per-statement timeout.

**Check:** in a new agent session, ask it to run `SELECT sqlite_version()` through DnSpySql.

What DnSpySql writes, so the user is not surprised: once a sample is annotated, `<sample>.dnspysql.json` beside it
(`--no-project` keeps annotations in memory); the files the agent asks for (`save()`, `export_project()`,
`bp_export()`); and `dnSpy.xml` as above. dnSpy must be closed while its `dnSpy.xml` is changed; see "Kept in step
with dnSpy" under [Breakpoints](README.md#breakpoints) in the README.

## 6. Without MCP: command line or HTTP

An agent that can run shell commands needs no registration:

```
build/dnspysql <assembly> --no-project --format json -c "SELECT full_name FROM types LIMIT 5"
```

`--format json` returns `{success, statement_count, results[{columns, rows, ...}]}`; `-c` can be repeated.

An agent that can only make HTTP requests can use a server the user starts:

```
build/dnspysql --http 8081 --token <secret>
curl -s -H "Authorization: Bearer <secret>" --data "SELECT open('/path/app.dll')" http://127.0.0.1:8081/query
```

It listens on `127.0.0.1` only unless `--bind` says otherwise. The endpoints are in the README (Usage).

## 7. Updating

```
git pull
git submodule update --init
git -C external/dnSpyEx submodule update --init --depth 1 Extensions/ILSpy.Decompiler/ICSharpCode.Decompiler Extensions/ILSpy.Decompiler/NRefactory
```

Then build again (step 3; a running MCP server locks `build\`, see above), run the tests, and restart the client so
it starts the new binary.

## 8. Uninstalling

Remove the client registration (`claude mcp remove dnspysql`, or delete the `dnspysql` entry from the client's
configuration file), then delete the repository folder. Project files (`*.dnspysql.json`) beside analysed samples,
and entries DnSpySql added to `dnSpy.xml`, are left in place.

## Alternative: Docker

Linux, no toolchain on the host. After step 2:

```
docker build -t dnspysql .
docker run --rm --network none -v "$PWD:/samples:ro" dnspysql /samples/app.dll -c "SELECT count(*) FROM types"
./dpq open app.dll               # sandboxed session per sample (uid 1000, read-only root, no capabilities)
./dpq q <id> "SELECT * FROM entry_points"
```

`dpq` keeps one container per sample, with its project file in the `dpq-projects` volume; `./dpq` without arguments
lists its commands. The image is for local use only (see Binaries in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md#binaries)).

## Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `NU1100: Unable to resolve 'dnlib ...'` / `Microsoft.NETCore.App.Runtime...` | no NuGet package source | step 1, NuGet source |
| `nethost not found under .../packs (install the .NET SDK)` | only a .NET runtime, or `dotnet` not found | install the .NET 8 SDK; put it on `PATH` |
| `MSVC build tools not found` | no VS C++ workload | step 1, Build Tools (**ask**) |
| `dotnet-install.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | run it with `powershell -ExecutionPolicy Bypass -File`, as in step 1 |
| `'cmake'` / `'ninja'` is not recognized | not installed, or installed in another shell | step 1; open a new shell after `winget` |
| CMake: `CMakeCache.txt directory ... is different` / `does not match the source` | `build/` was generated elsewhere | move `build/` aside and rebuild |
| `MSB3027` / `MSB3021`: `DnSpySql.Engine.dll` is being used by another process | a running DnSpySql (MCP server) | [build into `build-dev`](#when-build-is-locked-rebuilding-while-dnspysql-runs) |
| `MSB3021 ... Cannot create '...\sample' because a file or directory with the same name already exists` | test `bin/` copied from Linux (an apphost named `Sample`) | delete `tests/**/bin` and `tests/**/obj` |
| `Couldn't find a valid ICU package` (Linux) | minimal distribution without ICU | **ask**, then `sudo apt install libicu-dev`, or set `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` |
| `could not locate the .NET runtime (hostfxr)` | .NET installed in a non-standard place | set `DOTNET_ROOT` to the .NET folder (for MCP, in the server's `env`) |
| `note: could not fetch .NET Framework reference assemblies` (Linux build) | offline | harmless; pass `--ref DIR` for .NET Framework targets, or rerun `build.sh` online |
| MCP server shows *Failed* in the client | wrong path, or a relative path | use the absolute path to the binary; run it with `--version` to check |
| `note: ... dnSpy is running` | dnSpy overwrites `dnSpy.xml` on exit | close dnSpy, `SELECT dnspy_sync()`, start dnSpy |
