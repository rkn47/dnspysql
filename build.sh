#!/bin/sh
# dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
# Configure and build dnspysql (Release) with the system C++ compiler + Ninja into ./build, then regenerate
# docs/SCHEMA.md from the live catalog.
set -e
here=$(cd "$(dirname "$0")" && pwd)
[ -n "$DOTNET_ROOT" ] || { [ -x "$HOME/.dotnet/dotnet" ] && export DOTNET_ROOT="$HOME/.dotnet"; }
[ -n "$DOTNET_ROOT" ] && export PATH="$DOTNET_ROOT:$PATH"
cmake -S "$here" -B "$here/build" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$here/build" "$@"
"$here/build/dnspysql" --schema-md > "$here/docs/SCHEMA.md"

# .NET Framework reference assemblies (MIT, Microsoft.NETFramework.ReferenceAssemblies.net48) so mscorlib-based
# targets resolve their framework types (decompiler transforms, compile_method/edit_type) where no .NET Framework or
# Mono is installed. Optional: skipped when offline (set NO_REFS=1 to skip). Windows has the real framework.
refs="$here/build/engine/refs"
if [ -z "${NO_REFS:-}" ] && [ ! -d "$refs/v4.8" ]; then
  t=$(mktemp -d)
  printf '%s\n' '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>' \
    '<ItemGroup><PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies.net48" Version="1.0.3" /></ItemGroup></Project>' > "$t/refs.csproj"
  if dotnet restore "$t/refs.csproj" --packages "$t/pkgs" -v q >/dev/null 2>&1; then
    mkdir -p "$refs"
    cp -r "$t/pkgs/microsoft.netframework.referenceassemblies.net48/1.0.3/build/.NETFramework/v4.8" "$refs/"
    find "$refs" -name '*.xml' -delete
    echo "bundled .NET Framework 4.8 reference assemblies in build/engine/refs/v4.8"
  else
    echo "note: could not fetch .NET Framework reference assemblies (offline?); use --ref or reference_paths for Framework targets"
  fi
  rm -rf "$t"
fi
echo "built build/dnspysql ($("$here/build/dnspysql" --version))"
