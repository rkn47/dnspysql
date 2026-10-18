// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
// dnSpy's BAML -> XAML decompiler (XamlDecompiler, BamlReader, ...) is `internal`. The engine drives it directly for
// the baml table, so access is granted here rather than by patching the vendored dnSpyEx source.
//
// This is our file, not dnSpyEx's; it lives outside external/dnSpyEx so the
// submodule stays unmodified.

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("DnSpySql.Engine")]
