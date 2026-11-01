#!/usr/bin/env python3
# DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
"""Regenerates the table list in README.md (section "Schema", from "Every table and view, by area" to "### Conventions")
from the live catalog of a built dnspysql, so the README cannot drift from the code.

    python tools/docs/readme_tables.py [--exe build/dnspysql] [--readme README.md] [--check]

--check exits 1 when the README is out of date (for CI) instead of writing it.
"""
import argparse, json, os, subprocess, sys

# README section per catalog domain, in order. A new domain must be added here (the script stops otherwise).
ORDER = [("meta", "Session and assembly"), ("metadata", "Metadata"), ("code", "Code"), ("xrefs", "Cross-references and call graph"),
         ("decompiler", "Decompiler"), ("search", "Search"), ("resources", "Resources"), ("pe", "PE file and raw metadata"),
         ("pdb", "Debug information (PDB)"), ("annotations", "Annotations"), ("breakpoints", "Breakpoints for dnSpy"),
         ("dnspy", "dnSpy's own state (dnSpy.xml)")]

# Shorter wording where the catalog text is a usage manual rather than a description.
SHORT = {
    "il": "IL instructions, one row per instruction. `WHERE method = ...` reads one body; without it every body is scanned",
    "search": "dnSpy's search window, with optional `kind`, `match_mode` (contains, exact, word, regex) and `case_sensitive`",
    "bundle_entries": "Files inside a .NET single-file bundle the module was opened from; `open_bundle_entry(path)` loads an embedded assembly",
    "breakpoints": "Code breakpoints and tracepoints: method + IL offset, condition, hit count, filter, trace message, labels",
    "pseudocode": "Decompiled source, one row per entity, in C#, VB or IL (`language`)",
    "analyze": "dnSpy's Analyzer as a table-valued function: every relation of `target`, optionally one `relation`",
    "byte_search": "Byte pattern search over the module files (`??` wildcards)",
    "md_rows": "Raw metadata table cells (dnSpy's metadata table view); UPDATE patches the file",
    "resource_elements": "Entries of `.resources` files: strings, primitives, byte arrays, serialized objects",
    "resources": "Manifest resources and their embedded bytes",
    "file_bytes": "Raw file bytes including patches; UPDATE patches like a hex editor (`save_raw`)",
    "pe_fields": "Every field of the DOS, file, optional, COR20 and metadata headers, with its file offset; UPDATE patches the file",
    "comments": "Comments on entities or on IL offsets inside methods; `save()` writes them as XML documentation for dnSpy",
    "bookmarks": "Bookmarks (dnSpy's Bookmarks window); exported to dnSpy with the breakpoints",
    "exception_handlers": "try/catch/finally/fault/filter regions of method bodies",
    "user_strings": "The `#US` heap: every `ldstr` literal of the module",
    "callers": "Who calls a method (`WHERE method = ...`), also through a base or interface method it overrides or implements (`via`)",
    "dispatch_calls": "Virtual calls that can reach a method through a base or interface method it overrides or implements (dnSpy's Virtual Used By)",
    "dnspysql_guides": "How to use DnSpySql's tables (basics, explore, dnspy); the MCP server offers them as prompts",
    "callees": "What a method calls (`WHERE method = ...`); external callees have `callee = 0`",
    "entry_points": "Managed entry points, module initializers and static constructors of every module",
    "pseudocode_refs": "Names in the decompiled source and what they refer to (dnSpy's click-to-definition): members, locals, parameters, labels",
    "method_bodies": "Method bodies as they are in the file: tiny/fat/invalid header (or C++/CLI native code), exception sections, IL that does not decode, shared or overlapping bodies",
    "heap_entries": "Entries of the `#Strings`, `#US`, `#Blob` and `#GUID` heaps, whether anything references them, and slack",
    "file_map": "Every byte range of the file and what it is (dnSpy's hex view), with the gaps no structure accounts for; `WHERE contains = <offset>`",
    "resource_images": "Images in resources, including serialized Bitmap/Icon/ImageListStreamer (read without deserializing), with the image file in `data`",
    "api_docs": "XML documentation of a referenced type or member (dnSpy's tooltips)",
    "dnspy_debugger_settings": "dnSpy's debugger options, including its anti-anti-debug protections; UPDATE value to set one",
    "dnspy_watch": "Expressions in dnSpy's Watch windows; INSERT adds one for the next debugging session",
    "dnspy_documents": "The assemblies dnSpy opens at startup; `save()` adds the annotated copy",
    "dnspy_tabs": "The tabs dnSpy showed when it last exited, resolved to handles",
}


def resolve_exe(path):
    """The dnspysql binary as an absolute path; `build/dnspysql` also finds build/dnspysql.exe on Windows."""
    for p in (path, path + ".exe"):
        if os.path.isfile(p):
            return os.path.abspath(p)
    sys.exit(f"dnspysql binary not found: {path} (build it, or pass --exe / set DNSPYSQL)")


def esc(t):
    # < and > outside code spans would be read as HTML tags in a Markdown table
    parts = t.split("`")
    return "`".join(p if i % 2 else p.replace("<", "&lt;").replace(">", "&gt;") for i, p in enumerate(parts))


def writes(r):
    return ", ".join(n for k, n in (("can_update", "UPDATE"), ("can_insert", "INSERT"), ("can_delete", "DELETE")) if r[k])


def render(rows):
    missing = {r["domain"] for r in rows} - {d for d, _ in ORDER}
    if missing:
        sys.exit(f"readme_tables.py: add a section for domain(s) {sorted(missing)} to ORDER")
    out = []
    for dom, title in ORDER:
        rs = sorted((r for r in rows if r["domain"] == dom), key=lambda r: (r["kind"] == "view", r["table_name"]))
        # one collapsible block per area: the whole list open would be most of the README
        out += ["<details>", f"<summary><b>{title}</b> ({len(rs)})</summary>", "", "| table | writes | description |", "|---|---|---|"]
        for r in rs:
            desc = esc(SHORT.get(r["table_name"], r["description"]).rstrip("."))
            if r["kind"] == "view":
                desc = "*View.* " + desc
            if r["required_filter"]:
                desc += f" (needs `{r['required_filter']}`)"
            out.append(f"| `{r['table_name']}` | {writes(r)} | {desc} |")
        out += ["", "</details>", ""]
    return "\n".join(out).rstrip("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=os.environ.get("DNSPYSQL") or os.path.join("build", "dnspysql"))
    ap.add_argument("--readme", default="README.md")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    q = ("SELECT domain, table_name, kind, can_update, can_insert, can_delete, required_filter, description "
         "FROM dnspysql_tables ORDER BY domain, table_name")
    out = subprocess.run([resolve_exe(a.exe), "--no-project", "--dnspy-xml", "off", "--format", "json", "-c", q], capture_output=True, check=True).stdout
    j = json.loads(out)
    cols = j["results"][0]["columns"]
    rows = [dict(zip(cols, r)) for r in j["results"][0]["rows"]]
    s = open(a.readme, encoding="utf-8").read()
    start = s.index("Every table and view, by area")
    end = s.index("\n### Conventions", start)
    new = (s[:start]
           + f"Every table and view, by area ({len(rows)} in all; click an area to open it). *writes* lists what the table\n"
           + "accepts besides `SELECT`; edits are journaled (`undo()`/`redo()`) and refused with `--readonly`. Columns are in\n"
           + "[docs/SCHEMA.md](docs/SCHEMA.md).\n\n"
           + render(rows) + "\n" + s[end:])
    if a.check:
        if new != s:
            sys.exit("README.md table list is out of date: run python tools/docs/readme_tables.py")
        print(f"README.md table list is current ({len(rows)} tables)")
        return
    open(a.readme, "w", encoding="utf-8", newline="").write(new)
    print(f"README.md table list: {len(rows)} tables")


if __name__ == "__main__":
    main()
