# dnSpy → DnSpySql mapping

This document maps everything dnSpy(Ex) can **show** and everything it can **do** onto DnSpySql tables, columns
and functions. The decompiler, the project exporter and
the BAML decompiler are dnSpyEx's, vendored under `engine/vendor`. Status: ✅ implemented,
◐ partial, ❌ not implemented (see [Gaps](#gaps)).

Entities are addressed by `handle` = `module << 32 | metadata token`, as described under Conventions in the
[README](../README.md#schema).

## 1. Readable data

### 1.1 Documents and tree (dnSpy Assembly Explorer)

| dnSpy | DnSpySql | |
|---|---|---|
| Assembly / module documents, in-memory modules | `modules`, `assemblies`, `binary` | ✅ |
| Anti-tamper: the decrypted module (dnSpy needs the process: debug, then open the module from memory) | `untamper()`: the startup routine that decrypts them, interpreted over a copy of the image, the result opened as a module | ✅ |
| Open a module from memory or from a decoded blob | `open_bytes(data [, name [, memory_layout [, parent]]])`: the blob a `decrypt`/`decompress`/`base64_decode` chain produced, or a memory dump (a native PE gives NULL and a note) | ✅ |
| Single-file bundles (the app host's embedded assemblies) | `bundle_entries`, `open_bundle_entry(path)` | ✅ |
| Namespace nodes | `namespaces` | ✅ |
| Type nodes (kind, visibility, layout, base, nested) | `types` | ✅ |
| Base Types folder (recursive) | `analyze … relation = 'type.base_types'`, `type_hierarchy` view | ✅ |
| Derived Types folder | `analyze … 'type.derived_types'` (direct) / `'type.subtypes'` (transitive) | ✅ |
| Method / field / property / event nodes | `methods`, `fields`, `properties`, `events`, `accessors` | ✅ |
| Parameters, generic parameters, constraints | `params`, `generic_params` (constraints column) | ✅ |
| References folder (assembly refs, module refs) | `asmrefs` (+ resolved path/module), `modrefs` | ✅ |
| Type References folder (TypeRef/TypeSpec/MemberRef) | `typerefs`, `typespecs`, `memberrefs`, `methodspecs`, `standalonesigs` | ✅ |
| Interfaces, MethodImpl overrides | `interfaces`, `method_overrides` | ✅ |
| P/Invoke (ImplMap) | `pinvokes`, `native_imports` view | ✅ |
| Custom attributes (incl. on params, generic params, interface impls, resources) | `custom_attributes` (`args`, `args_json`) | ✅ |
| DeclSecurity | `decl_security` | ✅ |
| Exported types / forwarders, File table | `exported_types`, `files` | ✅ |
| Pseudo custom attributes (Serializable, StructLayout, DllImport …) | flags columns (`types.flags`, `layout`, `pinvokes`, `fields.field_offset`, `marshal`) | ◐ not synthesized as attribute rows |
| Tree settings (show tokens, member order) | n/a (SQL ordering) | — |

### 1.2 Code

| dnSpy | DnSpySql | |
|---|---|---|
| IL body (instructions, operands, offsets) | `il` (`WHERE method = ...` for one body; scannable across all bodies, e.g. `WHERE opcode = 'callvirt'`) | ✅ |
| Locals (with PDB names) | `locals`, `pdb_locals` | ✅ |
| Exception handlers | `exception_handlers` | ✅ |
| Method body header (max stack, init locals, code size, RVA, file offset) | `methods` columns, `method_bytes()` | ✅ |
| Hex view of a method body as it is in the file: tiny/fat/invalid header, exception sections, padding | `method_bodies` (also: IL that does not decode, C++/CLI native methods, bodies that share or overlap another) | ✅ |
| Basic blocks / control flow (not in dnSpy) | `blocks`, `cfg_edges` | ✅ |
| Number / string literal search | `literals`, `search … kind = 'number'/'string'` | ✅ |

### 1.3 PE / metadata / hex views

| dnSpy | DnSpySql | |
|---|---|---|
| DOS / file / optional headers, data directories, section headers | `pe_fields` (every field with offset; writable), `pe_sections`, `pe_data_directories` | ✅ |
| COR20 header, storage signature/header, stream headers, tables header | `pe_fields` structures `cor20_header`, `metadata_header`, `stream_header`, `tables_header` | ✅ |
| Metadata streams | `md_streams` | ✅ |
| Metadata tables + row view (all ECMA + portable PDB tables) | `md_tables`, `md_rows` (raw cells, decoded strings/tokens; writable) | ✅ |
| #US heap | `user_strings` | ✅ |
| #Strings / #Blob / #GUID heaps as tables | `heap_entries` (every entry, whether anything references it, slack after the last entry) | ✅ |
| Hex editor (view + edit, fill, paste) | `file_bytes` (range pushdown, UPDATE), `read_bytes()`, `patch_bytes()`, `save_raw()` | ✅ |
| Hex view structure info (what each byte range is) | `file_map` (headers, sections, directories, CLR/metadata structures, tables, streams, method bodies, resources, field data, overlay, and the gaps no structure accounts for; `WHERE contains = <offset>`) | ✅ |
| Go to RVA / file offset | `rva_to_offset()`, `offset_to_rva()`, `file_bytes.rva` | ✅ |
| Debug directory, Win32 resources (not shown by dnSpy) | `debug_directories` (CodeView GUID/age/path), `win32_resources` (+ version/manifest text) | ✅ |
| Section entropy (not in dnSpy) | `pe_sections.entropy` | ✅ |
| Configs in static/instance fields (not in dnSpy: read from the constructors' IL) | `field_inits` (strings, numbers, byte arrays from field data, string arrays, a getter's constant, arithmetic on constants, with the storing instruction; `is_default` marks the compiler's default stores; computed values are `decryptor_calls`' and `decoded_fields`') | ✅ |
| Configs decrypted in place at startup (not in dnSpy: seen only by debugging past the decoder) | `decoded_fields` (each settings field as the decoder leaves it, interpreted after the static constructor; `error` when it stops) | ✅ |
| Behaviour (not in dnSpy) | `capabilities` (API, import, reflection or string evidence at the call, also through proxy methods; `basis` says which; the labels in `Rules/capabilities.json`) | ✅ |
| The literals a call is given (dnSpy: reading the IL before the call) | `call_edges.string_args` (per string parameter, the `ldstr` that pushes it: a mutex's name, a registry key, a URL) | ✅ |
| Calls through proxy methods (de4dot's proxy call removal, without changing the code) | `call_edges.target` / `target_name` / `proxies` (the method behind up to three proxies), `callers.via = 'proxy'` | ✅ |
| Constant arithmetic in arguments (de4dot's constant folding) | every reader of call arguments folds it (`decryptor_calls`, `string_decryptors`, `inline_strings`); `field_inits.source = 'folded'` | ✅ |
| Turning the IL interpreter off | the `emulation` setting, `--no-emulation` | ✅ |
| What the IL interpreter answers, calls and refuses | `emulator_model` (environment placeholders, the allowlist, blocked and nondeterministic calls) | ✅ |
| Every call of a string decryptor and its plaintext (de4dot's string decryption, without running anything) | `decryptor_calls` (caller, offset, typed literal arguments or settings fields of known value, `plaintext` from the IL interpreter, `plaintext_kind` for a second layer), `emulate()` | ✅ |
| Protector identification (not in dnSpy; de4dot's detection) | `protections` (marker types with decoy detection, anti-tamper, anti-debug, anti-VM, string encryption, control-flow flattening, proxy calls, IL virtualization, code-less stub assemblies, encrypted/embedded resources; each with confidence and evidence) | ✅ |
| PE files inside a file that is no .NET module (not in dnSpy, which refuses to open it) | `carve_file WHERE path = '...'` (the PEs in its bytes, with `open_bytes(data)` for a .NET one) | ✅ |
| String decryptor location (not in dnSpy; de4dot's `--strtyp`) | `string_decryptors` (static methods returning a string, a number or a byte array, ranked by call sites with constant arguments, sample arguments, `return_type`) | ✅ |
| Byte pattern search | `byte_search WHERE pattern = '4D 5A ?? 00'` | ✅ |

### 1.4 Debug symbols

| dnSpy | DnSpySql | |
|---|---|---|
| Sequence points | `sequence_points`, `il.line` | ✅ |
| PDB documents, embedded source | `pdb_documents` (`embedded_source`) | ✅ |
| Scopes, local names, constants, imports | `pdb_scopes`, `pdb_locals` | ✅ |
| Custom debug info (state machines, async, source link, compilation options) | `custom_debug_info` | ✅ |

### 1.5 Resources

| dnSpy | DnSpySql | |
|---|---|---|
| Manifest resources (embedded / linked / assembly-linked), raw data | `resources` (`data`, `sniffed_type`, `text`, `sha256`) | ✅ |
| `.resources` elements (strings, primitives, byte[], streams, serialized) | `resource_elements` | ✅ |
| Image / icon / ImageListStreamer preview | `resource_images` (image resources, images in `.resources`, serialized Bitmap/Icon/ImageListStreamer read without deserializing; `data` is the image file) | ✅ |
| BAML → XAML | `baml` table (`xaml` column, dnSpy's BAML decompiler) | ✅ |
| Embedded executables (not in dnSpy) | `embedded_pes` (PE files in the file bytes, resources and `.resources` entries, also behind gzip/zlib/deflate or split across numbered resources), `open_bytes(data)` for a .NET one (one module per payload; `modules.origin`, `derived_from`); a PE inside another carve names it (`parent_offset`); `resources.content_type` | ✅ |

### 1.6 Decompiler

| dnSpy | DnSpySql | |
|---|---|---|
| C# decompilation of type/member | `pseudocode` (one row, exact text), `decompile(handle)`: dnSpy's own engine, so the text (and its line numbers) is what dnSpy shows | ✅ |
| VB decompilation | `decompile(handle, 'vb')`, `pseudocode*` with `language = 'vb'` (line ↔ IL mapping and references too), `decompile_module(m, 'vb')`; setting `decompiler_language` | ✅ |
| Line ↔ IL offset mapping (MethodDebugInfo) | `pseudocode_lines` (`il_offset`, `method`, comments): the statement spans dnSpy's debugger uses | ✅ |
| IL disassembly | `il_text(handle)`, `decompile(handle, 'il')` | ✅ |
| Whole module | `decompile_module()` | ✅ |
| Export to Project | `export_project(dir [, module [, sdk]])`: dnSpy's own exporter with its dialog's defaults (solution, .resx, BAML → XAML, VS2010 or SDK-style projects), Windows-safe file names | ✅ |
| IL-with-C# / ILAst debug languages | — | ❌ |
| Decompiler options UI | `runtime_settings` (`decompiler_language`, `decompiler_show_tokens`) | ◐ |
| Reference spans in output (click to definition, highlighting) | `pseudocode_refs` (name → definition handle, locals/parameters with decompiled names, writes) | ✅ |
| Brace ranges in output | — | ❌ |
| Tooltips: XML documentation of referenced APIs | `api_docs`, `api_doc()` | ✅ |

### 1.7 Analyzer (every dnSpy node)

`SELECT * FROM analyze WHERE target = <handle> [AND relation = '…']`

| dnSpy node | relation | |
|---|---|---|
| Type: Used By | `type.used_by` | ✅ (code, signatures, locals, catch types, base/interfaces, fields, props, events) |
| Type: Instantiated By | `type.instantiated_by` | ✅ |
| Type: Exposed By | `type.exposed_by` | ✅ |
| Type: Subtypes / Derived Types | `type.subtypes`, `type.derived_types` | ✅ |
| Type: Extension Methods | `type.extension_methods` | ✅ |
| Attribute type: Applied To | `type.applied_to` | ✅ |
| Base types (tree folder) | `type.base_types` | ✅ |
| Method: Uses | `method.uses` | ✅ |
| Method: Used By (incl. base-method calls, P/Invoke twins) | `method.used_by` | ✅ |
| Method: Virtual Used By (through a base or interface slot) | `method.virtual_used_by`; as rows for any or every method: `dispatch_calls`, and `callers` (`via`) | ✅ |
| Method: Overrides / Overridden By | `method.overrides`, `method.overridden_by` | ✅ |
| Interface method: Implemented By | `method.implemented_by` (+ `method.implements`) | ✅ |
| Field: Read By / Assigned By | `field.read_by`, `field.assigned_by` | ✅ (ldflda counts as both, like dnSpy) |
| Property: accessors, Overrides, Overridden By, Implemented By | `property.read_by`, `property.written_by`, `property.overrides`, `property.overridden_by`, `property.implemented_by` | ✅ |
| Event: Raised By, Overrides, Overridden By, Implemented By | `event.raised_by`, `event.subscribed_by`, `event.unsubscribed_by`, `event.overrides`, `event.overridden_by`, `event.implemented_by` | ✅ |
| Accessibility-scoped module set, COM/NoPIA type equivalence, CA named-arg writes | scans all loaded modules | ◐ |
| Compiler-generated code remapped to the user method | hits stay in the generated method (`<>c`, `d__N`); `xrefs`/`callers` link an async method or iterator to its state machine's `MoveNext` (`kind = 'async'`) | ◐ |

Raw form: `xrefs` (every call/field/type/token/string reference), `call_edges`, `callers`, `callees`.

### 1.8 Search

| dnSpy | DnSpySql | |
|---|---|---|
| Search window (type/method/field/property/event/param/local/resource/resource element/asm/module/namespace/literal/number/string) | `search WHERE query = … [AND kind = …] [AND match_mode = 'contains'\|'exact'\|'word'\|'regex'] [AND case_sensitive = 1]` | ✅ (`/re/` regex, multi-term AND) |
| String References window (IL, constants, attribute args) | `string_refs` | ✅ |
| Go To Token / entity lookup | `resolve()`, `name_of()`, `jump_entities` | ✅ |

### 1.9 User data

| dnSpy | DnSpySql | |
|---|---|---|
| Bookmarks | `bookmarks` (persisted in the project file; `bp_export()` writes them to dnSpy's Bookmarks window, `bp_import()` reads them) | ✅ |
| Comments (not in dnSpy) | `comments`, `pseudocode_lines.comment`; `save()` writes them as an XML documentation file that dnSpy shows as `///` comments | ✅ |
| Tags / progress, key-value notes (not in dnSpy) | `tags`, `kv` | ✅ |
| Document lists (files dnSpy opens at startup) | `dnspy_documents` (dnSpy's lists, INSERT adds; `save()` adds the annotated copy) | ✅ |
| Tabs | `dnspy_tabs` (as dnSpy saved them at its last exit, resolved to handles) | ◐ read-only |
| Settings | `runtime_settings`; sessions are CLI arguments | ◐ |

### 1.10 Breakpoint windows (configuration only)

DnSpySql deliberately does not run, attach to or inspect processes. It covers the *configuration* side of dnSpy's
debugger, which can be prepared statically and handed to dnSpy, and it can write breakpoints into the assembly so that
any debugger stops there.

| dnSpy | DnSpySql | |
|---|---|---|
| Breakpoints window: code breakpoints (location, enabled, labels) | `breakpoints` (`method`, `offset`, `idx`, `instruction`, `document`, `line`, `status`) | ✅ |
| Breakpoint settings: condition (IsTrue / WhenChanged), hit count (Equals / MultipleOf / GreaterThanOrEquals), filter | `breakpoints.condition`, `condition_kind`, `hit_count`, `hit_count_kind`, `filter` | ✅ |
| Tracepoints (message, continue) | `breakpoints.message`, `continue`, `bp_trace()` | ✅ |
| Toggle breakpoint in IL / C# view / source | `bp_toggle()`, `bp_set()` (IL offset), `bp_set_decompiled()` (decompiled C# line), `bp_set_line()` (PDB source line) | ✅ |
| Enable/disable/delete all (by label) | `bp_enable(on [, label])`, `bp_clear([label])`, plain UPDATE/DELETE | ✅ |
| Module Breakpoints window | `module_breakpoints` (`matches_loaded` shows which loaded modules match) | ✅ |
| Exception Settings window (first/second chance, module conditions, custom exceptions) | `exception_settings`, `break_on_exception()`, `throw_sites` (where each exception type is thrown) | ✅ |
| dnSpy persistence (`dnSpy.xml`) | `bp_export(path [, module [, module_dir]])` / `export_dnspy_breakpoints()` merge into `dnSpy.xml` and keep dnSpy's own entries; a new path gets a Breakpoints-window import file; `bp_import()` / `import_dnspy_breakpoints()` read either | ✅ |
| Breakpoints without a debugger's settings file (not in dnSpy) | `bp_patch([module])`: `if (Debugger.IsAttached) Debugger.Break();` written into the IL (journaled), then `save()` | ✅ |
| Module breakpoint shortcut | `bp_module(pattern [, on_load])` | ✅ |
| Watch windows (expressions) | `dnspy_watch` (INSERT/DELETE, synced into `dnSpy.xml`) | ✅ |
| Debugger options, incl. anti-anti-debug (IsDebuggerPresent, CheckRemoteDebuggerPresent, managed detection) | `dnspy_debugger_settings` (UPDATE value, synced into `dnSpy.xml`) | ✅ |
| Bound breakpoint state / hit counts at run time | — (by design) | — |
| Processes, threads, call stack, locals, memory, stepping | — (by design: no process debugging) | — |

## 2. Action surface (dnSpy AsmEditor)

### 2.1 Assembly / module

| dnSpy command | DnSpySql | |
|---|---|---|
| Edit Assembly (name, version, culture, public key, hash alg, flags) | `UPDATE assemblies SET …` (rename fixes AssemblyRefs like dnSpy) | ✅ |
| Edit Module (name, MVID, kind, runtime version, machine, characteristics, COR20 flags, entry point) | `UPDATE modules SET …` | ✅ |
| Create Assembly / NetModule, convert, add/remove netmodule | — | ❌ |
| Remove assembly from workspace (Close, Close All) | `close(module [, with_derived])` (with the stages and `untamper()` copy that came out of it), `close_all([keep_first])`; frees the memory, refused while a module has unsaved edits | ✅ |
| Strip strong name (common RE task) | `strip_strong_name()` | ✅ |

### 2.2 Namespaces

| dnSpy | DnSpySql | |
|---|---|---|
| Rename Namespace / Move to empty namespace | `rename_namespace(old, new)` (TypeRef fix-ups) | ✅ |
| Delete Namespace | `delete_namespace(ns)` | ✅ |

### 2.3 Types and members

| dnSpy | DnSpySql | |
|---|---|---|
| Create Type / Nested Type (kind presets) | `INSERT INTO types(namespace, name[, declaring_type, kind, base_type_name, visibility])` | ✅ |
| Edit Type (name, ns, kind, visibility, layout, sealed/abstract/serializable, base type, packing/size, flags) | `UPDATE types SET …` (TypeRef fix-ups) | ✅ |
| Interfaces list | `INSERT/DELETE interfaces` | ✅ |
| Delete Type | `DELETE FROM types` | ✅ |
| Create Method | `INSERT INTO methods(type, name[, return_type, is_static, visibility, flags])` (stub body) | ✅ |
| Edit Method (name, visibility, flags, impl flags, return type, params) | `UPDATE methods`, `UPDATE params SET name/type/flags/default_value` | ✅ |
| Edit method signature (add/remove parameters) | change `params.type`; no add/remove | ◐ |
| Overrides list / generic params editing | read-only | ◐ |
| Delete Method (detaches property/event semantics) | `DELETE FROM methods` | ✅ |
| Create / Edit / Delete Field (type, constant, RVA data, offset, flags) | `INSERT/UPDATE/DELETE fields` | ✅ |
| Marshal info editing | read-only (`fields.marshal`) | ◐ |
| Create Property / Event | — (use `add_members`) | ◐ |
| Edit Property / Event (name, flags, accessors, event type) | `UPDATE properties/events` | ✅ |
| Delete Property / Event | `DELETE FROM properties/events` | ✅ |
| Custom attributes (add/remove; typed arguments) | `INSERT INTO custom_attributes(owner, attribute_type, args_json)`, `DELETE` | ✅ |
| DeclSecurity editing | read-only | ◐ |
| P/Invoke (ImplMap) editing | `UPDATE pinvokes SET dll/entry/flags` | ✅ |
| Rename fix-ups for TypeRef/MemberRef | automatic on type/method/field rename | ✅ |

### 2.4 Method bodies (IL editor)

| dnSpy | DnSpySql | |
|---|---|---|
| Edit IL Instructions (opcode, operand of every kind) | `UPDATE il SET opcode/operand`, `il_set()` | ✅ |
| Insert / remove instructions (branch retargeting) | `INSERT INTO il`, `DELETE FROM il`, `il_insert()`, `il_remove()` | ✅ |
| Locals add/remove/rename/retype | `INSERT/UPDATE/DELETE locals` | ✅ |
| Exception handlers | `INSERT/UPDATE/DELETE exception_handlers` | ✅ |
| NOP-out / Replace with multiple NOPs | `il_nop(m, idx, count, keep_size)` | ✅ |
| Invert branch / Convert to unconditional | `il_invert_branch()`, `il_to_unconditional()`, `il_skip_branch()` | ✅ |
| Simplify / Optimize macros | `il_simplify()`, `il_optimize()` | ✅ |
| Replace body with stub / hex "return true/false" | `set_body_stub(m [, value])` | ✅ |
| max stack / init locals | `UPDATE methods SET max_stack, init_locals` | ✅ |
| Copy/paste instructions between methods | — (re-insert via `il_insert`) | ❌ |
| Replace all ldstr | `replace_string(old, new)` | ✅ |
| Decrypted strings in the code (not in dnSpy; what de4dot is run for before opening a sample in it) | `inline_strings([module [, decryptor [, mode]]])`: each call site `decryptor_calls` interprets to a string becomes `ldstr`, undoable; `save()` then hands dnSpy a readable copy; `mode` 'comment' or 'both' writes plaintexts as comments where the code cannot or must not change | ✅ |

### 2.5 C# compiler (Roslyn)

| dnSpy | DnSpySql | |
|---|---|---|
| Edit Method (C#) | `compile_method(m, 'C# method declaration')` — private access, lambdas, iterators/async (generated types are cloned) | ✅ |
| Add Class Members (C#) | `add_members(type, 'C# members')` | ✅ |
| Add Class (C#) | `add_type('C# source')`, compiled against the SDK reference pack so output references `System.Runtime` like normal builds | ✅ |
| Edit Class (C#) (sync whole type) | `edit_type(type, 'C# type definition')`: recompiles the type and splices bodies, members, closures, iterators, async state machines and `<PrivateImplementationDetails>` into the live type (journaled) | ✅ |
| Edit Assembly Attributes (C#) | — (use `custom_attributes`) | ◐ |
| Merge with Assembly | — | ❌ |
| VB compiler | — | ❌ |

### 2.6 Resources

| dnSpy | DnSpySql | |
|---|---|---|
| Create file resource / Edit (name, visibility, data) / Delete | `INSERT/UPDATE/DELETE resources` | ✅ |
| Create multi-file (.resources) resource | `INSERT INTO resources(name, data) VALUES (…, resource_set_empty())` | ✅ |
| Create/Edit/Delete .resources elements (string, primitives, byte[], stream) | `INSERT/UPDATE/DELETE resource_elements` | ✅ |
| Bitmap / Icon / ImageListStreamer elements | read: `resource_images`; create/replace: — | ◐ |
| Linked / assembly-linked resources creation | — | ❌ |
| Save / Raw Save resources | `SELECT data FROM resources` (client writes the file) | ◐ |

### 2.7 Hex / raw metadata

| dnSpy | DnSpySql | |
|---|---|---|
| Hex editor writes | `UPDATE file_bytes`, `patch_bytes()`, `save_raw()` | ✅ |
| Edit header fields | `UPDATE pe_fields SET value` | ✅ |
| Edit metadata table cells | `UPDATE md_rows SET value` | ✅ |
| Sort tables, paste rows | — | ❌ |

### 2.8 Save

| dnSpy | DnSpySql | |
|---|---|---|
| Save Module (preserve tokens, keep max stack, PDB, mixed-mode native writer) | `save([module,] path)`, setting `save_preserve_tokens` | ✅ |
| Full writer options dialog (PE headers, metadata header, heaps, RID options) | — | ◐ |
| Undo / redo (one group per command) | `undo(n)`, `redo(n)`, `transactions` (one group per SQL statement) | ✅ |

### 2.9 Breakpoint actions

| dnSpy | DnSpySql | |
|---|---|---|
| Toggle Breakpoint (F9) on an IL instruction / C# statement | `bp_toggle(method, offset)`, `bp_set_decompiled(handle, line)` | ✅ |
| Breakpoint Settings dialog (condition, hit count, filter, actions/tracepoint, labels) | `UPDATE breakpoints SET ...` | ✅ |
| Enable / Disable / Delete All Breakpoints | `bp_enable()`, `bp_clear()` | ✅ |
| Add / edit / remove module breakpoint | `INSERT/UPDATE/DELETE module_breakpoints` | ✅ |
| Exception settings: toggle break when thrown, add custom exception, conditions, restore defaults | `UPDATE/INSERT/DELETE exception_settings`, `break_on_exception()` | ◐ dnSpy's built-in list is not shipped; overrides are exported as updates |
| Export / import breakpoints | `bp_export()` / `export_dnspy_breakpoints()`, `bp_import()` / `import_dnspy_breakpoints()` | ✅ |
| Start / attach / step / evaluate | — (by design) | — |

## 3. Conventions shared with other SQL-over-binary tools

| Convention | DnSpySql |
|---|---|
| `binary` key/value with canonical keys (summary, tool_name, processor, filetype, image_base, entry_point, is_64bit, bits, md5, sha256 …) | ✅ (+ module/assembly/mvid/tfm keys) |
| `runtime_settings` (UPDATE value), `sql_capabilities` feature matrix, `transactions` undo journal | ✅ |
| Catalog for discovery | `dnspysql_tables`, `dnspysql_columns`, `dnspysql_functions` (+ `pragma_table_list`, `PRAGMA table_xinfo`) |
| Required filters on expensive tables with an actionable error | `pseudocode`, `pseudocode_lines`, `pseudocode_refs`, `md_rows`, `analyze`, `search`, `byte_search`, `api_docs`, `split_text` say exactly which `WHERE` is needed; `il`, `locals`, `exception_handlers`, `blocks`, `cfg_edges` take the filter but also scan |
| `pseudocode` one exact row per entity + per-line rows | `pseudocode` + `pseudocode_lines` |
| `xrefs`, `call_edges`, `callers`, `callees`, `string_refs`, `byte_search`, `jump_entities` | ✅ (same names) |
| `comments`, `bookmarks`, `tags`, `kv` (key/value notes) | ✅ persisted in `<input>.dnspysql.json` |
| Ranking view (`hotness_score`) | `method_metrics` |
| HTTP: `POST /query` (raw SQL or JSON `{sql, continue_on_error, include_sql, max_rows}`), `?format=json\|text\|csv\|tsv`, `/status`, `/health`, `/schema`, `/cancel`, `/shutdown`, Bearer / `X-XSQL-Token` auth, statement envelope | ✅ |
| MCP over stdio with a single query tool | `dnspysql_query` + `dnspysql_schema` (and the older `sql` / `schema`) |
| REPL dot commands (`.tables .schema .mode .save .http …`) | ✅ |

## Gaps

Prioritised list of what dnSpy can do that DnSpySql cannot yet:

Out of scope by design: running, attaching to or inspecting processes (dnSpy's debugger engine). Breakpoints are
configured here and executed by dnSpy.

1. **Breakpoint export details**: dnSpy matches a breakpoint by assembly full name + module *path*, so the export needs
   the directory dnSpy will open the files from (`module_dir`); exception overrides of dnSpy's built-in list are written
   as updates (dnSpy's default list is not bundled), new exception types as additions; dnSpy must be closed while
   `dnSpy.xml` is rewritten.
2. **Breakpoints in modules dnSpy loads from memory** (dynamic / in-memory modules) cannot be expressed; only file modules.
3. **Merge with Assembly**, **Edit Assembly Attributes (C#)**, VB compilation.
4. **Create assembly / netmodule**, convert netmodule ↔ assembly, add/remove netmodules.
5. **Signature editing**: adding/removing parameters, generic parameters, method overrides, marshal info,
   DeclSecurity and creating properties/events directly (use `add_members` instead).
6. **Analyzer fidelity**: accessibility-based scoping, COM/NoPIA equivalence, custom-attribute named-argument writes,
   remapping hits in compiler-generated code to the user method (beyond the async/iterator `MoveNext` link).
7. **Decompiler**: the ILAst debug language (Debug builds of dnSpy only), the VB project export,
   brace ranges, option toggles beyond language/tokens.
8. **Resources**: creating or replacing image elements, linked resources. Decoding image pixels is left to the caller:
   `resource_images.data` hands out the image file.
9. **Writer options**: the full dnSpy save dialog (PE header overrides, metadata/heap options, RID preservation per table).
   Saving keeps all tokens (`PreserveAll`) or none.
10. **.NET Framework targets on Linux**: `build.sh` bundles the .NET Framework 4.8 reference assemblies
    (`build/engine/refs`), and Mono's are used when installed; without either (offline build), pass `--ref DIR`.
