---
name: dotnet-batch
description: Triage many .NET files in one DnSpySql session — open a batch, take one summary row per sample (hashes, kind, framework, protection signs, resources, P/Invoke DLLs, URL-like strings), close it, go on to the next, and write the rows to JSONL or CSV for sorting and picking what to look at first. Use for "triage this folder", corpus runs, deduplicating samples, or ranking which sample to analyse.
---

# Batch triage with DnSpySql

One session can work through thousands of files if it closes what it is done with: memory is only released by
`close()` / `close_all()`. The summary rows are facts from the tables; ranking and judging them is yours, and each
sample worth it then gets a full pass with `dotnet-triage`. Never run a sample.

Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first.

## Session

- Start the server or CLI with `--no-project`: otherwise the first file opened holds the project file and stays open,
  and annotations of every sample land in it. With `--dnspy-xml off` nothing reaches dnSpy.
- `SELECT set_setting('max_modules', 50)` refuses opening past 50 at once, a guard against a loop that forgets to close.
- Some files are not .NET (native PEs, scripts, archives): `open()` fails with a message saying what the file is. Keep
  going after an error (`--continue` on the CLI, `continue_on_error` over MCP) and record the message as that file's row.
- A file you have already seen: compare `modules.sha256` with the rows you have before analysing it again.

## One batch

```sql
SELECT open('C:/corpus/a.exe'), open('C:/corpus/b.dll');    -- 10 to 50 files per batch
SELECT m.id, m.path, m.sha256, m.kind, m.target_framework, m.is_mixed_mode, m.repair, m.overlay_kind,
       m.type_count, m.method_count,
       (SELECT count(*) FROM method_bodies b WHERE b.module = m.id AND b.il_status NOT IN ('ok', 'native')) AS undecodable_bodies,
       (SELECT count(*) FROM resources r WHERE r.module = m.id) AS resources,
       (SELECT group_concat(DISTINCT p.dll) FROM pinvokes p WHERE p.module = m.id) AS native_dlls,
       (SELECT count(*) FROM string_refs s WHERE s.module = m.id AND s.kind = 'il' AND s.value REGEXP '(?i)https?://') AS urls
  FROM modules m;
SELECT close_all();
```

From the CLI, a script per batch gives one JSON object per row:

```
dnspysql --no-project --dnspy-xml off --format jsonl --continue -f batch-001.sql >> rows.jsonl
```

Generate the `open()` lines from a directory listing in your own code (quote `'` as `''`), and write the rows as you
go, so an interrupted run resumes at the next batch. Add columns the task needs: `binary`'s `anomalies` for the
primary module, a count of `xrefs` to an API, `entry_points`, `asmrefs`. A query that reads every method body
(`decompile()` of everything, `il` without a filter) costs seconds per sample: keep it for the samples you pick.

## Ranking

Sort and group the rows in your own code: undecodable bodies and repaired headers (packing or anti-tamper), an
overlay, few types with large resources (a loader), many P/Invoke DLLs, URL-like strings, mixed-mode. Group identical
`sha256` values and samples whose summaries match. Report the table, the samples you picked and why, and the files that
did not open with the reason given.
