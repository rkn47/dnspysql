# Benchmarks

Wall time per query, including process start and assembly load. Each figure is the best of several
runs. Peak memory is the process's maximum resident set. Measured on Linux x64 (REMnux) on
2026-10-10.

- **before:** dnspysql as of `a85031e`, which used libxsql `cached_table` and full-row materialization.
- **after:** generator tables, column projection, batched cursors, count-only `COUNT(*)`, direct
  token lookups and engine-side equality indexes.

## FSharp.Compiler.Service.dll (38.5 MB)

| query | before | after |
|---|---|---|
| startup (`select 1`) | 0.32 s / 93 MB | 0.25 s / 93 MB |
| `count(*)` of types, methods, fields, memberrefs, user_strings | 6.83 s / 1189 MB | 1.70 s / 240 MB |
| `methods where name like 'get_%'` | 5.19 s / 1039 MB | 1.13 s / 280 MB |
| `select full_name from methods limit 10` | 5.73 s / 1041 MB | 0.88 s / 200 MB |
| methods per type (`types join methods`) | > 120 s | 1.42 s / 234 MB |
| `select *` from methods | 4.91 s / 1035 MB | 0.86 s / 197 MB |
| refs to one method (builds the reference index) | 7.53 s / 1016 MB | 6.88 s / 979 MB |

## A 4 MB obfuscated sample (39de24fdb23c: 2,857 types, 23,971 methods, 692,055 IL rows)

| query | before | after |
|---|---|---|
| startup | 0.20 s | 0.19 s |
| `count(*) from methods` | 1.43 s | 0.35 s |
| `count(distinct name) from methods` | 1.47 s | 0.46 s |
| method by token | 0.38 s | 0.21 s |
| methods per type (join) | 13.94 s | 0.56 s |
| IL of one method | 0.22 s | 0.22 s |
| IL full scan, count `call`s | 1.30 s | 1.44 s |
| all string references | 1.87 s | 1.89 s |
| `user_strings where value like '%http%'` | 0.20 s | 0.20 s |
| 30 queries in one session (distinct names, token lookup, join; ×10) | 167.6 s | 1.31 s |

## What changed and why

The `before` design pulled every row of a table, with every column computed, across the managed
boundary. It then buffered those rows twice. The join was quadratic: libxsql chose the
`methods.type_token` equality filter for each outer row, which is correct, and the engine answered
each probe by scanning all methods.

The rework uses only libxsql's public API (`generator_table`, `projection_generator`,
`filter_eq_projection`, `row_count`). libxsql itself is unmodified.

## Remaining gaps

- **`LIMIT` on a large table:** 0.88 s for 10 rows. A cursor snapshots the table's item
  list when it opens, so that an UPDATE or DELETE made while the cursor is open cannot invalidate it.
  The columns are still computed lazily.
- **Range filters (`token BETWEEN ...`)** are evaluated by SQLite over a projected scan, except on the
  columns that take ranges (`il.idx`, and `offset` in `file_bytes`, `file_map` and `heap_entries`). `IN`
  lists are pushed down as one equality probe per value.
- **The reference index is rebuilt in each process.** It dominates the first `refs` query.
