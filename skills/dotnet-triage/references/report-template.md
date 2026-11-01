# Triage report template

Fill each section from query results and your own decoding; leave a section out rather than padding it. Every
indicator is defanged.

```markdown
# <file name> — <verdict: malicious | suspicious | benign | unknown> (<confidence: high | medium | low>)

| | |
|---|---|
| SHA-256 | `<binary.sha256>` |
| MD5 | `<binary.md5>` |
| Type | <binary.summary> |
| Framework | <modules.target_framework> |
| Family | <name, or "unknown"> — <one line of evidence> |

## Summary
Two to four sentences: what it is, what it does, how it is protected, where its config came from.

## Protection
| technique | evidence |
|---|---|
From `binary.anomalies`, `method_bodies` (bodies that do not decode), `modules.repair`/`overlay`, obfuscated names,
and what the decompiled code shows (a string decryptor, a loader). List each stage opened with `open_bytes()` with
its module id and SHA-256 (`modules.sha256`).

## Configuration
| setting | value | source |
|---|---|---|
| C2 host | `hxxps://example[.]com:8443` | `Settings..cctor` IL_0012, decrypted by `a.b::c` (AES-CBC, key from `Settings.Key`) |
Source = a literal (`string_refs`, `il`), a resource, or your own decoding of one, with method and IL offset.

## Indicators
| kind | value (defanged) | where |
|---|---|---|

## Behaviour
| behaviour | API / evidence | method @ offset |
|---|---|---|

## Not determined statically
- Values computed at run time (machine-specific paths, random keys, server responses).
- Stages or strings that could not be decoded, and why.

## For dnSpy
- Methods worth opening, by full name and token (`tok(handle)`).
- Annotated copy and breakpoints, if made: path, and what each breakpoint shows.
```
