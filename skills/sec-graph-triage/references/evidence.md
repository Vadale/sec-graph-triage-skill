# Evidence collection reference

## Inputs and invocation

An existing SARIF 2.1.0 report and an explicitly selected Python directory.
The helper uses only the standard library and does not execute the target program,
scanner, graph engine or network client. A POSIX runtime with descriptor-relative
open/stat and no-follow flags is required; source symlinks are rejected. Python
3.11+ is the target API level. Local runtime validation was on Linux/Python 3.15;
Python 3.11 was not runtime-tested. Check other runtimes/platforms rather than
assuming compatibility.

Use `--root`, `--sarif`, `--output`; the output parent must already exist. Output
must be new and outside the source tree. Optional `--context 0..10` defaults to 3;
repeatable `--finding RUN:RESULT` selects at most 20 unique zero-based pairs.
Without selectors the first 20 results are collected and the remaining count is
explicit. That default can complete with status ok while other results remain
unselected; state the reviewed scope in the answer.

For a report made at another root, provide the user's explicit mapping:

```sh
python /path/to/skill/scripts/collect_context.py \
  --root /work/current-project --sarif /work/report.sarif \
  --map /old/build/project=. --finding 0:2 \
  --output /work/evidence-new.json
```

Mappings match whole absolute prefixes, longest first; destinations are relative
to the selected root. A location records whether a mapping was applied. There is
no suffix/basename search. Relative URI, in-root file URI, artifact index and checked
nested `originalUriBaseIds` are supported. Nonlocal schemes/hosts, traversal,
unresolved/cyclic bases, escaping absolute paths and unsupported physical shapes
remain explicit failures/gaps. Cached thread-location indices and logical-only
locations can be reported unsupported; do not invent their coordinates.
URI bases must be directory URIs ending `/`, with an absolute ancestor or a checked
parent chain. Container-relative nested artifacts are unsupported. Controls,
ambiguous leading whitespace and query/fragment delimiters are rejected rather
than silently selecting another filename.

## Read the output

The CLI prints a small JSON receipt. For exit 0/2, open its output JSON:

| Field | Meaning |
|---|---|
| `status` | Collection state only: ok, partial or error |
| `helper`, `input.sha256` | Helper version/hash and exact report-byte identity |
| `counts` | Input runs/results, selected results and unselected results |
| `diagnostics` | Structured code, explanation and affected positions |
| `results[].id` | RUN:RESULT, bound to this input hash; duplicates stay distinct |
| `reported` | Upstream rule/tool/message/level, not independently validated claims |
| `primary_locations` | Reported result locations, separate from flow steps |
| `code_flows[].thread_flows[].steps` | Original separate flow/thread order, indices and gaps |
| `*_counts` | Input, retained and omitted counts for bounded evidence arrays |
| Location `path`, `line`, `end_line`, `window` | Root-relative path and current line-numbered excerpts |
| Location/file `current_sha256` | Exact source-byte snapshot used for excerpts |
| `reported_digest_relation` | match/mismatch/unknown/unsupported versus supplied digest claims |
| `snippet_relation` | Separate current-text agreement, never whole-file identity |
| `files` | Collected file metadata; errors remain visible |
| `reported_columns` | Original column metadata, not semantically validated |

Each location's digest relation is scoped to its own run; a digest from another
run cannot establish its correspondence. File metadata retains
`reported_digest_relations` per run. A mixed file-wide aggregate is unknown; consult
the per-run entries and location evidence rather than treating it as one scan.

Exit 0 = requested collection completed; absent scan identity can still be unknown.
Exit 2 = a selected source/reference is missing, mismatched, unsupported, invalid
or truncated, or upstream execution failed. Use usable current evidence but retain
these limits. Exit 1 = invalid input/invocation, resource failure or output error;
the JSON error receipt is printed and no successful evidence is claimed.

Reported digests may have been supplied by a scanner or post-processing. A match
does not authenticate the producer or prove the scan used those bytes. New current
hashes identify this collection only. Source and snippets are read as UTF-8 (BOM
permitted); unsupported encodings are not silently replaced. Positive integer line
numbers are required; missing/invalid locations are never changed to line 1.

## Boundaries and limits

| Resource | Ceiling |
|---|---|
| SARIF / JSON depth | 8 MiB / 64 |
| Runs / input results / selected results | 20 / 200 / 20 |
| Primary locations / code flows per result | 16 / 8 |
| Threads per flow / steps per thread | 8 / 64 |
| URI base chain | 16 links |
| Unique source files / per-file bytes | 100 / 1 MiB |
| Context / source window / serialized bundle | 0–10 each side / 16 KiB / 2 MiB |

Top-level ceilings reject before collection; per-evidence limits retain original
positions/counts and diagnostics. If the complete serialized bundle exceeds 2 MiB,
select fewer results; the helper refuses to emit invalid truncated JSON. Source
files are read once per path as bounded byte snapshots. Output creation is exclusive.
The read boundary handles static symlinks/nonregular files, not an OS sandbox or
an actively hostile process racing filesystem changes.
Window-byte accounting includes a rendered delimiter per retained line, including
blank lines. Repeated evidence is budgeted while collected. The serialized-output
ceiling is not a process-memory limit: parsing, source snapshots and Python objects
also consume memory.

Useful response to partial evidence: identify the unresolved file/base/line or
digest relation and request the exact missing report/snapshot/mapping. Do not
silently install/run a scanner or collect unrelated project files as a workaround.

Specification: [OASIS SARIF 2.1.0 + Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
