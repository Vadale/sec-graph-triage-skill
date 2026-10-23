#!/usr/bin/env python3
"""Collect bounded current-source evidence for existing SARIF 2.1.0 findings.

Selected URI/base and physical-location concepts adapted from sec-graph,
Copyright (c) 2026 Alessandro Vadala, MIT; see ../LICENSE and ../references/provenance.md.
No target code, scanners, graph engine, network services or third-party packages run.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
from urllib.parse import unquote, urlsplit

VERSION = "0.1.0"
LIMITS = {"sarif_bytes": 8 * 1024**2, "json_depth": 64, "runs": 20,
          "input_results": 200, "selected_results": 20, "primary_locations": 16,
          "code_flows": 8, "thread_flows": 8, "steps": 64, "uri_base_links": 16,
          "source_files": 100, "source_bytes": 1024**2, "window_bytes": 16 * 1024,
          "evidence_bytes": 2 * 1024**2}


class CollectionError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path, ceiling, code):
    """Bound an explicitly supplied input without blocking on pipes/devices."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CollectionError(code, "Input must be a regular file")
        if info.st_size > ceiling:
            raise CollectionError(code, "Input exceeds its byte ceiling")
        raw = stream.read(ceiling + 1)
        if len(raw) > ceiling:
            raise CollectionError(code, "Input exceeds its byte ceiling")
        return raw


def parse_report(raw):
    # Check depth before json.loads, including arrays/objects in irrelevant fields.
    quoted, escaped, depth = False, False, 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > LIMITS["json_depth"]:
                raise CollectionError("json_depth", "JSON nesting exceeds the supported ceiling")
        elif byte in (93, 125):
            depth -= 1

    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise CollectionError("json_duplicate_key", "Duplicate JSON key")
            obj[key] = value
        return obj

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise CollectionError("invalid_shape", "Non-finite JSON number")
        return number

    def constant(_):
        raise CollectionError("invalid_shape", "Non-finite JSON constant")

    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=object_pairs,
                          parse_float=finite, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CollectionError("invalid_shape", "Invalid UTF-8 JSON document") from exc
    if not isinstance(data, dict):
        raise CollectionError("invalid_shape", "SARIF document must be an object")
    pending = [data]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise CollectionError("invalid_shape", "JSON contains a lone Unicode surrogate") from exc
    if data.get("version") != "2.1.0":
        raise CollectionError("unsupported_version", "Only the SARIF 2.1.0 profile is supported")
    runs = data.get("runs")
    if not isinstance(runs, list) or any(not isinstance(r, dict) for r in runs):
        raise CollectionError("invalid_shape", "runs must be an array of objects")
    if len(runs) > LIMITS["runs"]:
        raise CollectionError("input_limit", "Too many SARIF runs")
    count = 0
    for run in runs:
        results = run.get("results", [])
        if not isinstance(results, list):
            raise CollectionError("invalid_shape", "run.results must be an array")
        count += len(results)
    if count > LIMITS["input_results"]:
        raise CollectionError("input_limit", "Too many SARIF results")
    return data


def uri_path(uri):
    """Adapted URI normalization: no suffix rescue or unvalidated remote scheme."""
    if not isinstance(uri, str) or not uri or "\0" in uri:
        raise CollectionError("unsupported_reference", "Missing or invalid artifact URI")
    if re.search(r"%(?![0-9a-fA-F]{2})", uri):
        raise CollectionError("unsupported_reference", "Malformed URI escape")
    try:
        text = unquote(uri, errors="strict").replace("\\", "/")
        if any(ord(char) < 32 or ord(char) == 127 for char in text) or text[:1].isspace():
            raise CollectionError("unsupported_reference", "Ambiguous whitespace or control in artifact URI")
        if "?" in text or "#" in text:
            raise CollectionError("uri_query", "Query/fragment delimiters are unsupported, including escaped forms")
        parsed = urlsplit(text) if not re.match(r"^[A-Za-z]:/", text) else None
    except (ValueError, UnicodeError) as exc:
        raise CollectionError("unsupported_reference", "Malformed artifact URI") from exc
    if parsed is not None:
        if parsed.query or parsed.fragment:
            raise CollectionError("uri_query", "Queries and fragments are not supported")
        if parsed.scheme not in ("", "file"):
            raise CollectionError("uri_scheme", "Only local file URIs are supported")
        if parsed.netloc not in ("", "localhost"):
            raise CollectionError("uri_host", "Nonlocal URI host is not supported")
        text = parsed.path
    if "\0" in text or ".." in text.split("/"):
        raise CollectionError("path_traversal", "Traversal or NUL in artifact path")
    if text.startswith("//"):
        raise CollectionError("uri_host", "Network path is not supported")
    return posixpath.normpath(text)


def absolute(path):
    return path.startswith("/") or bool(re.match(r"^[A-Za-z]:/", path))


def source_lines(raw):
    text = raw.decode("utf-8-sig")
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


class Sources:
    """One byte snapshot per source file; source paths are never report roots."""
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise CollectionError("output_path", "Source root must be a directory")
        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
                or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd):
            raise CollectionError("unsupported_reference", "This runtime cannot enforce the source read boundary")
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.cache = {}

    def close(self):
        os.close(self.fd)

    def get(self, relative):
        if relative in self.cache:
            return self.cache[relative]
        if len(self.cache) >= LIMITS["source_files"]:
            raise CollectionError("source_file_limit", "Too many referenced source files")
        parts = PurePosixPath(relative).parts
        if not parts or ".." in parts or PurePosixPath(relative).is_absolute():
            raise CollectionError("outside_root", "Source path is outside the explicit root")
        fd = os.dup(self.fd)
        try:
            for index, part in enumerate(parts):
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    raise CollectionError("source_symlink", "Source symlinks are not followed")
                last = index == len(parts) - 1
                if not (stat.S_ISREG(info.st_mode) if last else stat.S_ISDIR(info.st_mode)):
                    raise CollectionError("source_nonregular", "Source must be a regular file through real directories")
                if last and info.st_size > LIMITS["source_bytes"]:
                    raise CollectionError("source_size", "Source exceeds its byte ceiling")
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                new = os.open(part, flags | (0 if last else os.O_DIRECTORY), dir_fd=fd)
                os.close(fd)
                fd = new
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIMITS["source_bytes"]:
                raise CollectionError("source_nonregular", "Source changed or is not a bounded regular file")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                raw = stream.read(LIMITS["source_bytes"] + 1)
            if len(raw) > LIMITS["source_bytes"]:
                raise CollectionError("source_size", "Source exceeds its byte ceiling")
            record = {"path": relative, "current_sha256": sha(raw), "bytes": len(raw), "status": "ok"}
            try:
                lines = source_lines(raw)
            except UnicodeError:
                raise CollectionError("source_encoding", "Source is not supported UTF-8")
            entry = (record, lines)
        except OSError as exc:
            code = "source_symlink" if exc.errno == errno.ELOOP else "source_missing"
            entry = ({"path": relative, "status": "missing", "error": code}, [])
        except CollectionError as exc:
            entry = ({"path": relative, "status": "unsupported", "error": exc.code}, [])
        finally:
            if fd is not None:
                os.close(fd)
        self.cache[relative] = entry
        return entry


class Collector:
    def __init__(self, sources, mappings, context):
        self.sources, self.context = sources, context
        self.diagnostics, self.claims, self.mappings = [], {}, []
        self.relations = {}
        self.budget_used = 0
        for mapping in mappings:
            if "=" not in mapping:
                raise CollectionError("output_path", "A mapping must have OLD=RELATIVE form")
            old, new = mapping.split("=", 1)
            old, new = uri_path(old), uri_path(new or ".")
            if not absolute(old) or absolute(new):
                raise CollectionError("outside_root", "Mapping needs an absolute old prefix and relative destination")
            if any(k == old and v != new for k, v in self.mappings):
                raise CollectionError("invalid_shape", "Conflicting mappings for the same prefix")
            self.mappings.append((old.rstrip("/"), new))
        self.mappings.sort(key=lambda pair: (-len(pair[0]), pair))

    def consume(self, value):
        # Stop repeated windows/diagnostics before they amplify a small input into
        # a huge in-memory evidence object. Final encoding has its own exact cap.
        for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":")).iterencode(value):
            self.budget_used += len(chunk.encode("utf-8"))
            if self.budget_used > LIMITS["evidence_bytes"]:
                raise CollectionError("evidence_limit", "Evidence exceeds its budget; select fewer results or less context")

    def issue(self, code, message, **where):
        item = {"code": code, "message": message, **where}
        self.consume(item)
        self.diagnostics.append(item)

    def bounded(self, value, ceiling, label, **where):
        if not isinstance(value, list):
            self.issue("invalid_shape", label + " must be an array", **where)
            return [], {"input": 0, "retained": 0, "omitted": 0}
        count = len(value)
        if count > ceiling:
            self.issue("input_limit", label + " truncated at the declared ceiling", **where)
        return value[:ceiling], {"input": count, "retained": min(count, ceiling), "omitted": max(0, count - ceiling)}

    def bind(self, artifact, run):
        if not isinstance(artifact, dict):
            raise CollectionError("unsupported_reference", "Missing artifact location")
        index = artifact.get("index")
        indexed = None
        if index is not None:
            artifacts = run.get("artifacts", [])
            if not integer(index) or not isinstance(artifacts, list) or not 0 <= index < len(artifacts):
                raise CollectionError("unsupported_reference", "Invalid artifact index")
            obj = artifacts[index]
            if not isinstance(obj, dict) or not isinstance(obj.get("location"), dict):
                raise CollectionError("unsupported_reference", "Artifact index has no physical file URI")
            if obj.get("parentIndex") is not None:
                raise CollectionError("unsupported_reference", "Nested/container artifacts are outside this source profile")
            indexed = obj["location"]
            if "index" in indexed and (not integer(indexed["index"]) or indexed["index"] != index):
                raise CollectionError("unsupported_reference", "Artifact's own location index is inconsistent")
        if "uri" not in artifact:
            if indexed is None:
                raise CollectionError("unsupported_reference", "No file URI in physical location")
            artifact = indexed
        path = uri_path(artifact.get("uri"))
        base_id = artifact.get("uriBaseId")
        if not absolute(path) and base_id is not None:
            bases, parts, seen = run.get("originalUriBaseIds", {}), [], set()
            if not isinstance(bases, dict):
                raise CollectionError("uri_base_missing", "URI base table is invalid")
            while base_id is not None:
                if not isinstance(base_id, str) or base_id not in bases:
                    raise CollectionError("uri_base_missing", "URI base is absent")
                if base_id in seen:
                    raise CollectionError("uri_base_cycle", "Cyclic URI base chain")
                if len(seen) >= LIMITS["uri_base_links"]:
                    raise CollectionError("uri_base_limit", "URI base chain exceeds its ceiling")
                seen.add(base_id)
                base = bases[base_id]
                if not isinstance(base, dict):
                    raise CollectionError("uri_base_missing", "Invalid URI base")
                if not isinstance(base.get("uri"), str) or not base["uri"].endswith("/"):
                    raise CollectionError("uri_base_missing", "URI bases must end with a directory slash")
                part = uri_path(base.get("uri"))
                parts.append(part)
                if absolute(part):
                    break
                base_id = base.get("uriBaseId")
                if base_id is None:
                    raise CollectionError("uri_base_missing", "Relative URI base has no absolute anchor or parent")
            path = posixpath.join(*reversed(parts), path)
        mapped = False
        if absolute(path):
            for old, new in self.mappings:
                if path == old or path.startswith(old + "/"):
                    path = posixpath.join(new, path[len(old):].lstrip("/"))
                    mapped = True
                    break
            if absolute(path):
                try:
                    path = PurePosixPath(path).relative_to(self.sources.root.as_posix()).as_posix()
                except ValueError as exc:
                    raise CollectionError("outside_root", "Absolute URI is outside the explicit root; mapping required") from exc
        path = posixpath.normpath(path)
        if absolute(path) or ".." in path.split("/"):
            raise CollectionError("outside_root", "Resolved source is outside the explicit root")
        if not path.endswith(".py"):
            raise CollectionError("unsupported_reference", "Only referenced Python .py files are supported")
        if indexed is not None and indexed is not artifact:
            index_path, _ = self.bind({key: value for key, value in indexed.items() if key != "index"}, run)
            if index_path != path:
                raise CollectionError("unsupported_reference", "Artifact URI conflicts with its index")
        return path, mapped

    def reported_hashes(self, run, run_index):
        artifacts = run.get("artifacts", [])
        if not isinstance(artifacts, list):
            self.issue("invalid_shape", "artifacts must be an array", run_index=run_index)
            return
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            if artifact.get("parentIndex") is not None:
                continue  # Container-relative contents are not source-root files.
            try:
                path, _ = self.bind(artifact.get("location"), run)
            except CollectionError:
                continue  # Unreferenced artifacts are not source-read requests.
            hashes = artifact.get("hashes", {})
            self.claims.setdefault((run_index, path), []).append({"run_index": run_index, "hashes": hashes})

    def digest_relation(self, path, record, run_index):
        key = (run_index, path)
        if key in self.relations:
            return self.relations[key]
        claims = self.claims.get(key, [])
        values, invalid, unsupported = [], False, False
        for claim in claims:
            hashes = claim["hashes"]
            if not isinstance(hashes, dict):
                invalid = True
                continue
            if hashes and "sha-256" not in hashes:
                unsupported = True
            if "sha-256" in hashes:
                value = hashes["sha-256"]
                if not isinstance(value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
                    invalid = True
                else:
                    values.append(value.lower())
        relation = "unknown"
        if invalid or len(set(values)) > 1:
            self.issue("reported_digest_invalid", "Malformed or conflicting reported SHA-256", path=path, run_index=run_index)
        elif values:
            relation = "match" if values[0] == record.get("current_sha256") else "mismatch"
            if relation == "mismatch":
                self.issue("reported_digest_mismatch", "Current bytes differ from the report-provided digest", path=path, run_index=run_index)
        elif unsupported:
            relation = "unsupported"
            self.issue("reported_digest_unsupported", "No supported SHA-256 in reported hashes", path=path, run_index=run_index)
        digest = values[0] if not invalid and len(set(values)) == 1 else None
        record.setdefault("reported_digest_relations", []).append(
            {"run_index": run_index, "relation": relation, "reported_sha256": digest})
        record.setdefault("reported_claims", []).extend(claims)
        relations = record["reported_digest_relations"]
        unique = {r["relation"] for r in relations}
        digests = {r["reported_sha256"] for r in relations}
        record.update(reported_sha256=next(iter(digests)) if len(digests) == 1 else None,
                      reported_digest_relation=next(iter(unique)) if len(unique) == 1 else "unknown",
                      scan_time_verified=False)
        problematic = invalid or len(set(values)) > 1 or relation in ("mismatch", "unsupported")
        self.relations[key] = (relation, problematic)
        return relation, problematic

    def location(self, raw, run, **where):
        out = self._location(raw, run, **where)
        # Window rows were charged before append; do not count them twice.
        self.consume({key: value for key, value in out.items() if key != "window"})
        return out

    def _location(self, raw, run, **where):
        out = {"status": "unsupported", "window": [], "snippet_relation": "unknown"}
        try:
            if not isinstance(raw, dict) or not isinstance(raw.get("physicalLocation"), dict):
                raise CollectionError("unsupported_reference", "No supported physical location")
            physical = raw["physicalLocation"]
            path, mapped = self.bind(physical.get("artifactLocation"), run)
            out.update(path=path, mapping_applied=mapped)
            region = physical.get("region", {})
            if not isinstance(region, dict):
                raise CollectionError("invalid_shape", "region must be an object")
            out["reported_columns"] = {name: region[name] for name in ("startColumn", "endColumn") if name in region}
            snippet = region.get("snippet", {})
            snippet_problem = not isinstance(snippet, dict) or ("text" in snippet and not isinstance(snippet["text"], str))
            if snippet_problem:
                self.issue("invalid_shape", "snippet must be an object with textual text", **where)
                out["snippet_error"] = "invalid_shape"
            line = region.get("startLine")
            if line is None:
                raise CollectionError("line_missing", "No source startLine supplied")
            if not integer(line) or line < 1:
                raise CollectionError("line_invalid", "startLine must be a positive integer")
            end = region.get("endLine", line)
            if not integer(end) or end < line:
                raise CollectionError("line_invalid", "Invalid endLine")
            out.update(line=line, end_line=end)
            record, lines = self.sources.get(path)
            if record["status"] != "ok":
                raise CollectionError(record["error"], "Referenced source could not be read within the profile")
            if end > len(lines):
                raise CollectionError("line_out_of_range", "Location exceeds current source lines")
            before = len(self.diagnostics)
            relation, digest_problem = self.digest_relation(path, record, where["run_index"])
            out.update(status="ok", current_sha256=record["current_sha256"], reported_digest_relation=relation)
            lo, hi = max(1, line - self.context), min(len(lines), end + self.context)
            total_bytes = sum(len(lines[n - 1].encode("utf-8")) + 1 for n in range(lo, hi + 1))
            used = 0
            for number in range(lo, hi + 1):
                text = lines[number - 1]
                size = len(text.encode("utf-8")) + 1  # Include a rendered line delimiter, even for blank lines.
                if used + size > LIMITS["window_bytes"]:
                    self.issue("window_limit", "Source window exceeds its byte ceiling", **where)
                    break
                row = {"line": number, "text": text}
                self.consume(row)
                out["window"].append(row)
                used += size
            out["window_counts"] = {"input": hi - lo + 1, "retained": len(out["window"]),
                                    "omitted": hi - lo + 1 - len(out["window"])}
            out["window_bytes"] = {"input": total_bytes, "retained": used, "omitted": total_bytes - used}
            if isinstance(snippet, dict) and isinstance(snippet.get("text"), str) and snippet["text"]:
                given = source_lines(snippet["text"].encode("utf-8"))
                out["snippet_relation"] = "match" if given == lines[line - 1:line - 1 + len(given)] else "mismatch"
                if out["snippet_relation"] == "mismatch":
                    self.issue("snippet_mismatch", "Reported snippet differs from current source", **where)
            if digest_problem or snippet_problem or len(self.diagnostics) != before:
                out["status"] = "partial"
        except CollectionError as exc:
            if exc.code == "evidence_limit":
                raise  # Global exhaustion must not become a recoverable location gap.
            out["error"] = exc.code
            self.issue(exc.code, exc.message, **where)
        return out

    def result(self, raw, run, run_index, result_index):
        where = {"run_index": run_index, "result_index": result_index}
        result = {"id": f"{run_index}:{result_index}", **where, "reported": {},
                  "primary_locations": [], "code_flows": []}
        if not isinstance(raw, dict):
            self.issue("invalid_shape", "Result must be an object", **where)
            return result
        tool = run.get("tool", {})
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        message = raw.get("message", {})
        claims = {"rule_id": raw.get("ruleId"),
                  "tool": driver.get("name") if isinstance(driver, dict) else None,
                  "message": message.get("text", message.get("markdown")) if isinstance(message, dict) else None,
                  "level": raw.get("level")}
        for name, value in claims.items():
            if value is not None and not isinstance(value, str):
                self.issue("invalid_shape", "Reported " + name + " must be text", **where)
                claims[name] = None
        if not isinstance(message, dict):
            self.issue("invalid_shape", "Result message must be an object", **where)
        elif any(key in message and not isinstance(message[key], str) for key in ("text", "markdown", "id")):
            self.issue("invalid_shape", "Message text, markdown and id must be strings", **where)
        if not isinstance(tool, dict) or not isinstance(driver, dict):
            self.issue("invalid_shape", "Tool/driver must be objects", **where)
        if claims["level"] is not None and claims["level"] not in ("none", "note", "warning", "error"):
            self.issue("invalid_shape", "Reported level is not a SARIF level", **where)
            claims["level"] = None
        result["reported"] = claims
        self.consume(claims)
        primary, counts = self.bounded(raw.get("locations", []), LIMITS["primary_locations"], "primary locations", **where)
        result["primary_locations_counts"] = counts
        result["primary_locations"] = [self.location(loc, run, location_index=i, **where) for i, loc in enumerate(primary)]
        flows, counts = self.bounded(raw.get("codeFlows", []), LIMITS["code_flows"], "code flows", **where)
        result["code_flows_counts"] = counts
        if not primary and not flows:
            self.issue("unsupported_reference", "Result has no supported source evidence", **where)
        for flow_index, flow in enumerate(flows):
            fwhere = {**where, "flow_index": flow_index}
            entry = {"index": flow_index, "thread_flows": []}
            if not isinstance(flow, dict):
                self.issue("invalid_shape", "Code flow must be an object", **fwhere)
                result["code_flows"].append(entry)
                continue
            threads, counts = self.bounded(flow.get("threadFlows"), LIMITS["thread_flows"], "thread flows", **fwhere)
            if not threads:
                self.issue("invalid_shape", "Code flow needs at least one thread flow", **fwhere)
            entry["thread_flows_counts"] = counts
            for thread_index, thread in enumerate(threads):
                twhere = {**fwhere, "thread_index": thread_index}
                tentry = {"index": thread_index, "steps": []}
                if not isinstance(thread, dict):
                    self.issue("invalid_shape", "Thread flow must be an object", **twhere)
                    entry["thread_flows"].append(tentry)
                    continue
                steps, counts = self.bounded(thread.get("locations"), LIMITS["steps"], "thread steps", **twhere)
                if not steps:
                    self.issue("invalid_shape", "Thread flow needs at least one location", **twhere)
                tentry["steps_counts"] = counts
                for step_index, step in enumerate(steps):
                    location = step.get("location") if isinstance(step, dict) else None
                    tentry["steps"].append({"index": step_index,
                                           "location": self.location(location, run, step_index=step_index, **twhere)})
                entry["thread_flows"].append(tentry)
            result["code_flows"].append(entry)
        return result


def collect(args):
    raw = regular_bytes(args.sarif, LIMITS["sarif_bytes"], "sarif_size")
    data = parse_report(raw)
    pairs = [(ri, i) for ri, run in enumerate(data["runs"]) for i, _ in enumerate(run.get("results", []))]
    if args.finding:
        if len(args.finding) > LIMITS["selected_results"]:
            raise CollectionError("input_limit", "Too many explicitly selected results")
        selected = []
        for value in args.finding:
            if not re.fullmatch(r"[0-9]{1,3}:[0-9]{1,3}", value):
                raise CollectionError("invalid_shape", "Finding selector must be RUN:RESULT")
            pair = tuple(int(n) for n in value.split(":"))
            if pair not in pairs or pair in selected:
                raise CollectionError("invalid_shape", "Unknown or duplicate finding selector")
            selected.append(pair)
    else:
        selected = pairs[:LIMITS["selected_results"]]
    sources = Sources(args.root)
    try:
        collector = Collector(sources, args.mapping, args.context)
        for run_index, run in enumerate(data["runs"]):
            collector.reported_hashes(run, run_index)
            invocations = run.get("invocations", [])
            if not isinstance(invocations, list):
                collector.issue("invalid_shape", "invocations must be an array", run_index=run_index)
            else:
                for invocation in invocations:
                    if not isinstance(invocation, dict) or ("executionSuccessful" in invocation and not isinstance(invocation["executionSuccessful"], bool)):
                        collector.issue("invalid_shape", "Invalid invocation or executionSuccessful boolean", run_index=run_index)
                    elif invocation.get("executionSuccessful") is False:
                        collector.issue("upstream_failed", "Upstream scanner reported unsuccessful execution", run_index=run_index)
        results = [collector.result(data["runs"][ri]["results"][i], data["runs"][ri], ri, i) for ri, i in selected]
        files = [entry[0] for _, entry in sorted(sources.cache.items())]
        bundle = {"schema_version": 1, "helper": {"name": "sec-graph-triage", "version": VERSION,
                  "sha256": sha(Path(__file__).read_bytes())}, "input": {"sha256": sha(raw), "version": "2.1.0"},
                  "status": "partial" if collector.diagnostics else "ok", "diagnostics": collector.diagnostics,
                  "counts": {"runs": len(data["runs"]), "input_results": len(pairs),
                             "selected_results": len(selected), "unselected_results": len(pairs) - len(selected)},
                  "results": results, "files": files, "limits": LIMITS}
        chunks, used = [], 1
        for chunk in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":")).iterencode(bundle):
            encoded_chunk = chunk.encode("utf-8")
            used += len(encoded_chunk)
            if used > LIMITS["evidence_bytes"]:
                raise CollectionError("evidence_limit", "Evidence exceeds its serialized ceiling; select fewer results")
            chunks.append(encoded_chunk)
        encoded = b"".join(chunks) + b"\n"
        return bundle, encoded
    finally:
        sources.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CollectionError("invalid_shape", message)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--finding", action="append", default=[])
    parser.add_argument("--map", dest="mapping", action="append", default=[])
    parser.add_argument("--context", type=int, default=3)
    try:
        args = parser.parse_args(argv)
        if not 0 <= args.context <= 10:
            raise CollectionError("input_limit", "Context must be between 0 and 10")
        output = Path(args.output)
        root = Path(args.root).resolve(strict=True)
        parent = output.parent.resolve(strict=True)
        resolved_output = parent / output.name
        if resolved_output == Path(args.sarif).resolve() or resolved_output.is_relative_to(root):
            raise CollectionError("output_path", "Output must be separate from SARIF and the source tree")
        if output.exists() or output.is_symlink():
            raise CollectionError("output_exists", "Output already exists; choose a new destination")
        bundle, encoded = collect(args)
        # Exclusive creation also protects an output created since the preflight.
        with output.open("xb") as stream:
            stream.write(encoded)
        print(json.dumps({"status": bundle["status"], "output": str(output), "counts": bundle["counts"]}))
        return 0 if bundle["status"] == "ok" else 2
    except CollectionError as exc:
        print(json.dumps({"status": "error", "diagnostics": [{"code": exc.code, "message": exc.message}]}))
        return 1
    except OSError as exc:
        code = "output_exists" if isinstance(exc, FileExistsError) else "output_path"
        print(json.dumps({"status": "error", "diagnostics": [{"code": code, "message": str(exc)}]}))
        return 1
    except UnicodeError:
        print(json.dumps({"status": "error", "diagnostics": [{"code": "invalid_shape", "message": "Unsupported Unicode input"}]}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
