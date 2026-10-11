"""Replay ASCII-encoded Unicode fixture patches with exact input/output hashes."""
import hashlib
import json
from pathlib import Path
import re


def apply_records(files, record_path):
    expected = dict(files)
    record = json.loads(Path(record_path).read_text())
    if record["format"] != 1:
        raise RuntimeError("unsupported English fixture record")
    seen = set()
    for entry in record["files"]:
        name = entry["path"]
        if name in seen or Path(name).is_absolute() or ".." in Path(name).parts:
            raise RuntimeError("invalid or duplicate English fixture path")
        seen.add(name)
        source = expected[name]
        if hashlib.sha256(source).hexdigest() != entry["before_sha256"]:
            raise RuntimeError(f"English fixture baseline mismatch: {name}")
        original = source.decode("utf-8").splitlines(keepends=True)
        lines = entry["patch"].splitlines(keepends=True)
        if lines[:2] != [f"--- a/{name}\n", f"+++ b/{name}\n"]:
            raise RuntimeError(f"English fixture patch path mismatch: {name}")
        output, cursor, index = [], 0, 2
        while index < len(lines):
            match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", lines[index])
            if not match:
                raise RuntimeError(f"invalid English fixture hunk: {name}")
            old_start, old_count, new_start, new_count = (int(match[1]), int(match[2] or 1),
                                                         int(match[3]), int(match[4] or 1))
            start = old_start if old_count == 0 else old_start - 1
            new_position = new_start if new_count == 0 else new_start - 1
            index += 1
            removed, added = [], []
            while index < len(lines) and not lines[index].startswith("@@ "):
                line = lines[index]
                if line[:1] not in {"-", "+"} or not line.endswith("\n"):
                    raise RuntimeError(f"invalid English fixture line: {name}")
                (removed if line[0] == "-" else added).append(line[1:])
                index += 1
            if (start < cursor or len(removed) != old_count or len(added) != new_count
                    or original[start:start + old_count] != removed):
                raise RuntimeError(f"English fixture hunk mismatch: {name}")
            output.extend(original[cursor:start])
            if len(output) != new_position:
                raise RuntimeError(f"English fixture output position mismatch: {name}")
            output.extend(added)
            cursor = start + old_count
        output.extend(original[cursor:])
        data = "".join(output).encode("utf-8")
        if hashlib.sha256(data).hexdigest() != entry["after_sha256"]:
            raise RuntimeError(f"English fixture output mismatch: {name}")
        expected[name] = data
    return expected
