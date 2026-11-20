"""Reviewable repeat/literal input recipes and semantic JSON identities for large matrices."""
import hashlib
import json
import re
import struct


def byte_identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def recipe(data):
    parts = []
    cursor = 0
    for match in re.finditer(rb"(.{1,16}?)\1{3,}", data, re.DOTALL):
        if match.start() > cursor:
            parts.append([data[cursor:match.start()].hex(), 1])
        pattern = match.group(1)
        parts.append([pattern.hex(), len(match.group()) // len(pattern)])
        cursor = match.end()
    if cursor < len(data):
        parts.append([data[cursor:].hex(), 1])
    return dict(byte_identity(data), parts=parts)


def json_recipe(value):
    return recipe(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode())


def identity(value):
    digest = hashlib.sha256()
    count = 0
    def put(data):
        nonlocal count
        count += len(data)
        digest.update(data)
    def length(size):
        put(struct.pack(">Q", size))
    def visit(item):
        if item is None:
            put(b"n")
        elif isinstance(item, bool):
            put(b"t" if item else b"f")
        elif isinstance(item, int):
            # Match the existing serde_json::Value comparison domain.
            if -(2**63) <= item < 2**64:
                put(b"i" + str(item).encode() + b";")
            else:
                put(b"d" + struct.pack(">d", float(item)))
        elif isinstance(item, float):
            put(b"d" + struct.pack(">d", 0.0 if item == 0 else item))
        elif isinstance(item, str):
            data = item.encode("utf-8")
            put(b"s"); length(len(data)); put(data)
        elif isinstance(item, list):
            put(b"a"); length(len(item))
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            put(b"o"); length(len(item))
            for key in sorted(item):
                visit(key); visit(item[key])
        else:
            raise TypeError(type(item))
    visit(value)
    return {"encoding": "json-value-v1", "bytes": count, "sha256": digest.hexdigest()}


def document(rows, raw_stdout):
    return {"version": 1, "raw_stdout": byte_identity(raw_stdout), "rows": rows}
