#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 GRANITE_EFI..." >&2
    exit 64
fi

python3 - "$@" <<'PY'
import pathlib
import struct
import sys

for argument in sys.argv[1:]:
    path = pathlib.Path(argument)
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"invalid Granite image: {path}")

    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit(f"invalid DOS header: {path}")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SystemExit(f"missing PE signature: {path}")

    machine, _, timestamp, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    if machine != 0x8664:
        raise SystemExit(f"Granite is not an x86-64 PE image: {path}")

    optional = pe_offset + 24
    optional_end = optional + optional_size
    if optional_size < 168 or optional_end > len(data):
        raise SystemExit(f"truncated PE32+ optional header: {path}")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise SystemExit(f"Granite is not PE32+: {path}")

    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if directory_count <= 6:
        raise SystemExit(f"PE debug directory is unavailable: {path}")
    debug_rva, debug_size = struct.unpack_from(
        "<II", data, optional + 112 + (6 * 8)
    )
    if timestamp != 0 or debug_rva != 0 or debug_size != 0:
        raise SystemExit(f"nondeterministic PE metadata remains: {path}")
PY

printf '%s\n' 'Granite deterministic PE metadata verified'
