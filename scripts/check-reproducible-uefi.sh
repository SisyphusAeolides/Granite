#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/granite-reproducible.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

artifact_root="$scratch/artifacts"
mkdir -p "$artifact_root"
printf '%s' 'bounded-kernel-fixture' >"$artifact_root/arach"
printf '%s' 'bounded-push-fixture' >"$artifact_root/push"
printf '%s' 'bounded-crest-fixture' >"$artifact_root/crest"

for build in first second; do
    ARACH_KERNEL_IMAGE="$artifact_root/arach" \
    ARACH_PUSH_IMAGE="$artifact_root/push" \
    ARACH_CREST_IMAGE="$artifact_root/crest" \
    CARGO_TARGET_DIR="$scratch/$build" \
        "$cargo_bin" build --locked --release \
            --manifest-path "$root/Cargo.toml" \
            --target x86_64-unknown-uefi \
            --features uefi-bin,require-artifacts
done

first="$scratch/first/x86_64-unknown-uefi/release/granite.efi"
second="$scratch/second/x86_64-unknown-uefi/release/granite.efi"
cmp --silent "$first" "$second"

python3 - "$first" "$second" <<'PY'
import pathlib
import struct
import sys

for argument in sys.argv[1:]:
    path = pathlib.Path(argument)
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise SystemExit(f"invalid PE image: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SystemExit(f"missing PE signature: {path}")
    timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
    optional = pe_offset + 24
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

sha256sum "$first" "$second"
printf '%s\n' 'Granite reproducible UEFI gate passed'
