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
"$root/scripts/verify-uefi-image.sh" "$first" "$second"

timestamped="$scratch/timestamped.efi"
debug_bearing="$scratch/debug-bearing.efi"
python3 - "$first" "$timestamped" "$debug_bearing" <<'PY'
import pathlib
import struct
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
pe_offset = struct.unpack_from("<I", source, 0x3C)[0]

timestamped = bytearray(source)
struct.pack_into("<I", timestamped, pe_offset + 8, 1)
pathlib.Path(sys.argv[2]).write_bytes(timestamped)

debug_bearing = bytearray(source)
optional = pe_offset + 24
struct.pack_into("<II", debug_bearing, optional + 112 + (6 * 8), 1, 1)
pathlib.Path(sys.argv[3]).write_bytes(debug_bearing)
PY

for invalid in "$timestamped" "$debug_bearing"; do
    if "$root/scripts/verify-uefi-image.sh" "$invalid" >/dev/null 2>&1; then
        echo "Granite metadata verifier accepted a mutated image" >&2
        exit 1
    fi
done

sha256sum "$first" "$second"
printf '%s\n' 'Granite reproducible UEFI gate passed'
