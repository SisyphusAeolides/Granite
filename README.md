# Granite

Granite is the measured UEFI bootloader for Arach OS. It admits only bounded
ELF load plans whose Arach Kernel, Push, and Crest bytes match independently
supplied SHA-256 manifests, then constructs the exact firmware handoff consumed
by Arach Kernel.

Image assembly supplies artifacts through `ARACH_ARTIFACT_DIR` or the explicit
`ARACH_KERNEL_IMAGE`, `ARACH_PUSH_IMAGE`, and `ARACH_CREST_IMAGE` variables.
Missing or empty artifacts produce an all-zero build manifest and the UEFI
loader fails closed. Production builds should enable the `require-artifacts`
feature; that turns a missing or empty input into a build error instead of
producing an EFI that cannot boot.

The UEFI target fixes the PE timestamp at zero and suppresses the CodeView
record whose generated signature otherwise varies between output directories.
The reproducibility gate performs two independent production builds, requires
byte-identical images, and parses both PE headers to reject either metadata
field if it reappears. `scripts/verify-uefi-image.sh` applies the same strict
PE32+ metadata contract to artifacts assembled by downstream repositories.

Rust implements artifact admission and the UEFI handoff. Fortran exposes
readiness telemetry that cannot override digest checks. Idris 2 makes complete
bundle assembly total, and Agda restricts firmware exit to a handoff carrying
all three verification witnesses.

## Validation

```sh
cargo fmt --all -- --check
cargo test --features fortran-policy
scripts/check-reproducible-uefi.sh
scripts/verify-uefi-image.sh target/x86_64-unknown-uefi/release/granite.efi
scripts/check-formal-models.sh

# Production UEFI build (requires all three image variables above)
cargo build --release --target x86_64-unknown-uefi \
  --features uefi-bin,require-artifacts
```
