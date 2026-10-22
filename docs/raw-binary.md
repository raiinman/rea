# Headerless raw-binary analysis with Ghidra

The `mipsel` extension described here is in the raiinman fork. Use a build of
this fork containing the change; installing the upstream npm release or only
updating the skill does not add this architecture to an older server.

REA admits a headerless executable when the caller supplies the CPU family and
the address where file offset 0 should be mapped. That interpretation is not
inferred from a `.bin` suffix or from unrecognized bytes.

## Open and inspect

```bash
rea inspect /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea function /absolute/path/to/ecu.bin 0x8000000 --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/absolute/path/to/ecu.bin",
    "format": "raw-binary",
    "architecture": "arm",
    "entry_point": "0x8000000",
    "provider_id": "ghidra"
  }
}
```

`architecture` is one of `x86`, `x86_64`, `arm`, `arm64`, `6502`, `m68k`, or `mipsel`. `entry_point` is a
hexadecimal address of the form `0x…`. The complete file is mapped starting at
that address, and Ghidra seeds an `entry` function there before auto-analysis.
ARM, AArch64 and mipsel entries must be 4-byte aligned; m68k entries must be 2-byte
aligned; x86 and 6502 entries may be byte-aligned.
For 6502, the entry and complete mapped file must fit within `0x0000..0xffff`;
images that cross the 16-bit boundary are rejected before provider startup.
For m68k and mipsel, the mapping must fit within `0x0..0xffffffff`.
`open_binary` and an open `binary_session` return the canonical `entry_point`
for raw targets so callers can verify the selected mapping directly.
Omitted `format` keeps header-based detection; architecture and entry without
`format=raw-binary` are rejected.

Ghidra imports a private snapshot with `BinaryLoader` and these generic
languages and compiler specifications. Each family has one fixed byte order:
m68k is big-endian and the others are little-endian.

| architecture | language_id           | compiler_spec_id |
| ------------ | --------------------- | ---------------- |
| x86          | `x86:LE:32:default`   | `gcc`            |
| x86_64       | `x86:LE:64:default`   | `gcc`            |
| arm          | `ARM:LE:32:v7`        | `default`        |
| arm64        | `AARCH64:LE:64:v8A`   | `default`        |
| 6502         | `6502:LE:16:default`  | `default`        |
| m68k         | `68000:BE:32:default` | `default`        |
| mipsel       | `MIPS:LE:32:default`  | `default`        |

Compiler specifications select analysis conventions; they do not identify the
original compiler or ABI of a headerless target. Ghidra's x86 languages do not
provide a compiler specification named `default`.

Those settings, the caller-supplied entry, and `language_selection:
caller-supplied-v1` are committed in the analysis profile. A different entry
or architecture is a different profile; snapshots from header-detected targets
do not replay.

The mapped start is independent of Ghidra's program image base, which remains
`0x0` for BinaryLoader. Ghidra may report additional language-defined entry
points, including unmapped ARM vectors. Load-image verification requires the
caller-supplied entry and preserves those other entries as observations.
For 6502, BinaryLoader maps the file before adding its language-defined zero-page
and stack blocks. Conflicting default blocks are skipped; low-address files stay
in the default address space rather than an overlay. Non-conflicting uninitialized
blocks remain observations, not file-backed bytes.
Independent raw verification streams the complete private snapshot digest and
extent with bounded memory and supports cancellation during the read.
It also requires the source-backed block to be initialized, loaded, and
non-overlay in the bound language's default address space. Contradictory mapping
observations are retained with `mismatch`, even when the source hashes agree.

Hopper and IDA refuse raw-binary targets. Windows Ghidra P0 admits native PE
applications/DLLs and explicitly selected raw 6502 and mipsel images. Other raw CPU families
remain outside the Windows boundary. Native path admission, private DACLs, Job
Object ownership, immutable snapshots, and the no-mutation policy still apply.

## NMOS 6502

```bash
rea function /absolute/path/to/image.bin 0x8001 --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
```

Select only headerless NMOS 6502 code with a known entry at file offset 0.
The built-in Ghidra processor supplies static instructions, functions,
pseudocode, and references. Evidence preserves `architecture: "6502"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret iNES headers, cartridge mappers, bank switching,
or other console-specific memory layouts. 65C02 and 65816 programs need different
processor semantics and are not admitted as those variants. REA does not infer
the CPU from the file suffix, guess the reset vector, or emulate the target.

`npm run verify:ghidra:6502` assembles and links the source-owned fixture with
`ca65` and `ld65` (tested from cc65 tag `V2.19`, whose tools report `V2.18`).
Set `REA_CA65` and `REA_LD65` to explicit executable paths if needed. The lane
checks real CLI/MCP load-image parity, mapped bytes, decoded calls, decompilation,
invalid mappings, unchanged source bytes and runtime cleanup.
Low-memory checks include a file spanning the zero-page/stack boundary at `0xff`
and a complete 64-KiB image at `0x0`, with verified default-space mappings through
both CLI and MCP. On Windows, the lane also checks that a caller-selected
junction path is rejected at snapshot admission through CLI and MCP, with
unchanged source bytes and complete runtime cleanup. Windows requires the
matching native addon; the POSIX provider path has not been exercised by the
Windows run.

## Motorola 68000

```bash
rea function /absolute/path/to/image.bin 0x1000 --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
```

Select only headerless big-endian 68000-family code with a known, even entry at
file offset 0. Ghidra's `68000:BE:32:default` language decodes the 68040
superset in the 32-bit `ram` address space. Instructions that a real MC68000
would not execute are therefore not rejected, and 68020, 68030, CPU32, and
ColdFire programs are not admitted as those variants. Addresses are not masked
to the MC68000 24-bit bus. Evidence preserves `architecture: "m68k"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret Amiga hunks, Atari ST, or other container headers,
cartridge or console memory maps, or bank switching. REA does not read the
initial stack pointer and reset vector from the first eight bytes; select the
entry explicitly. Windows Ghidra P0 does not admit m68k.

`npm run verify:ghidra:m68k` uses a source-owned 22-byte fixture written as
annotated hex in the verifier, so it needs no assembler. The lane checks real
CLI/MCP load-image parity, mapped bytes, a decoded call, decompilation by address
and file offset, misaligned and out-of-range mappings, unchanged source bytes and
runtime cleanup. It has been run with Ghidra 12.1.4 on macOS; Linux has not been
exercised.

## Little-endian MIPS BIOS images

The fork's `mipsel` selection is a headerless, little-endian 32-bit MIPS
interpretation, distinct from header-detected `mips` ELF support. It uses
Ghidra's generic `MIPS:LE:32:default` instruction superset and default compiler
specification. It does not prove MIPS-I or PlayStation R3000A conformance,
recover the original ABI, or reject every instruction unavailable on that CPU.
Big-endian raw MIPS, MIPS16, microMIPS and Allegrex are not selected by this lane.

For a caller-identified PS1 boot ROM whose reset entry is at file offset zero,
map the image at `0xbfc00000`:

```powershell
rea function "C:\images\ps1-bios.bin" 0xbfc00000 --target-format raw-binary --architecture mipsel --entry-point 0xbfc00000 --provider ghidra --json
rea inspect-native-load-image "C:\images\ps1-bios.bin" --target-format raw-binary --architecture mipsel --entry-point 0xbfc00000 --provider ghidra --json
```

The equivalent MCP open is:

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "C:/images/ps1-bios.bin",
    "format": "raw-binary",
    "architecture": "mipsel",
    "entry_point": "0xbfc00000",
    "provider_id": "ghidra"
  }
}
```

Inspect the returned load-image checks before relying on addresses. File offset
zero and the initial function entry share the caller-selected address; there
is no independent load-base/reset-entry setting. Physical, cached and uncached
ROM aliases are not created. RAM, scratchpad, MMIO, DMA, GPU, SPU, CD-ROM and
COP2/GTE behavior are not modeled. Code copied to RAM or reached through another
alias may remain unresolved. Static instruction and pseudocode results do not
establish execution, exact load/branch delay behavior, or boot completion.
Original BIOS bytes remain unchanged; do not commit private BIOS images or
provider project files as fixtures.

A source-build MCP verification on Windows x64 with Ghidra 12.1.4,
JDK 21.0.12.1 and Node.js 24.18 opened a caller-supplied 512-KiB PS1 BIOS
at `0xbfc00000`. Its complete raw mapping passed independent verification;
the first 64 mapped bytes matched the source, the first instruction decoded
as `LUI`, and address `0xbfc00030` mapped to file offset 48. Reset-entry
decompilation returned 2,655 characters; inventory reported 328 functions and
106 defined strings. The original digest remained unchanged, and closing the
session left no pending runtime and an empty private runtime directory.
The completed workflow took about 172 seconds including cold startup and
concurrent test contention; this is a single observation, not a performance
comparison. It establishes this source-build MCP workflow, not installed-package
verification, complete BIOS reconstruction or runtime semantic equivalence.

Debian MIPS disk images are unnecessary for this static workflow. The
[Debian QEMU image archive](https://people.debian.org/~aurel32/qemu/mips/)
contains old Linux/Malta images, and the
[QEMU MIPS system guide](https://www.qemu.org/docs/master/system/target-mips.html)
describes boards such as Malta, Pica and Magnum. Those board/device models do
not supply a PS1 machine model or establish BIOS runtime behavior.

## Limitations

- Headers are not discovered from file bytes. This increment does not guess
  load addresses, vector tables, or memory maps.
- Big-endian ARM, Thumb-only, Cortex-M, and other Ghidra processor variants are
  unsupported. m68k is the only big-endian family.
- Reset vectors, memory-mapped I/O, and firmware boot sequences are not
  emulated.
- Independent load-image verification covers source identity, mapped file
  bytes, the bound language, and the caller-supplied entry. Original bytes
  stay unchanged.
