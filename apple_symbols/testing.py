"""Builders of minimal Mach-O files, for testing code which symbolicates."""

import struct
import uuid
from typing import Any

FILESET_ENTRY_SPACING = 0x1000


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def build_macho(
    image_uuid: str,
    vmaddr: int,
    vmsize: int,
    symbols: dict[str, int],
    functions: list[int],
    file_offset: int = 0,
    text_exec: int = 0,
) -> bytes:
    """
    Build a Mach-O holding just the load commands and tables which symbolication reads.

    :param file_offset: Where the Mach-O gets placed in its file, for one held by a fileset.
    :param text_exec: Offset of a `__TEXT_EXEC` segment to add, as kernel images have.
    """
    strings = b"\x00"
    nlists = b""
    for name, offset in symbols.items():
        nlists += struct.pack("<IBBHQ", len(strings), 0x0F, 1, 0, vmaddr + offset)
        strings += name.encode() + b"\x00"
    # A debugging (stab) entry, which is not a symbol of the image
    nlists += struct.pack("<IBBHQ", 0, 0x24, 1, 0, vmaddr + 0x30)
    function_starts = b"".join(_uleb128(function - previous) for previous, function in zip([0, *functions], functions))
    function_starts += b"\x00"

    sizeofcmds = 72 + 24 + 24 + 16 + (72 if text_exec else 0)
    symoff = file_offset + 32 + sizeofcmds
    stroff = symoff + len(nlists)
    function_starts_offset = stroff + len(strings)
    commands = struct.pack("<2I16s4Q4I", 0x19, 72, b"__TEXT", vmaddr, vmsize, 0, 0, 5, 5, 0, 0)
    commands += struct.pack("<2I", 0x1B, 24) + uuid.UUID(image_uuid).bytes
    commands += struct.pack("<6I", 0x2, 24, symoff, len(nlists) // 16, stroff, len(strings))
    commands += struct.pack("<4I", 0x26, 16, function_starts_offset, len(function_starts))
    if text_exec:
        commands += struct.pack("<2I16s4Q4I", 0x19, 72, b"__TEXT_EXEC", vmaddr + text_exec, vmsize, 0, 0, 5, 5, 0, 0)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 6, 4 + bool(text_exec), len(commands), 0, 0)
    return header + commands + nlists + strings + function_starts


def build_fileset(entries: list[tuple[str, dict[str, Any]]]) -> bytes:
    """
    Build a fileset, which is what a kernelcache is.

    :param entries: Name of every Mach-O it holds and the arguments :func:`build_macho` takes to
        build it, apart from `file_offset`. Each has to fit in `FILESET_ENTRY_SPACING` bytes.
    """
    offsets = [FILESET_ENTRY_SPACING * (index + 1) for index in range(len(entries))]
    commands = b""
    for (name, arguments), offset in zip(entries, offsets):
        entry_id = name.encode() + b"\x00"
        entry_id += b"\x00" * (-len(entry_id) % 8)
        commands += struct.pack("<2I2Q2I", 0x80000035, 24 + 8 + len(entry_id), arguments["vmaddr"], offset, 32, 0)
        commands += entry_id
    data = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 12, len(entries), len(commands), 0, 0) + commands
    for (_name, arguments), offset in zip(entries, offsets):
        macho = build_macho(**arguments, file_offset=offset)
        if len(macho) > FILESET_ENTRY_SPACING:
            raise ValueError(f"{_name} does not fit in a fileset entry")
        data = data.ljust(offset, b"\x00") + macho
    return data
