"""Builders of minimal Mach-O files, for testing code which symbolicates."""

import uuid
from typing import Any

from apple_symbols.macho import (
    LC_FILESET_ENTRY,
    LC_FUNCTION_STARTS,
    LC_SEGMENT_64,
    LC_SYMTAB,
    LC_UUID,
    MH_MAGIC_64,
    FilesetEntryCommand,
    LinkeditDataCommand,
    MachHeader64,
    Nlist64,
    SegmentCommand64,
    SymtabCommand,
    UuidCommand,
)

CPU_TYPE_ARM64 = 0x0100000C
MH_DYLIB = 6
MH_FILESET = 12
N_SECT_EXT = 0x0F
N_FUN = 0x24
VM_PROT_READ_EXECUTE = 5

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
        nlists += Nlist64(n_strx=len(strings), n_type=N_SECT_EXT, n_sect=1, n_desc=0, n_value=vmaddr + offset).build()
        strings += name.encode() + b"\x00"
    # A debugging (stab) entry, which is not a symbol of the image
    nlists += Nlist64(n_strx=0, n_type=N_FUN, n_sect=1, n_desc=0, n_value=vmaddr + 0x30).build()
    function_starts = b"".join(_uleb128(function - previous) for previous, function in zip([0, *functions], functions))
    function_starts += b"\x00"

    segments = [("__TEXT", vmaddr)]
    if text_exec:
        segments.append(("__TEXT_EXEC", vmaddr + text_exec))
    sizeofcmds = (
        SegmentCommand64.SIZE * len(segments) + UuidCommand.SIZE + SymtabCommand.SIZE + LinkeditDataCommand.SIZE
    )
    symoff = file_offset + MachHeader64.SIZE + sizeofcmds
    stroff = symoff + len(nlists)
    text, *others = (
        SegmentCommand64(
            cmd=LC_SEGMENT_64,
            cmdsize=SegmentCommand64.SIZE,
            segname=segname,
            vmaddr=segment_vmaddr,
            vmsize=vmsize,
            maxprot=VM_PROT_READ_EXECUTE,
            initprot=VM_PROT_READ_EXECUTE,
        ).build()
        for segname, segment_vmaddr in segments
    )
    commands = text
    commands += UuidCommand(cmd=LC_UUID, cmdsize=UuidCommand.SIZE, uuid=uuid.UUID(image_uuid)).build()
    commands += SymtabCommand(
        cmd=LC_SYMTAB,
        cmdsize=SymtabCommand.SIZE,
        symoff=symoff,
        nsyms=len(nlists) // Nlist64.SIZE,
        stroff=stroff,
        strsize=len(strings),
    ).build()
    commands += LinkeditDataCommand(
        cmd=LC_FUNCTION_STARTS,
        cmdsize=LinkeditDataCommand.SIZE,
        dataoff=stroff + len(strings),
        datasize=len(function_starts),
    ).build()
    commands += b"".join(others)
    header = MachHeader64(
        magic=MH_MAGIC_64,
        cputype=CPU_TYPE_ARM64,
        cpusubtype=2,
        filetype=MH_DYLIB,
        ncmds=4 + len(others),
        sizeofcmds=len(commands),
    ).build()
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
        commands += FilesetEntryCommand(
            cmd=LC_FILESET_ENTRY,
            cmdsize=FilesetEntryCommand.SIZE + len(entry_id),
            vmaddr=arguments["vmaddr"],
            fileoff=offset,
            entry_id_offset=FilesetEntryCommand.SIZE,
        ).build()
        commands += entry_id
    header = MachHeader64(
        magic=MH_MAGIC_64,
        cputype=CPU_TYPE_ARM64,
        cpusubtype=2,
        filetype=MH_FILESET,
        ncmds=len(entries),
        sizeofcmds=len(commands),
    ).build()
    data = header + commands
    for (_name, arguments), offset in zip(entries, offsets):
        macho = build_macho(**arguments, file_offset=offset)
        if len(macho) > FILESET_ENTRY_SPACING:
            raise ValueError(f"{_name} does not fit in a fileset entry")
        data = data.ljust(offset, b"\x00") + macho
    return data
