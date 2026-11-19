"""The little of the Mach-O format which symbolication needs: load commands, symbol table, function starts."""

import struct
import uuid
from dataclasses import dataclass, field
from typing import BinaryIO, Optional

MH_MAGIC_64 = 0xFEEDFACF
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_FUNCTION_STARTS = 0x26
LC_FILESET_ENTRY = 0x80000035

N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E

MACH_HEADER_64 = struct.Struct("<8I")
LOAD_COMMAND = struct.Struct("<2I")
SEGMENT_COMMAND_64 = struct.Struct("<16s4Q")
SYMTAB_COMMAND = struct.Struct("<4I")
LINKEDIT_DATA_COMMAND = struct.Struct("<2I")
FILESET_ENTRY_COMMAND = struct.Struct("<2QI")
NLIST_64 = struct.Struct("<IBBHQ")

# Longest symbol name read from the string table; Swift manglings go well past the usual C lengths
MAX_SYMBOL_LENGTH = 4096


@dataclass
class MachO:
    """The load commands of a Mach-O which symbolication needs."""

    uuid: Optional[str] = None
    # `__TEXT`
    vmaddr: Optional[int] = None
    vmsize: int = 0
    text_exec_vmaddr: Optional[int] = None
    symoff: int = 0
    nsyms: int = 0
    stroff: int = 0
    function_starts_offset: int = 0
    function_starts_size: int = 0
    # Name and file offset of the Mach-O files a fileset (a kernelcache) holds
    fileset_entries: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])


def parse_macho(fd: BinaryIO, offset: int = 0) -> Optional[MachO]:
    """
    Parse the load commands of a thin 64-bit little-endian Mach-O, or `None` for anything else.

    :param offset: Where the Mach-O starts in the file, for one held by a fileset.
    """
    fd.seek(offset)
    header = fd.read(MACH_HEADER_64.size)
    if len(header) < MACH_HEADER_64.size:
        return None
    magic, _cputype, _cpusubtype, _filetype, ncmds, sizeofcmds, _flags, _reserved = MACH_HEADER_64.unpack(header)
    if magic != MH_MAGIC_64:
        return None
    commands = fd.read(sizeofcmds)
    macho = MachO()
    offset = 0
    for _ in range(ncmds):
        if offset + LOAD_COMMAND.size > len(commands):
            return None
        cmd, cmdsize = LOAD_COMMAND.unpack_from(commands, offset)
        if cmdsize < LOAD_COMMAND.size:
            return None
        body = offset + LOAD_COMMAND.size
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, _fileoff, _filesize = SEGMENT_COMMAND_64.unpack_from(commands, body)
            if segname.rstrip(b"\x00") == b"__TEXT":
                macho.vmaddr = vmaddr
                macho.vmsize = vmsize
            elif segname.rstrip(b"\x00") == b"__TEXT_EXEC":
                macho.text_exec_vmaddr = vmaddr
        elif cmd == LC_UUID:
            macho.uuid = str(uuid.UUID(bytes=commands[body : body + 16]))
        elif cmd == LC_SYMTAB:
            macho.symoff, macho.nsyms, macho.stroff, _strsize = SYMTAB_COMMAND.unpack_from(commands, body)
        elif cmd == LC_FUNCTION_STARTS:
            macho.function_starts_offset, macho.function_starts_size = LINKEDIT_DATA_COMMAND.unpack_from(commands, body)
        elif cmd == LC_FILESET_ENTRY:
            _vmaddr, fileoff, entry_id_offset = FILESET_ENTRY_COMMAND.unpack_from(commands, body)
            entry_id = commands[offset + entry_id_offset : offset + cmdsize].split(b"\x00", 1)[0]
            macho.fileset_entries.append((entry_id.decode(errors="replace"), fileoff))
        offset += cmdsize
    return macho


def read_symbols(fd: BinaryIO, macho: MachO, start: int, end: int) -> list[tuple[int, int]]:
    """Get the address and string table offset of every symbol of `macho` within [start, end), sorted."""
    fd.seek(macho.symoff)
    data = fd.read(macho.nsyms * NLIST_64.size)
    data = data[: len(data) - len(data) % NLIST_64.size]
    return sorted(
        (n_value, n_strx)
        for n_strx, n_type, _n_sect, _n_desc, n_value in NLIST_64.iter_unpack(data)
        if not n_type & N_STAB and n_type & N_TYPE == N_SECT and start <= n_value < end
    )


def read_symbol_name(fd: BinaryIO, offset: int) -> str:
    """Read the symbol name at the given file offset of a string table."""
    fd.seek(offset)
    name = fd.read(MAX_SYMBOL_LENGTH).split(b"\x00", 1)[0].decode(errors="replace")
    # C symbols carry a leading underscore in the symbol table
    return name[1:] if name.startswith("_") else name


def parse_function_starts(data: bytes, base: int) -> list[int]:
    """Decode `LC_FUNCTION_STARTS`: ULEB128 deltas between consecutive functions, starting at `__TEXT`."""
    starts: list[int] = []
    address = base
    delta = 0
    shift = 0
    for byte in data:
        delta |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
            continue
        if delta == 0:
            break
        address += delta
        starts.append(address)
        delta = 0
        shift = 0
    return starts
