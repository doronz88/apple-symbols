"""The little of the Mach-O format which symbolication needs: load commands, symbol table, function starts."""

import struct
from dataclasses import dataclass, field
from typing import Annotated, BinaryIO, Optional

from bytestruct import BinaryStruct, ByteReader, PaddedString, TruncatedDataError, u8, u16, u32, u64, uuid_t

MH_MAGIC_64 = 0xFEEDFACF
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_FUNCTION_STARTS = 0x26
LC_FILESET_ENTRY = 0x80000035

N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E


@dataclass
class MachHeader64(BinaryStruct, byte_order="<"):
    magic: u32
    cputype: u32
    cpusubtype: u32
    filetype: u32
    ncmds: u32
    sizeofcmds: u32
    flags: u32 = 0
    reserved: u32 = 0


@dataclass
class LoadCommand(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32


@dataclass
class SegmentCommand64(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32
    segname: Annotated[str, PaddedString(16, errors="replace")]
    vmaddr: u64
    vmsize: u64
    fileoff: u64 = 0
    filesize: u64 = 0
    maxprot: u32 = 0
    initprot: u32 = 0
    nsects: u32 = 0
    flags: u32 = 0


@dataclass
class Section64(BinaryStruct, byte_order="<"):
    sectname: Annotated[str, PaddedString(16, errors="replace")]
    segname: Annotated[str, PaddedString(16, errors="replace")]
    addr: u64
    size: u64
    offset: u32 = 0
    align: u32 = 0
    reloff: u32 = 0
    nreloc: u32 = 0
    flags: u32 = 0
    reserved1: u32 = 0
    reserved2: u32 = 0
    reserved3: u32 = 0


@dataclass
class UuidCommand(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32
    uuid: uuid_t


@dataclass
class SymtabCommand(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32
    symoff: u32
    nsyms: u32
    stroff: u32
    strsize: u32


@dataclass
class LinkeditDataCommand(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32
    dataoff: u32
    datasize: u32


@dataclass
class FilesetEntryCommand(BinaryStruct, byte_order="<"):
    cmd: u32
    cmdsize: u32
    vmaddr: u64
    fileoff: u64
    entry_id_offset: u32
    reserved: u32 = 0


@dataclass
class Nlist64(BinaryStruct, byte_order="<"):
    n_strx: u32
    n_type: u8
    n_sect: u8
    n_desc: u16
    n_value: u64


# The layout of `Nlist64`, for unpacking a whole symbol table at once without a record per symbol
NLIST_64 = struct.Struct("<IBBHQ")

# Longest symbol name read from the string table; Swift manglings go well past the usual C lengths
MAX_SYMBOL_LENGTH = 4096


@dataclass(frozen=True)
class Segment:
    """Where a segment is mapped and where the file keeps it."""

    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


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
    segments: list[Segment] = field(default_factory=list[Segment])
    # Address and size of the Objective-C metadata sections, by name
    objc_sections: dict[str, tuple[int, int]] = field(default_factory=dict[str, tuple[int, int]])
    # Name and file offset of the Mach-O files a fileset (a kernelcache) holds
    fileset_entries: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])


def parse_macho(fd: BinaryIO, offset: int = 0) -> Optional[MachO]:
    """
    Parse the load commands of a thin 64-bit little-endian Mach-O, or `None` for anything else.

    :param offset: Where the Mach-O starts in the file, for one held by a fileset.
    """
    fd.seek(offset)
    try:
        header = MachHeader64.parse(fd.read(MachHeader64.SIZE))
        if header.magic != MH_MAGIC_64:
            return None
        return _parse_load_commands(ByteReader(fd.read(header.sizeofcmds)), header.ncmds)
    except TruncatedDataError:
        return None


def _parse_load_commands(commands: ByteReader, ncmds: int) -> Optional[MachO]:
    macho = MachO()
    for _ in range(ncmds):
        start = commands.offset
        load_command = LoadCommand.read(commands)
        if load_command.cmdsize < LoadCommand.SIZE:
            return None
        commands.offset = start
        command = commands.sub(load_command.cmdsize)
        if load_command.cmd == LC_SEGMENT_64:
            segment = SegmentCommand64.read(command)
            macho.segments.append(
                Segment(segment.segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize)
            )
            for _ in range(segment.nsects):
                if command.remaining < Section64.SIZE:
                    break
                section = Section64.read(command)
                if section.sectname.startswith("__objc_"):
                    macho.objc_sections[section.sectname] = (section.addr, section.size)
            if segment.segname == "__TEXT":
                macho.vmaddr = segment.vmaddr
                macho.vmsize = segment.vmsize
            elif segment.segname == "__TEXT_EXEC":
                macho.text_exec_vmaddr = segment.vmaddr
        elif load_command.cmd == LC_UUID:
            macho.uuid = str(UuidCommand.read(command).uuid)
        elif load_command.cmd == LC_SYMTAB:
            symtab = SymtabCommand.read(command)
            macho.symoff = symtab.symoff
            macho.nsyms = symtab.nsyms
            macho.stroff = symtab.stroff
        elif load_command.cmd == LC_FUNCTION_STARTS:
            function_starts = LinkeditDataCommand.read(command)
            macho.function_starts_offset = function_starts.dataoff
            macho.function_starts_size = function_starts.datasize
        elif load_command.cmd == LC_FILESET_ENTRY:
            entry = FilesetEntryCommand.read(command)
            entry_id = command.data[start + entry.entry_id_offset : command.end].split(b"\x00", 1)[0]
            macho.fileset_entries.append((entry_id.decode(errors="replace"), entry.fileoff))
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
