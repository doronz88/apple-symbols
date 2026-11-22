import io
import json
import struct
import uuid
from pathlib import Path
from typing import Any, Callable

import pytest

from apple_symbols import (
    DeviceSupportSymbols,
    KernelSymbols,
    device_support,
    find_device_support_symbols,
    get_device_support_path,
    kernel,
)
from apple_symbols.macho import (
    LC_FUNCTION_STARTS,
    LC_SEGMENT_64,
    LC_SYMTAB,
    LC_UUID,
    MH_MAGIC_64,
    NLIST_64,
    LinkeditDataCommand,
    MachHeader64,
    Nlist64,
    Section64,
    SegmentCommand64,
    SymtabCommand,
    UuidCommand,
    parse_macho,
)
from apple_symbols.testing import build_fileset, build_macho

SHARED_CACHE_BASE = 0x180000000
KERNEL_UUID = "12121212-3434-5656-7878-909090909090"
KEXT_UUID = "abababab-cdcd-efef-0101-232323232323"
KERNEL_VMADDR = 0xFFFFFE0007004000
KEXT_VMADDR = 0xFFFFFE0007100000
# Offset of `__TEXT_EXEC` from `__TEXT` in the kernel images
TEXT_EXEC = 0x4000
LIBFOO_UUID = "11111111-2222-3333-4444-555555555555"
LIBFOO_VMADDR = SHARED_CACHE_BASE + 0x10000
DYLD_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APP_UUID = "99999999-8888-7777-6666-555555555555"
DRIVERKIT_UUID = "d0d0d0d0-1111-2222-3333-444444444444"


@pytest.fixture
def symbols_root(tmp_path: Path) -> Path:
    root = tmp_path / "Symbols"
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libfoo.dylib").write_bytes(
        build_macho(LIBFOO_UUID, LIBFOO_VMADDR, 0x1000, {"_foo": 0x100, "_bar": 0x200}, [0x100, 0x200, 0x300])
    )
    (root / "usr/lib/dyld").write_bytes(build_macho(DYLD_UUID, 0, 0x1000, {"_start": 0x40}, [0x40]))
    (root / "usr/lib/not-a-macho").write_bytes(b"dyld_v1  arm64e\x00" * 4)
    return root


@pytest.fixture
def symbols(symbols_root: Path, tmp_path: Path) -> DeviceSupportSymbols:
    return DeviceSupportSymbols.load(symbols_root, tmp_path / "index")


@pytest.fixture
def kernelcache(tmp_path: Path) -> Path:
    file = tmp_path / "kernelcache.decompressed"
    file.write_bytes(
        build_fileset([
            (
                "com.apple.kernel",
                {
                    "image_uuid": KERNEL_UUID,
                    "vmaddr": KERNEL_VMADDR,
                    "vmsize": 0x10000,
                    "symbols": {"_thread_block": TEXT_EXEC + 0x100, "_vm_pageout_continue": TEXT_EXEC + 0x200},
                    "functions": [TEXT_EXEC + 0x100, TEXT_EXEC + 0x200, TEXT_EXEC + 0x300],
                    "text_exec": TEXT_EXEC,
                },
            ),
            (
                "com.apple.driver.Foo",
                {
                    "image_uuid": KEXT_UUID,
                    "vmaddr": KEXT_VMADDR,
                    "vmsize": 0x10000,
                    "symbols": {},
                    "functions": [TEXT_EXEC + 0x100],
                    "text_exec": TEXT_EXEC,
                },
            ),
        ])
    )
    return file


def test_symbols_index_lists_the_images(symbols: DeviceSupportSymbols) -> None:
    assert [(image.path, image.uuid, image.vmaddr) for image in symbols.images] == [
        ("/usr/lib/dyld", DYLD_UUID, 0),
        ("/usr/lib/libfoo.dylib", LIBFOO_UUID, LIBFOO_VMADDR),
    ]
    assert symbols.has_shared_cache_images
    image = symbols.image_by_address(LIBFOO_VMADDR + 0x123)
    assert image is not None
    assert image.name == "libfoo.dylib"
    assert symbols.image_by_address(LIBFOO_VMADDR + 0x1000) is None
    assert symbols.image_by_uuid(LIBFOO_UUID.upper()) is image


def test_symbols_index_is_reused_until_the_tree_changes(
    symbols_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index_dir = tmp_path / "index"
    scans: list[Path] = []
    scan = device_support._scan

    def counting_scan(root: Path) -> Any:
        scans.append(root)
        return scan(root)

    monkeypatch.setattr(device_support, "_scan", counting_scan)
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 2
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 2
    assert len(scans) == 1

    # Splitting a shared cache fills directories which already exist
    (symbols_root / "usr/lib/libbar.dylib").write_bytes(build_macho(APP_UUID, LIBFOO_VMADDR + 0x1000, 0x1000, {}, []))
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 3
    assert len(scans) == 2


def test_symbolicate(symbols: DeviceSupportSymbols) -> None:
    image = symbols.image_by_uuid(LIBFOO_UUID)
    assert image is not None
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x100) == ("foo", 0)
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x1FC) == ("foo", 0xFC)
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x210) == ("bar", 0x10)
    # Before the first symbol
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x80) is None
    # In the function at 0x300, which has no symbol: must not be attributed to `bar`
    assert symbols.symbolicate(image, LIBFOO_VMADDR + 0x310) is None


def test_kernel_symbols_of_a_kernelcache(kernelcache: Path, tmp_path: Path) -> None:
    kernel_symbols = KernelSymbols.load(kernelcache, index_dir=tmp_path / "index")

    assert [(image.name, image.uuid, image.text_exec) for image in kernel_symbols.images] == [
        ("com.apple.kernel", KERNEL_UUID, KERNEL_VMADDR + TEXT_EXEC),
        ("com.apple.driver.Foo", KEXT_UUID, KEXT_VMADDR + TEXT_EXEC),
    ]
    assert kernel_symbols.has_symbols
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x1FC) == ("thread_block", 0xFC)
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x200) == ("vm_pageout_continue", 0)
    # In functions which have no symbol: must not be attributed to the symbol before them
    assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x310) is None
    assert kernel_symbols.symbolicate(KEXT_VMADDR + TEXT_EXEC + 0x110) is None


def test_kernel_symbols_come_from_signatures_and_are_kept(
    kernelcache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compressed = tmp_path / "kernelcache.release.iphone17"
    compressed.write_bytes(b"IM4P" + kernelcache.read_bytes())
    signatures = tmp_path / "signatures"
    signatures.mkdir()
    commands: list[list[str]] = []

    def run(*argv: Any) -> str:
        commands.append([str(arg) for arg in argv[:3]])
        output = Path(argv[argv.index("--output") + 1])
        output.mkdir(parents=True)
        if argv[2] == "dec":
            (output / "kernelcache.release.iphone17.decompressed").write_bytes(kernelcache.read_bytes())
        else:
            assert Path(argv[argv.index("--signatures") + 1]) == signatures.resolve()
            (output / "kernelcache.symbols.json").write_text(
                json.dumps({str(KEXT_VMADDR + TEXT_EXEC + 0x100): "Foo::start(IOService*)"})
            )
        return ""

    monkeypatch.setattr(kernel, "run", run)
    index_dir = tmp_path / "index"

    for _ in range(2):
        kernel_symbols = KernelSymbols.load(compressed, signatures, index_dir)
        assert kernel_symbols.symbolicate(KEXT_VMADDR + TEXT_EXEC + 0x110) == ("Foo::start(IOService*)", 0x10)
        assert kernel_symbols.symbolicate(KERNEL_VMADDR + TEXT_EXEC + 0x1FC) == ("thread_block", 0xFC)
    assert commands == [["ipsw", "kernel", "dec"], ["ipsw", "kernel", "symbolicate"]]

    # New signatures may name more functions
    (signatures / "27.0").mkdir()
    KernelSymbols.load(compressed, signatures, index_dir)
    assert len(commands) == 4


def test_shared_cache_base(symbols: DeviceSupportSymbols, tmp_path: Path) -> None:
    assert symbols.shared_cache_base == SHARED_CACHE_BASE

    root = tmp_path / "empty"
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/dyld").write_bytes(build_macho(DYLD_UUID, 0, 0x1000, {}, []))
    assert DeviceSupportSymbols.load(root, tmp_path / "index").shared_cache_base is None


def test_find_device_support_symbols(tmp_path: Path) -> None:
    assert get_device_support_path("iPhone17,3", "26.4", "23E246", tmp_path).name == "iPhone17,3 26.4 (23E246)"
    assert find_device_support_symbols("iPhone17,3", "23E246", root=tmp_path / "missing") is None

    # A directory whose download has not been finalized holds no `Symbols` yet
    (tmp_path / "iPhone17,3 26.4 (23E247)" / "arm64e").mkdir(parents=True)
    symbols = tmp_path / "iPhone17,3 26.4 (23E246)" / "Symbols"
    symbols.mkdir(parents=True)
    (tmp_path / "iPhone18,4 26.4 (23E246)" / "Symbols").mkdir(parents=True)

    assert find_device_support_symbols("iPhone17,3", "23E246", root=tmp_path) == symbols
    assert find_device_support_symbols("iPhone17,3", "23E246", "26.4", root=tmp_path) == symbols
    assert find_device_support_symbols("iPhone17,3", "23E246", "26.5", root=tmp_path) is None
    assert find_device_support_symbols("iPhone17,3", "23E247", root=tmp_path) is None
    assert find_device_support_symbols("iPhone17", "23E246", root=tmp_path) is None


def test_parse_macho_truncated_is_not_a_macho() -> None:
    data = build_macho(LIBFOO_UUID, 0x180000000, 0x4000, {"_function": 0x10}, [0x10])
    for size in (0, 16, MachHeader64.SIZE, MachHeader64.SIZE + 4, MachHeader64.SIZE + 40):
        assert parse_macho(io.BytesIO(data[:size])) is None


def test_nlist_layouts_agree() -> None:
    entry = Nlist64(n_strx=1, n_type=0x0F, n_sect=1, n_desc=0, n_value=0x180000010)
    assert NLIST_64.unpack(entry.build()) == (1, 0x0F, 1, 0, 0x180000010)


LIBOBJC_UUID = "0b0b0b0b-1111-2222-3333-444444444444"
LIBEXT_UUID = "e0e0e0e0-1111-2222-3333-444444444444"
OBJC_TEXT = SHARED_CACHE_BASE + 0x10000
OBJC_DATA = SHARED_CACHE_BASE + 0x110000
LIBEXT_DATA = SHARED_CACHE_BASE + 0x120000
LIBOBJC_TEXT = SHARED_CACHE_BASE + 0x20000
LIBOBJC_DATA = SHARED_CACHE_BASE + 0x130000
LIBOBJC_STRINGS = SHARED_CACHE_BASE + 0x200000


def _encode_cache_offset(address: int, authenticated: bool = False) -> int:
    """Encode a pointer the way the caches keeping offsets from their base do, as a link of a chain."""
    if not address:
        return 0
    raw = (address - SHARED_CACHE_BASE) | (3 << 52)
    return raw | (1 << 63) | (0xBEEF << 34) if authenticated else raw


def _encode_address(address: int, authenticated: bool = False) -> int:
    """Encode a pointer the way the caches keeping whole addresses do, as a link of a chain."""
    if not address:
        return 0
    if authenticated:
        return (1 << 63) | (0xBEEF << 32) | (address - SHARED_CACHE_BASE) | (3 << 51)
    return address | (3 << 51)


class _Segment:
    """Contents of a segment being laid out, handing out the address of whatever gets added."""

    def __init__(self, name: str, vmaddr: int, size: int = 0) -> None:
        self.name = name
        self.vmaddr = vmaddr
        self.data = bytearray(size)
        self.sections: dict[str, tuple[int, int]] = {}

    def add(self, data: bytes, section: str = "") -> int:
        self.data += b"\x00" * (-len(self.data) % 8)
        address = self.vmaddr + len(self.data)
        self.data += data
        if section:
            self.sections[section] = (address, len(data))
        return address

    def string(self, value: str) -> int:
        return self.add(value.encode() + b"\x00")


def _build_image(image_uuid: str, segments: list[_Segment], functions: list[int], symbols: dict[str, int]) -> bytes:
    """Build an image of a shared cache: `segments` (`__TEXT` first) followed by what :func:`build_macho` holds."""
    text = segments[0]
    commands_size = sum(SegmentCommand64.SIZE + Section64.SIZE * len(segment.sections) for segment in segments)
    commands_size += UuidCommand.SIZE + SymtabCommand.SIZE + LinkeditDataCommand.SIZE
    offset = MachHeader64.SIZE + commands_size
    commands = b""
    contents = b""
    for segment in segments:
        commands += SegmentCommand64(
            cmd=LC_SEGMENT_64,
            cmdsize=SegmentCommand64.SIZE + Section64.SIZE * len(segment.sections),
            segname=segment.name,
            vmaddr=segment.vmaddr,
            vmsize=len(segment.data),
            fileoff=offset + len(contents),
            filesize=len(segment.data),
            nsects=len(segment.sections),
        ).build()
        for sectname, (address, size) in segment.sections.items():
            commands += Section64(sectname=sectname, segname=segment.name, addr=address, size=size).build()
        contents += bytes(segment.data)
    strings = b"\x00"
    nlists = b""
    for name, symbol_offset in symbols.items():
        nlists += Nlist64(
            n_strx=len(strings), n_type=0x0F, n_sect=1, n_desc=0, n_value=text.vmaddr + symbol_offset
        ).build()
        strings += name.encode() + b"\x00"
    function_starts = bytes(function - previous for previous, function in zip([0, *functions], functions)) + b"\x00"
    symoff = offset + len(contents)
    commands += UuidCommand(cmd=LC_UUID, cmdsize=UuidCommand.SIZE, uuid=uuid.UUID(image_uuid)).build()
    commands += SymtabCommand(
        cmd=LC_SYMTAB,
        cmdsize=SymtabCommand.SIZE,
        symoff=symoff,
        nsyms=len(nlists) // Nlist64.SIZE,
        stroff=symoff + len(nlists),
        strsize=len(strings),
    ).build()
    commands += LinkeditDataCommand(
        cmd=LC_FUNCTION_STARTS,
        cmdsize=LinkeditDataCommand.SIZE,
        dataoff=symoff + len(nlists) + len(strings),
        datasize=len(function_starts),
    ).build()
    header = MachHeader64(
        magic=MH_MAGIC_64,
        cputype=0x0100000C,
        cpusubtype=2,
        filetype=6,
        ncmds=len(segments) + 3,
        sizeofcmds=len(commands),
    ).build()
    return header + commands + contents + nlists + strings + function_starts


Encoder = Callable[..., int]


def _objc_class(data: _Segment, encode: Encoder, name: int, methods: int, metaclass: int = 0, flags: int = 0) -> int:
    class_ro = data.add(struct.pack("<IIIIQQQ", 0, 0, 0, 0, 0, encode(name), encode(methods)))
    return data.add(struct.pack("<QQQQQ", encode(metaclass), 0, 0, 0, encode(class_ro, authenticated=True) | flags))


def _relative_method_list(data: _Segment, flags: int, methods: list[tuple[int, int]]) -> int:
    """Add a list of the (name, implementation) given, each name being relative to its field unless `flags` say otherwise."""
    address = data.add(b"\x00" * (8 + 12 * len(methods)))
    entries = struct.pack("<II", 0x80000000 | flags | 12, len(methods))
    for index, (name, imp) in enumerate(methods):
        entry = address + 8 + 12 * index
        direct = flags & 0x40000000
        entries += struct.pack("<iii", name if direct else name - entry, 0, imp - (entry + 8))
    data.data[address - data.vmaddr :] = entries
    return address


@pytest.fixture(params=[_encode_cache_offset, _encode_address])
def objc_symbols(request: pytest.FixtureRequest, tmp_path: Path) -> DeviceSupportSymbols:
    """
    A tree whose `libfoo.dylib` names none of its functions but `foo`, leaving its methods to its metadata.

    Its pointers are encoded as each kind of cache does.
    """
    encode: Encoder = request.param
    root = tmp_path / "Symbols"
    (root / "usr/lib").mkdir(parents=True)

    # libobjc holds the selectors of the whole cache, and tells where they start
    strings = _Segment("__OBJC_RO", LIBOBJC_STRINGS)
    strings.string("padding")
    selectors = {name: strings.string(name) for name in ("bar", "shared", "qux:", "run", "stop")}
    selector_base = min(selectors.values()) - 0x10
    libobjc_data = _Segment("__DATA_CONST", LIBOBJC_DATA)
    libobjc_data.add(
        struct.pack("<5Q", 4, encode(selector_base), encode(LIBOBJC_STRINGS + len(strings.data)), 0, 0),
        "__objc_scoffs",
    )
    (root / "usr/lib/libobjc.A.dylib").write_bytes(
        _build_image(LIBOBJC_UUID, [_Segment("__TEXT", LIBOBJC_TEXT, 0x1000), libobjc_data, strings], [], {})
    )

    # The class a category of libfoo extends lives in another image
    libext_data = _Segment("__DATA", LIBEXT_DATA)
    libext_data.add(b"\x00" * 8)
    ext_class = _objc_class(libext_data, encode, libext_data.string("Ext"), 0)
    (root / "usr/lib/libext.dylib").write_bytes(
        _build_image(LIBEXT_UUID, [_Segment("__TEXT", SHARED_CACHE_BASE + 0x30000, 0x1000), libext_data], [], {})
    )

    data = _Segment("__DATA", OBJC_DATA)
    data.add(b"\x00" * 8)
    # A class whose methods name their selectors by their offset in the cache, and a metaclass
    # whose methods hold pointers
    shared = data.add(struct.pack("<II", 24, 1) + struct.pack("<QQQ", encode(selectors["shared"]), 0, encode(OBJC_TEXT + 0x40, authenticated=True)))  # fmt: skip
    foo_metaclass = _objc_class(data, encode, data.string("Foo"), shared)
    bar = _relative_method_list(data, 0x40000000, [(selectors["bar"] - selector_base, OBJC_TEXT + 0x30)])
    foo_class = _objc_class(data, encode, data.string("Foo"), bar, foo_metaclass)
    # A Swift class which got categories attached, so holding a list of method lists, whose methods
    # refer to their selectors
    selector_reference = data.add(struct.pack("<Q", encode(selectors["qux:"])))
    qux = _relative_method_list(data, 0, [(selector_reference, OBJC_TEXT + 0x50)])
    lists = data.add(b"\x00" * 24)
    data.data[lists - data.vmaddr :] = struct.pack(
        "<IIqq", 8, 2, ((qux - (lists + 8)) << 16) | 1, ((0x7000000 - (lists + 16)) << 16) | 2
    )
    baz_class = _objc_class(data, encode, data.string("_TtC3foo3Baz"), lists | 1, flags=2)
    # A category, whose methods its class lists as well
    run = _relative_method_list(data, 0x40000000, [(selectors["run"] - selector_base, OBJC_TEXT + 0x60)])
    stop = _relative_method_list(data, 0x40000000, [(selectors["stop"] - selector_base, OBJC_TEXT + 0x70)])
    category = data.add(
        struct.pack("<QQQQ", encode(data.string("Extras")), encode(ext_class, authenticated=True), encode(run), encode(stop))
    )  # fmt: skip
    data.add(struct.pack("<QQ", encode(foo_class), encode(baz_class)), "__objc_classlist")
    data.add(struct.pack("<Q", encode(category)), "__objc_catlist")
    functions = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]
    (root / "usr/lib/libfoo.dylib").write_bytes(
        _build_image(LIBFOO_UUID, [_Segment("__TEXT", OBJC_TEXT, 0x1000), data], functions, {"_foo": 0x10})
    )

    # The cache of DriverKit is mapped over the very same addresses
    (root / "System/DriverKit/usr/lib").mkdir(parents=True)
    (root / "System/DriverKit/usr/lib/libdriver.dylib").write_bytes(
        _build_image(
            DRIVERKIT_UUID,
            [_Segment("__TEXT", OBJC_TEXT + 0x800, 0x1000), _Segment("__DATA", OBJC_DATA + 0x10, 0x1000)],
            [],
            {},
        )
    )
    return DeviceSupportSymbols.load(root, tmp_path / "index")


def test_symbolicate_objc_methods_of_a_stripped_image(objc_symbols: DeviceSupportSymbols) -> None:
    image = objc_symbols.image_by_uuid(LIBFOO_UUID)
    assert image is not None
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x14) == ("foo", 4)
    # No symbol and no method: must not be attributed to the method following or preceding it
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x24) is None
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x34) == ("-[Foo bar]", 4)
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x40) == ("+[Foo shared]", 0)
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x5C) == ("-[_TtC3foo3Baz qux:]", 0xC)
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x68) == ("-[Ext(Extras) run]", 8)
    assert objc_symbols.symbolicate(image, OBJC_TEXT + 0x70) == ("+[Ext(Extras) stop]", 0)


def test_driverkit_images_do_not_shadow_the_shared_cache(symbols_root: Path, tmp_path: Path) -> None:
    # The cache of DriverKit is mapped over the very same addresses
    (symbols_root / "System/DriverKit/usr/lib").mkdir(parents=True)
    (symbols_root / "System/DriverKit/usr/lib/libdriver.dylib").write_bytes(
        build_macho(DRIVERKIT_UUID, LIBFOO_VMADDR + 0x800, 0x1000, {}, [])
    )
    (symbols_root / "System/DriverKit/usr/lib/libfirst.dylib").write_bytes(
        build_macho(APP_UUID, SHARED_CACHE_BASE - 0x4000000, 0x1000, {}, [])
    )
    symbols = DeviceSupportSymbols.load(symbols_root, tmp_path / "index")
    image = symbols.image_by_address(LIBFOO_VMADDR + 0x900)
    assert image is not None
    assert image.name == "libfoo.dylib"
    assert symbols.shared_cache_base == SHARED_CACHE_BASE
    driver = symbols.image_by_uuid(DRIVERKIT_UUID)
    assert driver is not None
    assert driver.name == "libdriver.dylib"


def test_symbols_index_of_an_older_version_is_replaced(symbols_root: Path, tmp_path: Path) -> None:
    index_dir = tmp_path / "index"
    DeviceSupportSymbols.load(symbols_root, index_dir)
    (index_file,) = index_dir.iterdir()
    index = json.loads(index_file.read_text())
    del index["segments"]
    index["version"] = 1
    index_file.write_text(json.dumps(index))
    assert len(DeviceSupportSymbols.load(symbols_root, index_dir).images) == 2
    assert json.loads(index_file.read_text())["version"] == device_support.INDEX_VERSION
