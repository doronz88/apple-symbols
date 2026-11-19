import io
import json
from pathlib import Path
from typing import Any

import pytest

from apple_symbols import (
    DeviceSupportSymbols,
    KernelSymbols,
    device_support,
    find_device_support_symbols,
    get_device_support_path,
    kernel,
)
from apple_symbols.macho import NLIST_64, MachHeader64, Nlist64, parse_macho
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
