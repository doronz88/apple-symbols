from typing import Optional

import pytest
from symbolicator_server.client import SymbolicatorClient
from symbolicator_server.models import FunctionSymbol, ImageInfo, SharedCache

from apple_symbols.remote import KERNEL_HIGH_BIT, RemoteDeviceSymbols, RemoteKernelSymbols

CACHE_UUID = "8BAF1A04-DCD0-3DDE-97D4-78470487BCCC"
DRIVERKIT_CACHE_UUID = "AA10039A-2C36-38B1-86FB-6FDB4D4B6790"
KERNELCACHE_UUID = "31370FC9-3D00-8949-257B-717E28D14DA6"
SHARED_CACHE_BASE = 0x180000000
LIBFOO_UUID = "11111111-2222-3333-4444-555555555555"
LIBFOO = ImageInfo(
    LIBFOO_UUID.upper(), "/usr/lib/libfoo.dylib", SHARED_CACHE_BASE + 0x10000, SHARED_CACHE_BASE + 0x11000
)
DK_LIBFOO = ImageInfo(
    "D0D0D0D0-1111-2222-3333-444444444444", "/System/DriverKit/usr/lib/libfoo.dylib", LIBFOO.text_start, LIBFOO.text_end
)
KEXT_UUID = "ABABABAB-CDCD-EFEF-0101-232323232323"
KEXT = ImageInfo(KEXT_UUID, "com.apple.kec.Libm", 0x7FFFFE0007100000, 0x7FFFFE0007101000)


class FakeServer:
    def __init__(self) -> None:
        self.symbol_requests: list[tuple[str, Optional[str], Optional[str]]] = []

    def find_dscs(self, device: str, build: str) -> list[SharedCache]:
        if (device, build) != ("iPhone17,3", "23E246"):
            return []
        return [SharedCache(DRIVERKIT_CACHE_UUID, SHARED_CACHE_BASE), SharedCache(CACHE_UUID, SHARED_CACHE_BASE)]

    def dsc_images(self, uuid: str) -> Optional[list[ImageInfo]]:
        return {CACHE_UUID: [LIBFOO], DRIVERKIT_CACHE_UUID: [DK_LIBFOO]}.get(uuid.upper())

    def kernelcache_images(self, uuid: str) -> Optional[list[ImageInfo]]:
        return [KEXT] if uuid.upper() == KERNELCACHE_UUID else None

    def image_symbols(
        self, uuid: str, dsc: Optional[str] = None, kernelcache: Optional[str] = None
    ) -> Optional[list[FunctionSymbol]]:
        self.symbol_requests.append((uuid.upper(), dsc, kernelcache))
        if uuid.upper() == LIBFOO_UUID.upper() and (dsc or "").upper() == CACHE_UUID:
            start = LIBFOO.text_start
            return [
                FunctionSymbol(start + 0x200, start + 0x300, "__bar"),
                FunctionSymbol(start + 0x100, start + 0x200, "__foo"),
                FunctionSymbol(start + 0x300, start + 0x400, None),
            ]
        if uuid.upper() == KEXT_UUID and (kernelcache or "").upper() == KERNELCACHE_UUID:
            return [FunctionSymbol(KEXT.text_start + 0x10, KEXT.text_start + 0x20, "_kext_func")]
        return None


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> tuple[SymbolicatorClient, FakeServer]:
    client = SymbolicatorClient("http://symbolicator.invalid")
    fake = FakeServer()
    for name in ("find_dscs", "dsc_images", "kernelcache_images", "image_symbols"):
        monkeypatch.setattr(client, name, getattr(fake, name))
    return client, fake


def test_device_symbols(server: tuple[SymbolicatorClient, FakeServer]) -> None:
    client, fake = server
    symbols = RemoteDeviceSymbols.for_build(client, "iPhone17,3", "23E246")
    assert symbols.shared_cache_base == SHARED_CACHE_BASE
    assert symbols.has_shared_cache_images

    image = symbols.image_by_uuid(LIBFOO_UUID)
    assert image is not None
    assert image.path == "/usr/lib/libfoo.dylib"
    # The DriverKit cache is mapped over the same addresses, but is not looked up by address
    assert symbols.image_by_address(image.vmaddr + 0x150) == image
    assert symbols.image_by_address(image.vmaddr + image.vmsize) is None

    assert symbols.symbolicate(image, image.vmaddr + 0x104) == ("_foo", 4)
    assert symbols.symbolicate(image, image.vmaddr + 0x200) == ("_bar", 0)
    assert symbols.symbolicate(image, image.vmaddr + 0x310) is None  # unnamed function
    assert symbols.symbolicate(image, image.vmaddr + 0x50) is None  # before any function
    # The functions of an image are fetched once, from its own cache
    assert fake.symbol_requests == [(LIBFOO_UUID.upper(), CACHE_UUID, None)]


def test_device_symbols_unknown_build(server: tuple[SymbolicatorClient, FakeServer]) -> None:
    client, _ = server
    with pytest.raises(LookupError):
        RemoteDeviceSymbols.for_build(client, "iPhone17,3", "00A000")
    with pytest.raises(LookupError):
        RemoteDeviceSymbols.for_shared_cache(client, "00000000-0000-0000-0000-000000000000")


def test_kernel_symbols(server: tuple[SymbolicatorClient, FakeServer]) -> None:
    client, _ = server
    kernel = RemoteKernelSymbols.for_kernelcache(client, KERNELCACHE_UUID.lower())
    assert kernel.has_symbols
    image = kernel.image_by_uuid(KEXT_UUID.lower())
    assert image is not None
    assert image.name == "com.apple.kec.Libm"
    assert image.text_exec == KEXT.text_start | KERNEL_HIGH_BIT
    assert kernel.symbolicate(image.text_exec + 0x14) == ("_kext_func", 4)
    assert kernel.symbolicate(image.text_exec + 0x30) is None
    assert kernel.symbolicate(image.text_exec + 0x2000) is None  # past the kext
    with pytest.raises(LookupError):
        RemoteKernelSymbols.for_kernelcache(client, "00000000-0000-0000-0000-000000000000")
