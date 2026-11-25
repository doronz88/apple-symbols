"""
Symbol lookup against a symbolicator server (``pip install apple-symbols[remote]``).

The server holds the symbols of scanned IPSWs. Image lists are fetched up front; the functions of an
image the first time an address in it is looked up.
"""

import bisect
from typing import Optional

from symbolicator_server.client import SymbolicatorClient
from symbolicator_server.models import FunctionSymbol

from apple_symbols.device_support import DRIVERKIT_PREFIX, SymbolImage
from apple_symbols.kernel import KernelImage

# The server stores kernel addresses with bit 63 cleared
KERNEL_HIGH_BIT = 1 << 63


class _FunctionTable:
    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.names: list[Optional[str]] = []

    @classmethod
    def build(
        cls, symbols: Optional[list[FunctionSymbol]], high_bits: int = 0, strip_underscore: bool = False
    ) -> "_FunctionTable":
        """
        :param strip_underscore: Drop the leading underscore C symbols carry in a symbol table, as
            :func:`apple_symbols.macho.read_symbol_name` does.
        """
        table = cls()
        for symbol in sorted(symbols or [], key=lambda symbol: symbol.start):
            table.starts.append(symbol.start | high_bits)
            table.ends.append(symbol.end | high_bits)
            name = symbol.name
            if strip_underscore and name is not None and name.startswith("_"):
                name = name[1:]
            table.names.append(name)
        return table

    def lookup(self, address: int) -> Optional[tuple[str, int]]:
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0 or address >= self.ends[index]:
            return None
        name = self.names[index]
        if name is None:
            return None
        return name, address - self.starts[index]


class RemoteDeviceSymbols:
    """Resolves addresses to symbols using the shared caches a symbolicator server holds."""

    def __init__(
        self,
        client: SymbolicatorClient,
        images: dict[str, list[SymbolImage]],
        shared_cache_base: Optional[int] = None,
    ) -> None:
        """
        :param images: The images of each shared cache, by the cache's UUID.
        """
        self.client = client
        self._cache_of: dict[SymbolImage, str] = {
            image: cache_uuid for cache_uuid, cache_images in images.items() for image in cache_images
        }
        self.images = sorted(self._cache_of, key=lambda image: image.vmaddr)
        self._addressed = [image for image in self.images if not image.path.startswith(DRIVERKIT_PREFIX)]
        self._starts = [image.vmaddr for image in self._addressed]
        self._by_uuid = {image.uuid: image for image in self.images}
        self._shared_cache_base = shared_cache_base
        self._tables: dict[SymbolImage, _FunctionTable] = {}

    @classmethod
    def for_build(cls, client: SymbolicatorClient, device: str, build: str) -> "RemoteDeviceSymbols":
        """
        The shared caches of a device's build, e.g. ``("iPhone17,3", "23E246")``.

        :raises LookupError: If the server has no IPSW of this build for this device.
        """
        caches = client.find_dscs(device, build)
        if not caches:
            raise LookupError(f"{client.server} has no shared cache of {device} {build}")
        images = {cache.uuid: cls._cache_images(client, cache.uuid) for cache in caches}
        # The DriverKit cache is mapped over the same addresses; the base is the other cache's
        base = next(
            (
                cache.shared_region_start
                for cache in caches
                if any(not image.path.startswith(DRIVERKIT_PREFIX) for image in images[cache.uuid])
            ),
            None,
        )
        return cls(client, images, base)

    @classmethod
    def for_shared_cache(
        cls, client: SymbolicatorClient, cache_uuid: str, shared_region_start: Optional[int] = None
    ) -> "RemoteDeviceSymbols":
        """
        One shared cache, by its UUID.

        :raises LookupError: If the server does not have it.
        """
        return cls(client, {cache_uuid: cls._cache_images(client, cache_uuid)}, shared_region_start)

    @staticmethod
    def _cache_images(client: SymbolicatorClient, cache_uuid: str) -> list[SymbolImage]:
        images = client.dsc_images(cache_uuid)
        if images is None:
            raise LookupError(f"{client.server} has no shared cache {cache_uuid}")
        return [
            SymbolImage(image.path, image.uuid.lower(), image.text_start, image.text_end - image.text_start)
            for image in images
        ]

    @property
    def has_shared_cache_images(self) -> bool:
        return any(image.vmaddr for image in self.images)

    @property
    def shared_cache_base(self) -> Optional[int]:
        """The unslid address the shared cache of these images starts at, as the server has it."""
        return self._shared_cache_base

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        return self._by_uuid.get(image_uuid.lower())

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        """Get the image whose `__TEXT` contains the given unslid address."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        image = self._addressed[index]
        return image if address < image.vmaddr + image.vmsize else None

    def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]:
        """
        Get the function of `image` containing the given unslid address.

        :returns: The function name and the offset of `address` from it, or `None` when no named
            function contains it.
        """
        table = self._tables.get(image)
        if table is None:
            # Userland names come from symbol tables, which the local backend reads without the underscore.
            # Kernel names come mostly from ipsw signatures, which both backends keep as they are.
            symbols = self.client.image_symbols(image.uuid, dsc=self._cache_of[image])
            table = _FunctionTable.build(symbols, strip_underscore=True)
            self._tables[image] = table
        return table.lookup(address)


class RemoteKernelSymbols:
    """Resolves unslid kernel addresses to symbols using a kernelcache a symbolicator server holds."""

    def __init__(
        self, client: SymbolicatorClient, kernelcache_uuid: str, images: list[KernelImage], text_ends: dict[str, int]
    ) -> None:
        """
        :param text_ends: The unslid end of the `__TEXT_EXEC` of each image, by the image's UUID.
        """
        self.client = client
        self.kernelcache_uuid = kernelcache_uuid
        self.images = sorted(images, key=lambda image: image.text_exec)
        self._starts = [image.text_exec for image in self.images]
        self._text_ends = text_ends
        self._by_uuid = {image.uuid: image for image in self.images}
        self._tables: dict[KernelImage, _FunctionTable] = {}

    @classmethod
    def for_kernelcache(cls, client: SymbolicatorClient, kernelcache_uuid: str) -> "RemoteKernelSymbols":
        """
        A kernelcache, by its UUID.

        :raises LookupError: If the server does not have it.
        """
        images = client.kernelcache_images(kernelcache_uuid)
        if images is None:
            raise LookupError(f"{client.server} has no kernelcache {kernelcache_uuid}")
        return cls(
            client,
            kernelcache_uuid,
            [KernelImage(image.path, image.uuid.lower(), image.text_start | KERNEL_HIGH_BIT) for image in images],
            {image.uuid.lower(): image.text_end | KERNEL_HIGH_BIT for image in images},
        )

    @property
    def has_symbols(self) -> bool:
        """Whether the server has any image of this kernelcache; its functions are fetched only when looked up."""
        return bool(self.images)

    def image_by_uuid(self, image_uuid: str) -> Optional[KernelImage]:
        return self._by_uuid.get(image_uuid.lower())

    def symbolicate(self, address: int) -> Optional[tuple[str, int]]:
        """
        Get the function containing the given unslid address.

        :returns: The function name and the offset of `address` from it, or `None` when no named
            function contains it.
        """
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        image = self.images[index]
        if address >= self._text_ends.get(image.uuid, 0):
            return None
        table = self._tables.get(image)
        if table is None:
            symbols = self.client.image_symbols(image.uuid, kernelcache=self.kernelcache_uuid)
            table = _FunctionTable.build(symbols, KERNEL_HIGH_BIT)
            self._tables[image] = table
        return table.lookup(address)
