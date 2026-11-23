"""The interfaces every backend implements: local files or a symbolicator server."""

from typing import Optional, Protocol

from apple_symbols.device_support import SymbolImage
from apple_symbols.kernel import KernelImage


class UserlandSymbolSource(Protocol):
    """Resolves unslid userland addresses of one device and build to symbols."""

    images: list[SymbolImage]

    @property
    def has_shared_cache_images(self) -> bool: ...

    @property
    def shared_cache_base(self) -> Optional[int]: ...

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]: ...

    def image_by_address(self, address: int) -> Optional[SymbolImage]: ...

    def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]: ...


class KernelSymbolSource(Protocol):
    """Resolves unslid kernel addresses of one kernelcache to symbols."""

    images: list[KernelImage]

    @property
    def has_symbols(self) -> bool: ...

    def image_by_uuid(self, image_uuid: str) -> Optional[KernelImage]: ...

    def symbolicate(self, address: int) -> Optional[tuple[str, int]]: ...
