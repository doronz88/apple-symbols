"""
Symbol lookup against an Xcode ``DeviceSupport`` ``Symbols`` tree.

The tree holds the device's dyld shared cache split back into one Mach-O per image. Every image
keeps the unslid address it has inside the cache, so an address is resolved by finding the image
whose ``__TEXT`` contains it and then the nearest preceding entry of that image's symbol table.
"""

import bisect
import hashlib
import json
import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from apple_symbols._cache import default_cache_dir
from apple_symbols.macho import parse_function_starts, parse_macho, read_symbol_name, read_symbols

logger = logging.getLogger(__name__)

INDEX_VERSION = 1
INDEX_DIRNAME = "device_support_index"

DEVICE_SUPPORT_ROOT = Path("~/Library/Developer/Xcode/iOS DeviceSupport")

# Shared caches get mapped at a multiple of this, and their first image starts well within it
SHARED_CACHE_BASE_ALIGNMENT = 0x2000000


@dataclass(frozen=True)
class SymbolImage:
    """A Mach-O of the symbols tree. `path` is its on-device path."""

    path: str
    uuid: str
    vmaddr: int
    vmsize: int

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class _SymbolTable:
    addresses: list[int] = field(default_factory=list[int])
    string_offsets: list[int] = field(default_factory=list[int])
    stroff: int = 0
    function_starts: list[int] = field(default_factory=list[int])


def _scan(root: Path) -> list[SymbolImage]:
    images: list[SymbolImage] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            file = Path(dirpath) / filename
            try:
                with open(file, "rb") as fd:
                    macho = parse_macho(fd)
            except (OSError, struct.error):
                continue
            if macho is None or macho.uuid is None or macho.vmaddr is None:
                continue
            images.append(
                SymbolImage(
                    path="/" + file.relative_to(root).as_posix(),
                    uuid=macho.uuid,
                    vmaddr=macho.vmaddr,
                    vmsize=macho.vmsize,
                )
            )
    return images


def fingerprint(root: Path) -> list[int]:
    """
    Get a value which changes whenever a file is added to or removed from the tree.

    That is what touches the modification time of a directory, so no file has to be looked at.
    """
    count = 0
    latest = 0
    for dirpath, _dirnames, _filenames in os.walk(root):
        count += 1
        latest = max(latest, os.stat(dirpath).st_mtime_ns)
    return [count, latest]


class DeviceSupportSymbols:
    """Resolves addresses to symbols using the Mach-O files below `root`."""

    def __init__(self, root: Path, images: list[SymbolImage]) -> None:
        self.root = root
        self.images = sorted(images, key=lambda image: image.vmaddr)
        self._starts = [image.vmaddr for image in self.images]
        self._by_uuid = {image.uuid: image for image in self.images}
        self._symtabs: dict[str, _SymbolTable] = {}
        self._names: dict[tuple[str, int], str] = {}

    @classmethod
    def load(cls, root: Path, index_dir: Optional[Path] = None) -> "DeviceSupportSymbols":
        """
        Index the images below `root`.

        Reading the headers of a whole tree takes a while, so the index is kept in `index_dir`
        (:func:`default_cache_dir` by default) and reused for as long as no file is added to
        or removed from the tree.
        """
        root = root.resolve()
        if index_dir is None:
            index_dir = default_cache_dir() / INDEX_DIRNAME
        index_file = index_dir / f"{hashlib.sha256(str(root).encode()).hexdigest()[:16]}.json"
        tree_fingerprint = fingerprint(root)
        try:
            index = json.loads(index_file.read_text())
            if (
                index["version"] == INDEX_VERSION
                and index["root"] == str(root)
                and index["fingerprint"] == tree_fingerprint
            ):
                return cls(root, [SymbolImage(*image) for image in index["images"]])
        except (OSError, ValueError, KeyError, TypeError):
            pass

        logger.info(f"Indexing symbols of {root}")
        images = _scan(root)
        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            index_file.write_text(
                json.dumps({
                    "version": INDEX_VERSION,
                    "root": str(root),
                    "fingerprint": tree_fingerprint,
                    "images": [[image.path, image.uuid, image.vmaddr, image.vmsize] for image in images],
                })
            )
        except OSError as e:
            logger.debug(f"Could not store the symbols index at {index_file}: {e}")
        return cls(root, images)

    @property
    def has_shared_cache_images(self) -> bool:
        """Whether the tree holds images split out of the shared cache, which is where they get an address."""
        return any(image.vmaddr for image in self.images)

    @property
    def shared_cache_base(self) -> Optional[int]:
        """
        The unslid address the shared cache of these images starts at, or `None` without such images.

        The tree does not keep the header of the cache, so this is derived from its lowest image.
        """
        lowest = next((image.vmaddr for image in self.images if image.vmaddr), None)
        return None if lowest is None else lowest - lowest % SHARED_CACHE_BASE_ALIGNMENT

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        return self._by_uuid.get(image_uuid.lower())

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        """Get the image whose `__TEXT` contains the given unslid address."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        image = self.images[index]
        return image if address < image.vmaddr + image.vmsize else None

    def _symtab(self, image: SymbolImage) -> _SymbolTable:
        symtab = self._symtabs.get(image.path)
        if symtab is not None:
            return symtab
        symtab = _SymbolTable()
        try:
            with open(self.root / image.path.lstrip("/"), "rb") as fd:
                macho = parse_macho(fd)
                if macho is not None and macho.nsyms:
                    symbols = read_symbols(fd, macho, image.vmaddr, image.vmaddr + image.vmsize)
                    symtab.addresses = [address for address, _ in symbols]
                    symtab.string_offsets = [strx for _, strx in symbols]
                    symtab.stroff = macho.stroff
                if macho is not None and macho.function_starts_size:
                    fd.seek(macho.function_starts_offset)
                    symtab.function_starts = parse_function_starts(fd.read(macho.function_starts_size), image.vmaddr)
        except (OSError, struct.error) as e:
            logger.debug(f"Could not read the symbols of {image.path}: {e}")
        self._symtabs[image.path] = symtab
        return symtab

    def _symbol_name(self, image: SymbolImage, offset: int) -> str:
        key = (image.path, offset)
        name = self._names.get(key)
        if name is None:
            with open(self.root / image.path.lstrip("/"), "rb") as fd:
                name = read_symbol_name(fd, offset)
            self._names[key] = name
        return name

    def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]:
        """
        Get the symbol preceding the given unslid address of `image`.

        :returns: The symbol name and the offset of `address` from it, or `None` when the symbol
            table does not name the function the address is in.
        """
        symtab = self._symtab(image)
        index = bisect.bisect_right(symtab.addresses, address) - 1
        if index < 0:
            return None
        symbol_address = symtab.addresses[index]
        function = bisect.bisect_right(symtab.function_starts, address) - 1
        if function >= 0 and symtab.function_starts[function] > symbol_address:
            # The address belongs to a function the symbol table does not name
            return None
        try:
            name = self._symbol_name(image, symtab.stroff + symtab.string_offsets[index])
        except OSError:
            return None
        if not name:
            return None
        return name, address - symbol_address


def get_device_support_path(
    product_type: str, product_version: str, product_build_version: str, root: Optional[Path] = None
) -> Path:
    """Get the Xcode DeviceSupport directory of a device, e.g. ``iPhone17,3 26.4 (23E246)``."""
    if root is None:
        root = DEVICE_SUPPORT_ROOT.expanduser()
    return root / f"{product_type} {product_version} ({product_build_version})"


def find_device_support_symbols(
    product_type: str, product_build_version: str, product_version: Optional[str] = None, root: Optional[Path] = None
) -> Optional[Path]:
    """
    Get the ``Symbols`` directory of the Xcode DeviceSupport of a device, if it exists.

    :param product_version: Narrows the search down to one directory. A product type and a build
        already tell a firmware apart, so it may be omitted when unknown.
    """
    if root is None:
        root = DEVICE_SUPPORT_ROOT.expanduser()
    if product_version is not None:
        candidates = [get_device_support_path(product_type, product_version, product_build_version, root)]
    else:
        prefix = f"{product_type} "
        suffix = f" ({product_build_version})"
        try:
            candidates = sorted(
                entry for entry in root.iterdir() if entry.name.startswith(prefix) and entry.name.endswith(suffix)
            )
        except OSError:
            return None
    for candidate in candidates:
        symbols = candidate / "Symbols"
        if symbols.is_dir():
            return symbols
    return None
