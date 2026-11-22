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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from apple_symbols._cache import default_cache_dir
from apple_symbols.macho import MachO, parse_function_starts, parse_macho, read_symbol_name, read_symbols
from apple_symbols.objc import (
    CLASS_DATA,
    CLASS_DATA_MASK,
    CLASS_RO_NAME,
    POINTER_SIZE,
    ImageData,
    ObjCMethod,
    PointerDecoder,
    find_pointer_decoder,
    read_objc_methods,
)

logger = logging.getLogger(__name__)

INDEX_VERSION = 2
INDEX_DIRNAME = "device_support_index"

DEVICE_SUPPORT_ROOT = Path("~/Library/Developer/Xcode/iOS DeviceSupport")

# The image holding the strings of the Objective-C metadata of the whole cache, and telling where
# its selectors start
LIBOBJC_PATH = "/usr/lib/libobjc.A.dylib"
SELECTOR_OFFSETS_SECTION = "__objc_scoffs"
# The tree also holds the images of the shared cache DriverKit extensions run with, which is mapped
# over the same addresses, so only one of the caches gets to be looked up by address
DRIVERKIT_PREFIX = "/System/DriverKit/"

# Anything above it in that section is a pointer
SELECTOR_OFFSETS_MAX_VERSION = 0xFFFF
# Longest class or selector name read
MAX_OBJC_NAME_LENGTH = 1024

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


@dataclass
class _ObjCTable:
    addresses: list[int] = field(default_factory=list[int])
    methods: list[ObjCMethod] = field(default_factory=list[ObjCMethod])


# Address and size of a segment, and the index of its image
_Segment = tuple[int, int, int]


def _scan(root: Path) -> tuple[list[SymbolImage], list[_Segment]]:
    images: list[SymbolImage] = []
    segments: list[_Segment] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            file = Path(dirpath) / filename
            try:
                with open(file, "rb") as fd:
                    macho = parse_macho(fd)
            except OSError:
                continue
            if macho is None or macho.uuid is None or macho.vmaddr is None:
                continue
            if macho.vmaddr:
                # Only the images of the shared cache have addresses of their own to be found by
                segments += [
                    (segment.vmaddr, segment.vmsize, len(images))
                    for segment in macho.segments
                    if segment.filesize and segment.name != "__LINKEDIT"
                ]
            images.append(
                SymbolImage(
                    path="/" + file.relative_to(root).as_posix(),
                    uuid=macho.uuid,
                    vmaddr=macho.vmaddr,
                    vmsize=macho.vmsize,
                )
            )
    return images, segments


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

    def __init__(self, root: Path, images: list[SymbolImage], segments: Optional[list[_Segment]] = None) -> None:
        """
        :param segments: Address and size of the segments of the images, each with the index of its
            image in `images`. They locate what the Objective-C metadata of an image refers to
            outside of it, so the methods of categories and of stripped images go unnamed without.
        """
        self.root = root
        self.images = sorted(images, key=lambda image: image.vmaddr)
        self._addressed = [image for image in self.images if not image.path.startswith(DRIVERKIT_PREFIX)]
        self._starts = [image.vmaddr for image in self._addressed]
        self._by_uuid = {image.uuid: image for image in self.images}
        self._symtabs: dict[str, _SymbolTable] = {}
        self._names: dict[tuple[str, int], str] = {}
        self._segments = sorted(
            (
                (vmaddr, vmsize, images[index])
                for vmaddr, vmsize, index in segments or []
                if not images[index].path.startswith(DRIVERKIT_PREFIX)
            ),
            key=lambda segment: segment[0],
        )
        self._segment_starts = [vmaddr for vmaddr, _, _ in self._segments]
        self._machos: dict[str, Optional[MachO]] = {}
        self._objc: dict[str, _ObjCTable] = {}
        self._objc_names: dict[int, Optional[str]] = {}
        self._decode: Optional[PointerDecoder] = None
        self._selector_base: Optional[int] = None
        self._selector_base_read = False

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
                return cls(
                    root,
                    [SymbolImage(*image) for image in index["images"]],
                    [(vmaddr, vmsize, image) for vmaddr, vmsize, image in index["segments"]],
                )
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            pass

        logger.info(f"Indexing symbols of {root}")
        images, segments = _scan(root)
        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            index_file.write_text(
                json.dumps({
                    "version": INDEX_VERSION,
                    "root": str(root),
                    "fingerprint": tree_fingerprint,
                    "images": [[image.path, image.uuid, image.vmaddr, image.vmsize] for image in images],
                    "segments": segments,
                })
            )
        except OSError as e:
            logger.debug(f"Could not store the symbols index at {index_file}: {e}")
        return cls(root, images, segments)

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
        lowest = next((image.vmaddr for image in self._addressed if image.vmaddr), None)
        return None if lowest is None else lowest - lowest % SHARED_CACHE_BASE_ALIGNMENT

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        return self._by_uuid.get(image_uuid.lower())

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        """Get the image whose `__TEXT` contains the given unslid address."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        image = self._addressed[index]
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
        except OSError as e:
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
        function = bisect.bisect_right(symtab.function_starts, address) - 1
        function_start = symtab.function_starts[function] if function >= 0 else None
        if index < 0 or (function_start is not None and function_start > symtab.addresses[index]):
            # The address belongs to a function the symbol table does not name
            return self._symbolicate_objc_method(image, address, function_start)
        symbol_address = symtab.addresses[index]
        try:
            name = self._symbol_name(image, symtab.stroff + symtab.string_offsets[index])
        except OSError:
            return None
        if not name:
            return None
        return name, address - symbol_address

    def _symbolicate_objc_method(
        self, image: SymbolImage, address: int, function_start: Optional[int]
    ) -> Optional[tuple[str, int]]:
        """Name the function `address` is in as the Objective-C method it implements, if it is one."""
        if function_start is None:
            # Nothing tells whether the method preceding the address reaches it
            return None
        table = self._objc_table(image)
        index = bisect.bisect_left(table.addresses, function_start)
        if index == len(table.addresses) or table.addresses[index] != function_start:
            return None
        name = self._objc_method_name(table.methods[index])
        return None if name is None else (name, address - function_start)

    def _macho(self, image: SymbolImage) -> Optional[MachO]:
        if image.path not in self._machos:
            try:
                with open(self.root / image.path.lstrip("/"), "rb") as fd:
                    self._machos[image.path] = parse_macho(fd)
            except OSError as e:
                logger.debug(f"Could not read {image.path}: {e}")
                self._machos[image.path] = None
        return self._machos[image.path]

    def _read(self, address: int, size: int) -> Optional[bytes]:
        """Read what the image mapped at the given unslid address holds there, up to the end of its segment."""
        index = bisect.bisect_right(self._segment_starts, address) - 1
        if index < 0:
            return None
        vmaddr, vmsize, image = self._segments[index]
        macho = self._macho(image) if address < vmaddr + vmsize else None
        if macho is None:
            return None
        segment = next((segment for segment in macho.segments if segment.vmaddr == vmaddr), None)
        if segment is None or address - vmaddr >= segment.filesize:
            return None
        try:
            with open(self.root / image.path.lstrip("/"), "rb") as fd:
                fd.seek(segment.fileoff + address - vmaddr)
                return fd.read(min(size, segment.filesize - (address - vmaddr)))
        except OSError:
            return None

    def _read_pointer(self, address: int) -> int:
        data = self._read(address, POINTER_SIZE)
        if data is None or len(data) < POINTER_SIZE or self._decode is None:
            return 0
        return self._decode(int.from_bytes(data, "little"))

    def _read_objc_name(self, address: int) -> Optional[str]:
        if address not in self._objc_names:
            data = self._read(address, MAX_OBJC_NAME_LENGTH) if address else None
            name = data.split(b"\x00", 1)[0].decode(errors="replace") if data else None
            self._objc_names[address] = name or None
        return self._objc_names[address]

    def _objc_selector_base(self) -> Optional[int]:
        """Get the address the method lists of the cache count their selectors from, which libobjc tells."""
        if not self._selector_base_read:
            self._selector_base_read = True
            libobjc = next((image for image in self.images if image.path == LIBOBJC_PATH), None)
            macho = self._macho(libobjc) if libobjc is not None else None
            address, size = macho.objc_sections.get(SELECTOR_OFFSETS_SECTION, (0, 0)) if macho is not None else (0, 0)
            data = self._read(address, size) if size else None
            if data is not None and self._decode is not None:
                # The section holds the bounds of the selectors next to a version, whose place varies
                for offset in range(0, len(data) - len(data) % POINTER_SIZE, POINTER_SIZE):
                    raw = int.from_bytes(data[offset : offset + POINTER_SIZE], "little")
                    if raw > SELECTOR_OFFSETS_MAX_VERSION:
                        self._selector_base = self._decode(raw)
                        break
        return self._selector_base

    def _objc_table(self, image: SymbolImage) -> _ObjCTable:
        table = self._objc.get(image.path)
        if table is not None:
            return table
        table = _ObjCTable()
        self._objc[image.path] = table
        cache_base = self.shared_cache_base
        macho = self._macho(image)
        if cache_base is None or macho is None or not image.vmaddr or not macho.objc_sections:
            return table
        try:
            data = (self.root / image.path.lstrip("/")).read_bytes()
        except OSError as e:
            logger.debug(f"Could not read the Objective-C metadata of {image.path}: {e}")
            return table
        image_data = ImageData(macho, data)
        if self._decode is None:
            # Every image of a cache encodes its pointers alike
            self._decode = find_pointer_decoder(image_data, cache_base)
        if self._decode is None:
            return table
        table.methods = read_objc_methods(image_data, self._decode, self._objc_selector_base())
        table.addresses = [method.imp for method in table.methods]
        return table

    def _objc_method_name(self, method: ObjCMethod) -> Optional[str]:
        class_ro = self._read_pointer(method.class_address + CLASS_DATA) & CLASS_DATA_MASK
        class_name = self._read_objc_name(self._read_pointer(class_ro + CLASS_RO_NAME)) if class_ro else None
        selector = self._read_objc_name(method.selector)
        if class_name is None or selector is None:
            return None
        if method.category_name:
            category = self._read_objc_name(method.category_name)
            if category is None:
                return None
            class_name = f"{class_name}({category})"
        return f"{'+' if method.is_class_method else '-'}[{class_name} {selector}]"


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
