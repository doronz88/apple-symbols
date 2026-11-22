"""
The Objective-C methods of an image taken out of a dyld shared cache.

Apple strips the local symbols of some images entirely, which leaves the Objective-C metadata as
the only thing still naming their methods: every class and category lists the implementation of
each of its methods next to its selector.

The pointers of such an image are the ones the cache keeps on disk. They are links of the chain
dyld walks to slide the cache, so each has to be decoded into the address it stands for.
"""

import struct
from dataclasses import dataclass
from typing import Callable, Optional

from apple_symbols.macho import MachO

POINTER_SIZE = 8

# objc_class
CLASS_ISA = 0x00
CLASS_DATA = 0x20
# The low bits of the data pointer of a class flag it, e.g. as a Swift class
CLASS_DATA_MASK = ~0x7

# class_ro_t
CLASS_RO_NAME = 0x18
CLASS_RO_BASE_METHODS = 0x20

# category_t
CATEGORY_NAME = 0x00
CATEGORY_CLASS = 0x08
CATEGORY_INSTANCE_METHODS = 0x10
CATEGORY_CLASS_METHODS = 0x18

# method_list_t: `entsizeAndFlags` and `count`, followed by the methods
METHOD_LIST_HEADER = struct.Struct("<II")
METHOD_LIST_ENTSIZE_MASK = 0xFFFC
# The methods hold offsets relative to their own fields instead of pointers
METHOD_LIST_RELATIVE = 0x80000000
# The name of a relative method is an offset from the selectors of the cache, not to a selector reference
METHOD_LIST_DIRECT_SELECTORS = 0x40000000
RELATIVE_METHOD = struct.Struct("<iii")
POINTER_METHOD = struct.Struct("<QQQ")
# Offset of `imp` in a relative method, which is what it is relative to
RELATIVE_METHOD_IMP = 8

# A class which got the methods of categories attached keeps a list of method lists instead,
# flagged by the low bit of the pointer. Each entry is the index of an image and, above it, the
# signed offset of a method list from the entry.
METHOD_LIST_LIST_FLAG = 1
METHOD_LIST_LIST_HEADER = struct.Struct("<II")
METHOD_LIST_LIST_ENTRY = struct.Struct("<q")
METHOD_LIST_LIST_OFFSET_SHIFT = 16

POINTER_AUTHENTICATED = 1 << 63

PointerDecoder = Callable[[int], int]


def _decode_address(cache_base: int, raw: int) -> int:
    """Decode a pointer of the caches which keep whole addresses (slide info up to version 3)."""
    if raw & POINTER_AUTHENTICATED:
        return cache_base + (raw & 0xFFFFFFFF)
    return raw & 0xFFFFFFFFFF


def _decode_cache_offset(cache_base: int, raw: int) -> int:
    """Decode a pointer of the caches which keep offsets from their base (slide info version 5)."""
    return cache_base + (raw & 0x3FFFFFFFF)


_DECODERS = (_decode_address, _decode_cache_offset)


@dataclass(frozen=True)
class ObjCMethod:
    """A method implementation and the addresses of what names it."""

    imp: int
    #: The class the method belongs to: the one a category extends, never a metaclass
    class_address: int
    #: The name of the category defining the method, 0 for a method of the class itself
    category_name: int
    selector: int
    is_class_method: bool


class ImageData:
    """The contents of an image, read by address."""

    def __init__(self, macho: MachO, data: bytes) -> None:
        self.macho = macho
        self.data = data
        self._segments = [segment for segment in macho.segments if segment.filesize and segment.name != "__LINKEDIT"]

    def offset(self, address: int, size: int = 1) -> Optional[int]:
        """Get the file offset of `size` bytes at `address`, or `None` when the image does not hold them."""
        for segment in self._segments:
            relative = address - segment.vmaddr
            if relative >= 0 and relative + size <= min(segment.vmsize, segment.filesize):
                offset = segment.fileoff + relative
                return offset if offset + size <= len(self.data) else None
        return None

    def pointer(self, address: int) -> Optional[int]:
        """Get the raw pointer at `address`."""
        offset = self.offset(address, POINTER_SIZE)
        if offset is None:
            return None
        return int.from_bytes(self.data[offset : offset + POINTER_SIZE], "little")

    def section_pointers(self, name: str) -> list[int]:
        """Get the raw pointers a section of the Objective-C metadata lists."""
        address, size = self.macho.objc_sections.get(name, (0, 0))
        offset = self.offset(address, size) if size else None
        if offset is None:
            return []
        size -= size % POINTER_SIZE
        return [raw for (raw,) in struct.iter_unpack("<Q", self.data[offset : offset + size])]


def find_pointer_decoder(image: ImageData, cache_base: int) -> Optional[PointerDecoder]:
    """
    Tell how the cache `image` comes from encodes its pointers.

    An image defines the classes and categories it lists, so the right decoding is the one which
    makes the lists point into the image itself.

    :returns: `None` when the image lists nothing, or in no way this module knows of.
    """
    raws = [raw for name in ("__objc_classlist", "__objc_catlist") for raw in image.section_pointers(name) if raw]
    if not raws:
        return None
    for decode in _DECODERS:
        if all(image.offset(decode(cache_base, raw), POINTER_SIZE) is not None for raw in raws[:8]):

            def decoder(raw: int, decode: Callable[[int, int], int] = decode) -> int:
                return decode(cache_base, raw) if raw else 0

            return decoder
    return None


class _MethodReader:
    def __init__(self, image: ImageData, decode: PointerDecoder, selector_base: Optional[int]) -> None:
        self.image = image
        self.decode = decode
        self.selector_base = selector_base
        self.methods: dict[int, ObjCMethod] = {}

    def pointer(self, address: int) -> int:
        """Get the address the pointer at `address` stands for, 0 when it is null or not of the image."""
        raw = self.image.pointer(address)
        return self.decode(raw) if raw else 0

    def read_class(self, class_address: int) -> None:
        self._read_class_methods(class_address, class_address, is_class_method=False)
        metaclass = self.pointer(class_address + CLASS_ISA)
        if metaclass:
            self._read_class_methods(metaclass, class_address, is_class_method=True)

    def _read_class_methods(self, address: int, class_address: int, is_class_method: bool) -> None:
        class_ro = self.pointer(address + CLASS_DATA) & CLASS_DATA_MASK
        if not class_ro:
            return
        methods = self.pointer(class_ro + CLASS_RO_BASE_METHODS)
        if methods & METHOD_LIST_LIST_FLAG:
            self._read_method_list_list(methods & ~METHOD_LIST_LIST_FLAG, class_address, is_class_method)
        else:
            self.read_method_list(methods, class_address, 0, is_class_method)

    def _read_method_list_list(self, address: int, class_address: int, is_class_method: bool) -> None:
        offset = self.image.offset(address, METHOD_LIST_LIST_HEADER.size)
        if offset is None:
            return
        entsize, count = METHOD_LIST_LIST_HEADER.unpack_from(self.image.data, offset)
        if entsize != METHOD_LIST_LIST_ENTRY.size:
            return
        for index in range(count):
            entry = address + METHOD_LIST_LIST_HEADER.size + index * entsize
            offset = self.image.offset(entry, entsize)
            if offset is None:
                return
            (packed,) = METHOD_LIST_LIST_ENTRY.unpack_from(self.image.data, offset)
            # The lists of the categories of other images are theirs to name
            self.read_method_list(entry + (packed >> METHOD_LIST_LIST_OFFSET_SHIFT), class_address, 0, is_class_method)

    def read_method_list(self, address: int, class_address: int, category_name: int, is_class_method: bool) -> None:
        offset = self.image.offset(address, METHOD_LIST_HEADER.size) if address else None
        if offset is None:
            return
        flags, count = METHOD_LIST_HEADER.unpack_from(self.image.data, offset)
        relative = bool(flags & METHOD_LIST_RELATIVE)
        layout = RELATIVE_METHOD if relative else POINTER_METHOD
        if flags & METHOD_LIST_ENTSIZE_MASK != layout.size:
            return
        first = address + METHOD_LIST_HEADER.size
        offset = self.image.offset(first, count * layout.size)
        if offset is None:
            return
        entries = layout.iter_unpack(self.image.data[offset : offset + count * layout.size])
        for index, (name, _types, imp) in enumerate(entries):
            entry = first + index * layout.size
            if not relative:
                selector = self.decode(name)
                imp = self.decode(imp)
            elif not imp:
                continue
            else:
                imp += entry + RELATIVE_METHOD_IMP
                if not flags & METHOD_LIST_DIRECT_SELECTORS:
                    selector = self.pointer(entry + name)
                elif self.selector_base is not None:
                    selector = self.selector_base + name
                else:
                    selector = 0
            if not imp or not selector:
                continue
            # A category of the image is read ahead of its class, whose list may repeat it
            self.methods.setdefault(imp, ObjCMethod(imp, class_address, category_name, selector, is_class_method))


def read_objc_methods(image: ImageData, decode: PointerDecoder, selector_base: Optional[int]) -> list[ObjCMethod]:
    """
    Get the methods the classes and categories of `image` implement, sorted by address.

    :param selector_base: The address the cache counts its selectors from, which names the methods
        of the lists holding direct selector offsets. Those are left out when it is unknown.
    """
    reader = _MethodReader(image, decode, selector_base)
    for raw in image.section_pointers("__objc_catlist"):
        category = decode(raw)
        class_address = reader.pointer(category + CATEGORY_CLASS)
        name = reader.pointer(category + CATEGORY_NAME)
        if not class_address or not name:
            continue
        for field, is_class_method in ((CATEGORY_INSTANCE_METHODS, False), (CATEGORY_CLASS_METHODS, True)):
            reader.read_method_list(reader.pointer(category + field), class_address, name, is_class_method)
    for raw in image.section_pointers("__objc_classlist"):
        reader.read_class(decode(raw))
    return sorted(reader.methods.values(), key=lambda method: method.imp)
