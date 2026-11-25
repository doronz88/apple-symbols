# apple-symbols

Turn addresses of Apple devices into symbol names, in pure Python:

- **Userland**: against an Xcode `DeviceSupport` `Symbols` tree, which holds the dyld shared cache of a
  device split into one Mach-O per image.
- **Kernel**: against a kernelcache. Released kernelcaches are stripped, so naming their functions
  takes [`ipsw`](https://github.com/blacktop/ipsw) and its
  [symbolication signatures](https://github.com/blacktop/symbolicator).

It only reads files: getting the symbols of a device onto the host is up to tools such as Xcode or
`pymobiledevice3 developer fetch-symbols download`.

## Installation

```shell
python3 -m pip install apple-symbols
```

## Usage

```python
from apple_symbols import DeviceSupportSymbols, find_device_support_symbols

# ~/Library/Developer/Xcode/iOS DeviceSupport/iPhone17,3 26.4 (23E246)/Symbols
root = find_device_support_symbols("iPhone17,3", "23E246")
symbols = DeviceSupportSymbols.load(root)

# By the UUID of an image and an offset into it, as crash reports give
image = symbols.image_by_uuid("11111111-2222-3333-4444-555555555555")
print(symbols.symbolicate(image, image.vmaddr + 0x1234))  # (symbol name, offset from it) or None

# By an unslid address of the shared cache
image = symbols.image_by_address(0x180012345)
```

Apple ships some images of the shared cache with no local symbols at all. The functions of such an
image which implement Objective-C methods are named after its Objective-C metadata instead, e.g.
`-[APSigningAuthority setupWithCompletion:completion:]`; its other functions stay unnamed.

```python
from pathlib import Path

from apple_symbols import KernelSymbols

kernel = KernelSymbols.load(Path("kernelcache.release.iphone17"), signatures=Path("symbolicator/kernel"))
image = kernel.image_by_uuid("12121212-3434-5656-7878-909090909090")
print(image.name, kernel.symbolicate(image.text_exec + 0x1234))  # addresses are unslid
```

### From a symbolicator server

[symbolicator-server](https://github.com/netanelc305/symbolicator-server) holds the symbols of scanned
IPSWs. `pip install apple-symbols[remote]`; the classes have the same methods as the local ones
(`UserlandSymbolSource`, `KernelSymbolSource`):

```python
from symbolicator_server.client import SymbolicatorClient

from apple_symbols.remote import RemoteDeviceSymbols, RemoteKernelSymbols

client = SymbolicatorClient.connect("http://localhost:3993")
symbols = RemoteDeviceSymbols.for_build(client, "iPhone17,3", "23E246")
kernel = RemoteKernelSymbols.for_kernelcache(client, "12121212-3434-5656-7878-909090909090")
# a stackshot does not tell its kernelcache, only its kernel images
kernel = RemoteKernelSymbols.for_build(client, "iPhone17,3", "23E246", image_uuids)
```

Indexing a tree or a kernelcache takes a while, so the result is kept in
`$XDG_CACHE_HOME/apple-symbols` (`~/.cache/apple-symbols` by default) and reused until the files
change. Both `load()` methods take an `index_dir` to keep it elsewhere.

`apple_symbols.testing` builds minimal Mach-O files and filesets, for testing code which symbolicates.
