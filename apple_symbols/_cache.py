import os
from pathlib import Path


def default_cache_dir() -> Path:
    """Where indexes are kept between runs: ``$XDG_CACHE_HOME/apple-symbols``, ``~/.cache`` by default."""
    return Path(os.environ.get("XDG_CACHE_HOME") or "~/.cache").expanduser() / "apple-symbols"
