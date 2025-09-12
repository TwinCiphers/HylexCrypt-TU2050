from . import cli, core
__all__ = ["cli", "core"]

"""
HylexCrypt - The Ultimate 2050 - stego + crypto CLI tool
Package initializer.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    # Try to use package metadata (from pyproject.toml)
    __version__ = version("HylexCrypt")
except PackageNotFoundError:
    # Fallback if not installed as a package
    try:
        from ._version import __version__  # type: ignore
    except Exception:
        __version__ = "0+unknown"

__all__ = ["__version__"]
