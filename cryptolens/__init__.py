"""CryptoLens: finds cryptographic primitives in Python source code."""
from .detector import scan_source, scan_path

__all__ = ["scan_source", "scan_path"]