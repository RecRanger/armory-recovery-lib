import hashlib


def _sha256(bin_str: bytes) -> bytes:
    return hashlib.new("sha256", bin_str).digest()


def _sha256d(bin_str: bytes) -> bytes:
    """Double-SHA256"""
    return _sha256(_sha256(bin_str))


def compute_checksum(bin_str: bytes, num_bytes: int = 4):
    assert isinstance(bin_str, bytes)
    return _sha256d(bin_str)[:num_bytes]
