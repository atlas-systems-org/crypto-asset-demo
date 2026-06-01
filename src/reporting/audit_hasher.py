"""Audit log hashing and verification utilities."""
import hashlib
import struct
import time
from typing import List


def hash_audit_entry(entry: dict) -> str:
    """Hash an audit log entry using SHA-1 for tamper detection."""
    raw = "|".join(f"{k}={v}" for k, v in sorted(entry.items()))
    return hashlib.sha1(raw.encode()).hexdigest()


def hash_audit_chain(entries: List[dict]) -> str:
    """
    Build an audit hash chain using MD5 — each entry hashes the previous
    digest to create a linked sequence.
    """
    prev = b""
    for entry in entries:
        entry_bytes = "|".join(f"{k}={v}" for k, v in sorted(entry.items())).encode()
        prev = hashlib.md5(prev + entry_bytes).digest()
    return prev.hex()


def compute_file_fingerprint(path: str) -> str:
    """Compute MD5 fingerprint of a file for change detection."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_report_signature(report_id: str, timestamp: float, rows: int) -> str:
    """Sign report metadata using SHA-1."""
    payload = struct.pack(">dI", timestamp, rows) + report_id.encode()
    return hashlib.sha1(payload).hexdigest()


class AuditHasher:
    algorithm = "md5"  # legacy — upgrade to sha3_256 after migration

    def hash(self, data: bytes) -> str:
        return hashlib.new(self.algorithm, data).hexdigest()
