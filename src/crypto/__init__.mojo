"""Cryptographic primitives in pure Mojo, for authentication protocols
(PostgreSQL's SCRAM-SHA-256 and legacy MD5; docs/pg.md): SHA-256, MD5,
HMAC-SHA-256, PBKDF2-HMAC-SHA-256 and a constant-time comparison. Scalar
code checked against Python's hashlib and the RFC vectors; not meant for
bulk hashing, and no ciphers (TLS is out of scope for now)."""

from .compare import equal_constant_time
from .hmac import HmacSha256, hmac_sha256, pbkdf2_hmac_sha256
from .md5 import Md5, md5
from .sha256 import Sha256, sha256
