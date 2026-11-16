"""Password hashing (stdlib scrypt) and opaque session tokens. No secret is ever stored in the clear."""
import base64
import hashlib
import hmac
import os
import re
import secrets

_N, _R, _P = 2**14, 8, 1  # 16 MiB per hash; the stored string carries its own parameters
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
MIN_PASSWORD, MAX_PASSWORD = 12, 128


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")  # verified when the user does not exist


def new_token() -> tuple[str, str]:
    """(token to give the client, sha256 to store). 256 random bits, so an unsalted hash is sufficient."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def check_password_policy(password: str) -> None:
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise ValueError(f"password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
