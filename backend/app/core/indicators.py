import re
from ipaddress import ip_address

_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def normalize_indicator(raw: str) -> tuple[str, str]:
    """(kind, canonical value) for an IPv4/IPv6 address, domain name or SHA-256 hash; ValueError for anything else.
    The value ends up in provider URLs, so nothing but these three shapes is accepted: no paths, ports, spaces or scope ids."""
    v = raw.strip()
    if "%" not in v:
        try:
            return "ip", str(ip_address(v))
        except ValueError:
            pass
    v = v.lower().rstrip(".")
    if _SHA256.match(v):
        return "sha256", v
    if _DOMAIN.match(v):
        return "domain", v
    raise ValueError("indicator must be an IPv4/IPv6 address, a domain name or a SHA-256 hash")
