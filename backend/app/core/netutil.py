from ipaddress import ip_address, ip_network

# RFC 5737 / RFC 3849 documentation ranges count as "external" for detection so lab fixtures need no real addresses.
DOC_NETS = [ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def is_global_ip(ip: str) -> bool:
    """A routable public address. Multicast counts as global in the stdlib but is not a destination worth acting on."""
    a = ip_address(ip)
    return a.is_global and not a.is_multicast


def is_external(ip: str) -> bool:
    """Public, or a documentation range (detection and lab use). Never use this to decide what may leave the network."""
    a = ip_address(ip)
    return is_global_ip(ip) or any(a in n for n in DOC_NETS)
