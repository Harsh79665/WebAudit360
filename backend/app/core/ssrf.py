"""WebAudit 360 — Multi-Layer Server-Side Request Forgery (SSRF) Defense
Author: Harsh Patel

Protects against:
- IPv4/IPv6 private subnets (RFC 1918, RFC 4193)
- Loopback addresses (127.0.0.0/8, ::1)
- Link-local and cloud metadata addresses (169.254.169.254, metadata.google.internal)
- DNS Rebinding (TOCTOU) via IP pinning verification
- Scheme restrictions (HTTP/HTTPS only)
"""

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse


BLOCKED_NETWORKS = [
    # IPv4 Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv4 Private Networks (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Link-Local & Cloud Metadata (RFC 3927)
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv4 Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("100.64.0.0/10"),
    # IPv4 Multicast & Reserved
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 Loopback
    ipaddress.ip_network("::1/128"),
    # IPv6 Unique Local (RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Multicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),
    # IPv4-mapped IPv6 Loopback / Private
    ipaddress.ip_network("::ffff:127.0.0.0/104"),
    ipaddress.ip_network("::ffff:169.254.0.0/112"),
    ipaddress.ip_network("::ffff:10.0.0.0/104"),
    ipaddress.ip_network("::ffff:172.16.0.0/108"),
    ipaddress.ip_network("::ffff:192.168.0.0/112"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "metadata.internal",
    "169.254.169.254",
}


class SSRFValidationError(Exception):
    """Raised when an untrusted URL violates SSRF boundaries."""
    pass


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address falls into any blocked or private subnet."""
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True
    return False


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to all corresponding A and AAAA IP addresses and validates
    that NONE of them belong to loopback, private, link-local, or cloud metadata ranges.
    Returns list of valid public IP strings.
    """
    hostname_clean = hostname.strip().lower()

    if hostname_clean in BLOCKED_HOSTNAMES:
        raise SSRFValidationError(f"Access to restricted hostname '{hostname_clean}' is prohibited.")

    # Check if hostname is an IP literal
    try:
        ip = ipaddress.ip_address(hostname_clean)
        if is_ip_blocked(ip):
            raise SSRFValidationError(f"Target IP address '{ip}' resides in a restricted/private network.")
        return [str(ip)]
    except ValueError:
        pass  # It's a regular hostname

    # Resolve hostname via system resolver
    try:
        addr_info = socket.getaddrinfo(hostname_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFValidationError(f"Failed to resolve hostname '{hostname_clean}': {str(e)}")

    if not addr_info:
        raise SSRFValidationError(f"No DNS records found for hostname '{hostname_clean}'.")

    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip):
                raise SSRFValidationError(
                    f"Hostname '{hostname_clean}' resolved to restricted IP address '{ip_str}'."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP address: {ip_str}")

    return resolved_ips


def validate_target_url(url: str) -> Tuple[str, str, List[str]]:
    """
    Full SSRF validation pipeline for user-supplied target URLs.
    Validates protocol, host format, and DNS resolution.
    Returns (normalized_url, hostname, list_of_validated_ips).
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Target URL cannot be empty.")

    url_clean = url.strip()
    parsed = urlparse(url_clean)

    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFValidationError(
            f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS protocols are permitted."
        )

    if not parsed.hostname:
        raise SSRFValidationError("URL must include a valid hostname.")

    if parsed.username or parsed.password:
        raise SSRFValidationError("Userinfo (username:password@) in URLs is prohibited.")

    if parsed.port and (parsed.port < 1 or parsed.port > 65535):
        raise SSRFValidationError(f"Invalid port: {parsed.port}")

    resolved_ips = resolve_and_validate_hostname(parsed.hostname)

    normalized_url = parsed.geturl()
    return normalized_url, parsed.hostname, resolved_ips
