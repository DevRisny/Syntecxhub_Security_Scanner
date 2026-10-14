"""Safety gate: refuse to scan a target the user hasn't confirmed they are allowed to test."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class PermissionDenied(Exception):
    """Raised when a scan target was not confirmed as in-scope."""


def _is_private_host(hostname: str) -> bool:
    """True for localhost and private/loopback/link-local addresses (safe-by-default targets)."""
    if hostname in ("localhost",) or hostname.endswith(".localhost") or hostname.endswith(".local"):
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


def check_permission(url: str, *, allow_public: bool, assume_yes: bool, confirm) -> None:
    """Allow local/private targets automatically. For any public target, require both the
    --allow-public flag AND an explicit typed confirmation, mirroring the port scanner's gate.

    `confirm` is a callable (usually `input`) so tests can stub it without touching stdin.
    """
    host = urlparse(url).hostname
    if not host:
        raise PermissionDenied(f"could not parse a hostname from '{url}'")
    if _is_private_host(host):
        return
    if not allow_public:
        raise PermissionDenied(
            f"'{host}' looks like a public host. Only scan systems you own or are explicitly "
            f"authorized to test (e.g. a local DVWA/juice-shop instance). Re-run with "
            f"--allow-public if you have written permission for this target."
        )
    if assume_yes:
        return
    answer = confirm(
        f"Confirm you have explicit written permission to scan '{host}'. Type 'yes' to continue: "
    )
    if answer.strip().lower() != "yes":
        raise PermissionDenied("scan not confirmed")
