"""
safety.py
Lab-only safety guard for XXEProbe.

RULE: XXEProbe must never be pointed at a system you do not own or do not
have written permission to test. By default this tool REFUSES any target
whose hostname does not resolve to a local / loopback / private-lab
address. The guard can only be bypassed with an explicit flag AND an
explicit typed confirmation, so there is no accidental "oops I scanned
a real site" moment.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(Exception):
    """Raised when a target fails the lab-only safety check."""


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def is_local_target(url: str) -> bool:
    """Return True if the URL's host resolves to a loopback/private address."""
    host = urlparse(url).hostname
    if not host:
        return False
    if host.lower() in ("localhost",):
        return True
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    return all(_is_private_or_loopback(ip) for ip in resolved_ips)


def enforce_lab_only(url: str, allow_remote: bool, confirmed_phrase: str) -> None:
    """
    Raise UnsafeTargetError unless:
      - the target is local/private (normal case), OR
      - the caller explicitly passed --allow-remote AND typed the exact
        confirmation phrase proving they have written permission.
    """
    if is_local_target(url):
        return

    required_phrase = "I OWN THIS TARGET OR HAVE WRITTEN PERMISSION"
    if allow_remote and confirmed_phrase.strip() == required_phrase:
        return

    raise UnsafeTargetError(
        f"Refusing to probe '{url}': it is not a local/lab address.\n"
        f"XXEProbe only tests systems you own or are explicitly authorised "
        f"to test (see PECA 2016, Pakistan).\n"
        f"If this really is your own authorised lab target, re-run with:\n"
        f'  --allow-remote --confirm "{required_phrase}"\n'
    )
