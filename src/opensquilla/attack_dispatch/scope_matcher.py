"""Deterministic scope safety for the attack dispatch model.

2026-06-14: Adopts the Claude-BugHunter ``engine/scope.py`` pattern
language so the ROE can be enforced in CODE rather than trusting the
LLM. The pattern forms are the same:

  example.com            -> the apex AND any subdomain
  *.example.com          -> any subdomain (NOT the bare apex)
  api.example.com        -> that exact host
  10.0.0.0/8             -> any IP in the CIDR (IPv4)
  re:^staging[0-9]+\\.example\\.com$  -> explicit regex (prefix re:)

Semantics preserved verbatim from the upstream reference:

* **Deny wins** — an out-of-scope match excludes even if an in-scope
  pattern also matches.
* **Default deny** — anything not matching an in-scope pattern is
  out of scope.
* **Suffix-confusion guard** — ``example.com.evil.com`` does NOT
  match ``example.com``. The matcher anchors on label boundaries.
* **Wildcard depth** — ``*.test.example.com`` matches ``a.test.example.com``
  but NOT ``test.example.com`` (the apex).

This module is the canonical scope gate used by:

* the W4 penetration specialist's scope_audit hook (raises
  ``ScopeViolation`` on out-of-scope contact),
* the W6 lateral-movement specialist's pivot-point filter,
* the W8 reporting-remediation specialist's finding inclusion check,
* the executor's pre-dispatch scope gate (rejects out-of-scope
  ``HandoffEnvelope`` payloads at dispatch time).

The module is **pure**: no I/O, no logging side effects, no LLM calls.
A self-test is included (run with ``python -m
opensquilla.attack_dispatch.scope_matcher``).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final
from urllib.parse import urlparse

# Public surface ------------------------------------------------------------

WILDCARD_PREFIX: Final[str] = "*."
REGEX_PREFIX: Final[str] = "re:"

# Reject reasons — stable strings so the W4/W6/W8 specialists can
# log them verbatim and the executor can index them.
REJECT_DENY_WINS: Final[str] = "matches an out-of-scope rule"
REJECT_DEFAULT_DENY: Final[str] = "matches no in-scope rule (default deny)"
REJECT_CANNOT_PARSE: Final[str] = "could not parse host"
REJECT_SUFFIX_CONFUSION: Final[str] = "suffix-confusion guard tripped"
REJECT_WILDCARD_TOO_SHALLOW: Final[str] = (
    "wildcard pattern requires a label deeper than the pattern base"
)


# Pattern parsing ----------------------------------------------------------


def _host_of(target: str) -> str:
    """Extract and normalize the host from a URL or hostname string.

    Strips scheme, port, path, and trailing dot. Returns "" on parse
    failure (caller treats empty as reject).
    """
    t = (target or "").strip()
    if "://" not in t:
        t = "//" + t
    host = (urlparse(t).hostname or "").lower().rstrip(".")
    return host


def _is_cidr(pattern: str) -> bool:
    """Heuristic: a pattern is a CIDR if it contains / and the rest is
    digits + dots (caller still validates via ipaddress)."""
    p = pattern.strip()
    if "/" not in p:
        return False
    head = p.split("/", 1)[0]
    return head.replace(".", "").isdigit()


def _match_single(pattern: str, host: str) -> bool:
    """True if ``host`` matches ``pattern`` (one pattern)."""
    p = (pattern or "").strip().lower()
    if not p or not host:
        return False
    if p.startswith(REGEX_PREFIX):
        try:
            return re.search(p[len(REGEX_PREFIX) :], host) is not None
        except re.error:
            return False
    if _is_cidr(p):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    if p.startswith(WILDCARD_PREFIX):
        # *.example.com -> match any subdomain of example.com, NOT the apex.
        base = p[len(WILDCARD_PREFIX) :]
        if not base:
            return False
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


# Public API ---------------------------------------------------------------


def in_scope(
    target: str,
    *,
    in_scope_patterns: list[str] | tuple[str, ...] = (),
    out_of_scope_patterns: list[str] | tuple[str, ...] = (),
) -> bool:
    """Return True iff ``target`` is in scope under the given rules.

    Deny-wins / default-deny semantics: an out-of-scope match
    excludes even if an in-scope pattern also matches. If no
    in-scope pattern matches, the target is rejected (default deny).
    """
    host = _host_of(target)
    if not host:
        return False
    if any(_match_single(p, host) for p in out_of_scope_patterns):
        return False
    return any(_match_single(p, host) for p in in_scope_patterns)


def reject_reason(
    target: str,
    *,
    in_scope_patterns: list[str] | tuple[str, ...] = (),
    out_of_scope_patterns: list[str] | tuple[str, ...] = (),
) -> str | None:
    """Return None if in scope, else a stable human-readable reason."""
    host = _host_of(target)
    if not host:
        return REJECT_CANNOT_PARSE
    if any(_match_single(p, host) for p in out_of_scope_patterns):
        return REJECT_DENY_WINS
    if not any(_match_single(p, host) for p in in_scope_patterns):
        return REJECT_DEFAULT_DENY
    return None


def extract_hosts_from_blob(blob: str) -> list[str]:
    """Pull every host out of a free-form string (URL, request, evidence).

    Used by the W4 specialist's ``scope_audit`` hook to scan a captured
    ``ExploitRequest`` / ``ExploitResponse`` for out-of-scope contact.
    Returns hosts in dedup-sorted order, lowercase.
    """
    if not blob:
        return []
    hosts: set[str] = set()
    # 1. http(s) URLs
    for m in re.finditer(r"https?://([A-Za-z0-9.\-]+)", blob):
        hosts.add(m.group(1).lower())
    # 2. proto://host:port (postgres, redis, mongodb, etc.)
    for m in re.finditer(
        r"(?:postgres|postgresql|redis|mongodb|mysql|amqp|amqps)://[^@/\s]+@?([A-Za-z0-9.\-]+)",
        blob,
    ):
        hosts.add(m.group(1).lower())
    return sorted(hosts)


def scope_audit_hosts(
    hosts: list[str],
    *,
    in_scope_patterns: list[str] | tuple[str, ...] = (),
    out_of_scope_patterns: list[str] | tuple[str, ...] = (),
) -> list[str]:
    """Given a list of hosts, return the ones that are out of scope.

    Used by the W4 / W6 / W8 specialists' scope-audit hook. Empty
    input -> empty result. The returned list is dedup-sorted.
    """
    return sorted(
        {
            h
            for h in hosts
            if h and reject_reason(
                h,
                in_scope_patterns=in_scope_patterns,
                out_of_scope_patterns=out_of_scope_patterns,
            )
            is not None
        }
    )


# Self-test -----------------------------------------------------------------


def _selftest() -> None:
    """Built-in self-test mirroring the upstream reference suite.

    Run with ``python -m opensquilla.attack_dispatch.scope_matcher``
    to verify the pattern matcher after any change. The test is
    pure (no I/O) and exits 0 on pass.
    """
    in_pats = [
        "example.com",
        "*.test.example.com",
        "10.0.0.0/8",
        "re:^lab[0-9]+\\.acme\\.io$",
    ]
    out_pats = ["admin.example.com", "internal.example.com"]

    def _ok(t: str) -> bool:
        return in_scope(t, in_scope_patterns=in_pats, out_of_scope_patterns=out_pats)

    def _reason(t: str) -> str | None:
        return reject_reason(
            t, in_scope_patterns=in_pats, out_of_scope_patterns=out_pats
        )

    # In-scope
    assert _ok("https://example.com/login")
    assert _ok("http://api.example.com/x")
    assert _ok("https://a.test.example.com")
    assert _ok("https://10.1.2.3:8080/")
    assert _ok("https://lab42.acme.io")
    # Bare-domain rule includes subdomains
    assert _ok("https://test.example.com")

    # Out-of-scope (deny wins)
    assert not _ok("https://admin.example.com")
    assert not _ok("https://internal.example.com/x")

    # Default deny
    assert not _ok("https://evil.com")

    # Suffix-confusion guard
    assert not _ok("https://notexample.com")
    assert not _ok("https://example.com.evil.com")
    assert not _ok("https://11.0.0.1")

    # Wildcard depth
    s2_in = ["*.test.example.com"]
    assert in_scope("https://a.test.example.com", in_scope_patterns=s2_in)
    assert not in_scope("https://test.example.com", in_scope_patterns=s2_in)

    # Reject reasons
    assert _reason("https://evil.com") == REJECT_DEFAULT_DENY
    assert _reason("https://admin.example.com") == REJECT_DENY_WINS
    assert _reason("https://example.com") is None
    assert _reason("") == REJECT_CANNOT_PARSE

    # extract_hosts_from_blob + scope_audit_hosts
    blob = (
        "POST https://admin.example.com/x HTTP/1.1\n"
        "Host: api.example.com\n"
        "GET postgres://u:p@db.internal:5432/x"
    )
    hosts = extract_hosts_from_blob(blob)
    # extract_hosts_from_blob only matches http(s):// and proto://user@host
    # forms; bare "Host:" headers are NOT picked up (use Burp / proxy
    # data for that). The blob above surfaces 2 hosts.
    assert "admin.example.com" in hosts
    assert "db.internal" in hosts
    audit = scope_audit_hosts(
        hosts, in_scope_patterns=in_pats, out_of_scope_patterns=out_pats
    )
    # admin.example.com matches out-of-scope rule
    assert "admin.example.com" in audit
    # db.internal -> default-deny (no in-scope rule)
    assert "db.internal" in audit
    # api.example.com would be in-scope via bare example.com, but
    # it is not present in the host set returned by the regex (we
    # need a full http(s):// form to pick it up).
    assert "api.example.com" not in audit

    # Sanity: a fully-qualified http URL surfaces its host.
    blob2 = "GET https://api.example.com/v1/x HTTP/1.1"
    hosts2 = extract_hosts_from_blob(blob2)
    assert "api.example.com" in hosts2
    audit2 = scope_audit_hosts(
        hosts2, in_scope_patterns=in_pats, out_of_scope_patterns=out_pats
    )
    assert audit2 == []  # api.example.com is in-scope via bare example.com

    print("scope_matcher self-test: PASS")


if __name__ == "__main__":
    _selftest()
