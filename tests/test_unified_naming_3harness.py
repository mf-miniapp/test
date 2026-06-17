"""Tests for the 2026-06-15 unified-naming + 3-harness-split refactor.

Asserts:

1. The 3 owner LLM packages exist with hyphenated names:
   opensquilla.agents.hack-deep
   opensquilla.agents.hack-deep-find
   opensquilla.agents.hack-deep-ex
2. The old underscore-named packages do NOT exist:
   opensquilla.agents.hack_deep
   opensquilla.agents.hack_deep_find
3. Each package exposes ``SOUL_BODY`` and ``ATTRIBUTION_BODY`` as
   non-empty strings.
4. The 13 v4 hack-deep-find specialist subpackages exist with hyphenated
   names: domain-expander, port-scanner, service-fingerprint,
   endpoint-crawler, storage-discoverer, webapp-discoverer,
   component-detector, api-surface-mapper, content-classifier,
   osint-collector, secret-scanner, surface-aggregator, leaf-verifier.
   (v3 16-specialist list was consolidated in 2026-06-17 by 3-way merge
   + 2 NEW; the 8 retired v3 names remain on disk for historical
   reference but are NOT exposed via the specialists package.)
5. The specialists package's __init__ exposes BOTH the hyphenated
   attribute name (e.g. ``endpoint-crawler``) and the snake_case
   alias (``endpoint_crawler``) for backward compat.
6. ``attack_dispatch.waves`` correctly tags every wave with one
   of the 3 owner_agent values.
7. ``owner_of_wave`` / ``check_authorization`` work correctly.
8. The Typed Envelope (HANDOFF / RESULT marker) is unchanged.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Package existence + naming
# ---------------------------------------------------------------------------


PACKAGES = (
    "opensquilla.agents.hack-deep",
    "opensquilla.agents.hack-deep-find",
    "opensquilla.agents.hack-deep-ex",
)


@pytest.mark.parametrize("pkg_name", PACKAGES)
def test_package_exists(pkg_name: str) -> None:
    mod = importlib.import_module(pkg_name)
    assert mod is not None
    # Every package must expose the 3-item contract surface
    assert hasattr(mod, "SOUL_BODY")
    assert hasattr(mod, "ATTRIBUTION_BODY")
    assert hasattr(mod, "reload")
    assert len(mod.SOUL_BODY) > 1000
    assert len(mod.ATTRIBUTION_BODY) > 200


def test_old_underscore_packages_gone() -> None:
    """The old hack_deep* names must NOT be importable."""
    for old in (
        "opensquilla.agents.hack_deep",
        "opensquilla.agents.hack_deep_find",
        "opensquilla.agents.hack_deep_ex",
    ):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(old)


# ---------------------------------------------------------------------------
# Specialist subpackages
# ---------------------------------------------------------------------------


SPECIALISTS = (
    # v4 active (13). v3 retired names
    # (subdomain-discoverer, ip-resolver, seed-expander, api-surface,
    #  parameter-extract, static-asset, auth-mapper, cookie-header)
    # are NOT in this tuple; their directories remain on disk for
    # historical reference but the package no longer exposes them.
    "domain-expander",
    "port-scanner",
    "service-fingerprint",
    "endpoint-crawler",
    "storage-discoverer",
    "webapp-discoverer",
    "component-detector",
    "api-surface-mapper",
    "content-classifier",
    "osint-collector",
    "secret-scanner",
    "surface-aggregator",
    "leaf-verifier",
)


@pytest.mark.parametrize("specialist", SPECIALISTS)
def test_specialist_dir_exists(specialist: str) -> None:
    p = Path("src/opensquilla/agents/hack-deep-find/specialists") / specialist
    assert p.is_dir(), f"missing specialist dir: {p}"
    assert (p / "SOUL_BODY.md").is_file(), f"missing SOUL_BODY.md in {p}"
    assert (p / "__init__.py").is_file(), f"missing __init__.py in {p}"


def test_old_underscore_specialist_dirs_gone() -> None:
    base = Path("src/opensquilla/agents/hack-deep-find/specialists")
    for old in (
        "subdomain_discoverer",
        "ip_resolver",
        "port_scanner",
        "service_fingerprint",
        "endpoint_crawler",
        "leaf_verifier",
    ):
        assert not (base / old).exists(), f"stale dir: {old}"


def test_specialists_package_exposes_hyphen_and_alias() -> None:
    pkg = importlib.import_module(
        "opensquilla.agents.hack-deep-find.specialists"
    )
    # Hyphenated attribute names (new convention)
    for specialist in SPECIALISTS:
        assert hasattr(pkg, specialist), f"missing {specialist} attribute"
        mod = getattr(pkg, specialist)
        assert hasattr(mod, "SOUL_BODY")
        assert len(mod.SOUL_BODY) > 200
    # Snake-case aliases (backward compat)
    for snake, hyphen in (
        ("domain_expander", "domain-expander"),
        ("port_scanner", "port-scanner"),
        ("service_fingerprint", "service-fingerprint"),
        ("endpoint_crawler", "endpoint-crawler"),
        ("storage_discoverer", "storage-discoverer"),
        ("webapp_discoverer", "webapp-discoverer"),
        ("component_detector", "component-detector"),
        ("api_surface_mapper", "api-surface-mapper"),
        ("content_classifier", "content-classifier"),
        ("osint_collector", "osint-collector"),
        ("secret_scanner", "secret-scanner"),
        ("surface_aggregator", "surface-aggregator"),
        ("leaf_verifier", "leaf-verifier"),
    ):
        assert hasattr(pkg, snake), f"missing {snake} alias"
        # Both names should resolve to the same module object
        assert getattr(pkg, snake) is getattr(pkg, hyphen)


# ---------------------------------------------------------------------------
# 3-harness split: owner_agent per wave
# ---------------------------------------------------------------------------


def test_waves_have_owner_agent() -> None:
    from opensquilla.attack_dispatch.waves import WAVES, OwnerAgent

    valid = set(OwnerAgent.__args__)
    for wave_id, spec in WAVES.items():
        assert spec.owner_agent in valid, f"{wave_id}: invalid owner {spec.owner_agent!r}"


def test_owner_split() -> None:
    """The 15 waves split cleanly across the 3 owners per the
    2026-06-15 refactor:
      hack-deep-find : W0.5 W0.6 W1 W1.5 W1.5c W2.5 W3.5 (7 waves)
      hack-deep      : W0 W2 W3 W4              (4 waves)
      hack-deep-ex   : W5 W6 W7 W8              (4 waves)
    """
    from opensquilla.attack_dispatch.waves import WAVES

    by_owner = {"hack-deep-find": [], "hack-deep": [], "hack-deep-ex": []}
    for wave_id, spec in WAVES.items():
        by_owner[spec.owner_agent].append(wave_id)

    assert set(by_owner["hack-deep-find"]) == {
        "W0.5", "W0.6", "W1", "W1.5", "W1.5c", "W2.5", "W3.5"
    }
    assert set(by_owner["hack-deep"]) == {"W0", "W2", "W3", "W4"}
    assert set(by_owner["hack-deep-ex"]) == {"W5", "W6", "W7", "W8"}


def test_owner_of_wave_for_drill_in() -> None:
    """Drill-in slots inherit parent wave's owner."""
    from opensquilla.attack_dispatch.waves import owner_of_wave

    # W4.5a is a W4 drill-in -> owner = hack-deep
    assert owner_of_wave("W4.5a") == "hack-deep"
    # W6.5a is a W6 drill-in -> owner = hack-deep-ex
    assert owner_of_wave("W6.5a") == "hack-deep-ex"
    # W1.6a is a W1 drill-in -> owner = hack-deep-find
    assert owner_of_wave("W1.6a") == "hack-deep-find"


def test_check_authorization_blocks_cross_owner_spawns() -> None:
    from opensquilla.attack_dispatch.waves import (
        check_authorization,
        UnauthorizedOwnerError,
    )

    # hack-deep-find cannot drive W5 (post-exploit)
    with pytest.raises(UnauthorizedOwnerError):
        check_authorization("W5", "hack-deep-find")
    # hack-deep cannot drive W5 either
    with pytest.raises(UnauthorizedOwnerError):
        check_authorization("W5", "hack-deep")
    # Only hack-deep-ex can drive W5
    check_authorization("W5", "hack-deep-ex")

    # hack-deep cannot drive W0.5 (asset discovery)
    with pytest.raises(UnauthorizedOwnerError):
        check_authorization("W0.5", "hack-deep")
    # hack-deep-ex cannot drive W4 (attack)
    with pytest.raises(UnauthorizedOwnerError):
        check_authorization("W4", "hack-deep-ex")


# ---------------------------------------------------------------------------
# Typed Envelope untouched
# ---------------------------------------------------------------------------


def test_envelope_regex_unchanged() -> None:
    """The Typed Envelope is unchanged by the 3-harness split."""
    from opensquilla.attack_dispatch.envelope import (
        RESULT_REGEX,
        parse_envelope,
    )

    # A canonical envelope header
    text = (
        "HANDOFF W5.privilege-escalation.1 | "
        "deps=POST-EXPLOIT-COMPLETE.deep.1 | schema=privesc-v1 | eta=300"
    )
    env = parse_envelope(text)
    assert env is not None
    assert env.handoff_id == "W5.privilege-escalation.1"
    assert env.evidence_schema == "privesc-v1"

    # Result Marker also unchanged
    marker_line = (
        "schema: privesc-v1 | phase: evidence-collection | "
        "wave: 5/8 | deps: POST-EXPLOIT-COMPLETE.deep.1"
    )
    assert RESULT_REGEX.search(marker_line) is not None
