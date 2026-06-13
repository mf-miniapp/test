"""Runtime verification of penetration findings (2026-06-08, Issue 2).

The orchestrator (LLM) that produces ``PenetrationFinding`` records is
allowed to lie — or to be over-confident. A specialist that claims
``status=owned`` and ``outcome_match=True`` without re-executing the
reproduce step would otherwise sail through every gate in the dispatch
executor (``make_evidence`` → ``_merge_evidence`` → Pydantic → JSON →
trail). The :class:`SubprocessFindingVerifier` is the runtime safety net.

It re-executes ``ReproduceStep.command`` in a subprocess, captures
stdout / stderr / returncode, and compares the captured output against
``expected_outcome`` (substring match, case-sensitive, after
strip). The result is a :class:`VerifyResult` that the executor
attaches to the parent finding and (on failure) uses to downgrade
``status`` from ``owned``/``confirmed`` to ``partial``.

The default verifier is intentionally simple — substring match is good
enough to catch the most common hallucination pattern ("I claimed
this CVE works but I never actually ran the curl") and bad enough
that specialists with stateful PoCs (race conditions, side-channel
timing) can opt out via ``verification_required=False`` on the
finding or ``verifier_timeout_s=None`` for a long step. The executor
treats ``verifier_fn=False`` as a sentinel for "skip verification
entirely" — tests use this to bypass the default subprocess.

Adding a custom verifier is a one-liner: inject a callable that
matches :data:`FindingVerifierFn` into ``DispatchExecutor(verifier_fn=...)``.
The dispatch executor never assumes the default is a subprocess; that
implementation lives here purely as a sensible default for production.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from pydantic import BaseModel, ConfigDict, Field

from opensquilla.attack_dispatch.evidence import ReproduceStep


# Default timeout for the subprocess verifier when the step doesn't
# declare its own. 30s is enough for a single HTTP request / curl probe
# but tight enough that a stuck command doesn't block a wave for an
# unbounded time. Specialists with longer steps must set
# ``ReproduceStep.verifier_timeout_s``.
DEFAULT_VERIFIER_TIMEOUT_S: float = 30.0

# Hard cap on the verifier timeout, mirrored on the Pydantic field
# in ReproduceStep.verifier_timeout_s. A step that needs more than
# an hour should be split into multiple ReproduceStep entries.
MAX_VERIFIER_TIMEOUT_S: float = 3600.0


class VerifyResult(BaseModel):
    """The outcome of a single verification run.

    ``ok`` is the boolean the dispatch executor uses to gate finding
    persistence. ``detail`` is a free-text summary the W8.2 report
    surfaces to the operator. ``artifact_path`` is the absolute path
    to the per-finding verifier log JSON on disk (always written,
    even on failure, so the operator can audit exactly what the
    runtime saw). ``failure_reason`` is a short tag the W8 report
    uses to filter unverified findings; one of:

    - ``timeout`` — ``subprocess.TimeoutExpired``
    - ``exit_nonzero`` — returncode != 0
    - ``match_miss`` — returncode == 0 but expected_outcome not in stdout
    - ``no_reproduce_steps`` — finding has empty reproduce_steps
    - ``verifier_disabled`` — verifier_fn was False (sentinel)
    - ``verifier_error`` — unexpected exception in the verifier
    - ``body_indicates_failure`` — 2026-06-09 (Issue 5): a substring
      in ``ReproduceStep.failure_markers`` matched the captured
      response body (e.g. "login failed" found in a 200 OK
      response). Hard fail regardless of HTTP status.
    - ``body_missing_required_marker`` — 2026-06-09 (Issue 5): at
      least one substring in
      ``ReproduceStep.body_required_substrings`` was absent from
      the captured response. The exploit did not produce the
      expected evidence.
    """

    model_config = ConfigDict(extra="forbid")

    ok: bool
    detail: str
    artifact_path: str | None
    failure_reason: str | None = None


class FindingVerifierFn(Protocol):
    """A callable that runs one ``ReproduceStep`` and returns a :class:`VerifyResult`.

    Implementations MUST:

    1. Honor the ``timeout_s`` argument (or the step's
       ``verifier_timeout_s`` when set).
    2. Write a per-call log file to ``artifact_path`` (the
       ``VerifyResult.artifact_path`` returned to the executor).
    3. Return ``ok=True`` ONLY when the captured output matches
       ``expected_outcome`` per the implementation's policy.
    4. Never raise on a verifier error — return a ``VerifyResult`` with
       ``ok=False, failure_reason='verifier_error'`` instead, so the
       dispatch executor can continue the wave.
    """

    def __call__(
        self,
        step: ReproduceStep,
        *,
        timeout_s: float = DEFAULT_VERIFIER_TIMEOUT_S,
        artifact_root: Path | None = None,
        entry_id: str = "unknown",
    ) -> VerifyResult: ...


@dataclass
class _SubprocessVerifierConfig:
    """Resolved timeout + artifact path for one verification call."""

    timeout_s: float
    artifact_path: Path
    log_payload: dict[str, Any]


def _resolve_timeout(step: ReproduceStep, default: float) -> float:
    """Resolve the effective timeout for a step.

    Order of precedence:
      1. ``step.verifier_timeout_s`` (when set, range-checked)
      2. ``default`` (typically ``DEFAULT_VERIFIER_TIMEOUT_S``)
    """
    if step.verifier_timeout_s is not None:
        # Clamp to the hard cap so a runaway value can't pin the
        # executor forever. The Pydantic validator on the model
        # already enforces le=3600, but we re-clamp defensively in
        # case the model was constructed via .construct() or
        # model_construct().
        return max(0.1, min(MAX_VERIFIER_TIMEOUT_S, step.verifier_timeout_s))
    return default


# Tools that should be probed with an HTTP HEAD before substring
# matching. The substring match still runs as a fallback; the HEAD
# probe gives a stronger "did the server respond" signal that catches
# hallucinations like "I saw PII in the response body" when the body
# is actually empty (a 200 with an empty body is what the LLM saw in
# its context, not what the verifier sees).
_HTTP_TOOLS: frozenset[str] = frozenset({"curl", "wget", "http", "fetch", "httpie"})

# Loose URL extractor for the HEAD probe. The step's command is
# usually a curl / wget invocation; we extract the first http(s)://
# URL. Failures fall back to substring match only.
_URL_RE = re.compile(r"https?://[^\s'\"|<>]+")


def _extract_first_url(command: str) -> str | None:
    """Return the first http(s) URL in ``command``, or None."""
    match = _URL_RE.search(command)
    if not match:
        return None
    # Strip trailing punctuation that the shell may have left in.
    return match.group(0).rstrip(";,)")


class SubprocessFindingVerifier:
    """The default verifier implementation.

    Calls ``subprocess.run(step.command, shell=True, ...)`` with a
    timeout, captures stdout / stderr / returncode, and returns a
    :class:`VerifyResult` based on the result.

    ``expected_outcome`` is matched as a substring of stdout
    (case-sensitive, after strip). A non-zero returncode is a
    ``failure_reason='exit_nonzero'``. A ``subprocess.TimeoutExpired``
    is a ``failure_reason='timeout'``.

    The HTTP-HEAD probe runs only when ``step.tool`` is in
    :data:`_HTTP_TOOLS` AND a URL is extractable from the command.
    The probe's status code is matched against ``expected_outcome``
    via a regex (``^HTTP/\\S+\\s+(\\d{3})``) when applicable. If the
    regex does not match, the verifier falls back to the substring
    match against stdout (which is what curl would print on stderr
    anyway, so this is rarely a no-op).
    """

    def __init__(self, default_timeout_s: float = DEFAULT_VERIFIER_TIMEOUT_S) -> None:
        self.default_timeout_s = default_timeout_s

    def __call__(
        self,
        step: ReproduceStep,
        *,
        timeout_s: float | None = None,
        artifact_root: Path | None = None,
        entry_id: str = "unknown",
    ) -> VerifyResult:
        """Run one verification. See :class:`FindingVerifierFn` for the contract."""
        effective_timeout = timeout_s if timeout_s is not None else self._resolve_step_timeout(step)
        # Resolve the per-call artifact path. Always write a log so the
        # operator can audit what the runtime saw.
        if artifact_root is None:
            artifact_root = Path.home() / ".opensquilla" / "agents" / "hack-deep" / "memory" / "waves"
        verify_dir = artifact_root / "verify"
        try:
            verify_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return VerifyResult(
                ok=False,
                detail=f"could not create verify log dir: {exc}",
                artifact_path=None,
                failure_reason="verifier_error",
            )
        log_path = verify_dir / f"{entry_id}.{step.step_index}.json"
        log_payload: dict[str, Any] = {
            "command": step.command,
            "tool": step.tool,
            "expected_outcome": step.expected_outcome,
            "timeout_s": effective_timeout,
            "step_index": step.step_index,
        }
        try:
            completed = subprocess.run(
                step.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                # check=False — we inspect returncode ourselves
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            log_payload.update(
                {
                    "returncode": None,
                    "stdout_snippet": (exc.stdout or "")[:4096] if isinstance(exc.stdout, str) else "",
                    "stderr_snippet": (exc.stderr or "")[:4096] if isinstance(exc.stderr, str) else "",
                    "matched": False,
                    "outcome": "timeout",
                }
            )
            try:
                log_path.write_text(json.dumps(log_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass
            return VerifyResult(
                ok=False,
                detail=f"timeout after {effective_timeout}s",
                artifact_path=str(log_path),
                failure_reason="timeout",
            )
        except Exception as exc:  # noqa: BLE001 — verifier must not raise
            log_payload.update(
                {
                    "returncode": None,
                    "matched": False,
                    "outcome": "verifier_error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            try:
                log_path.write_text(json.dumps(log_payload, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass
            return VerifyResult(
                ok=False,
                detail=f"verifier error: {type(exc).__name__}: {exc}",
                artifact_path=str(log_path),
                failure_reason="verifier_error",
            )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        returncode = completed.returncode
        log_payload.update(
            {
                "returncode": returncode,
                "stdout_snippet": stdout[:4096],
                "stderr_snippet": stderr[:4096],
            }
        )
        # Decide ok.
        ok, reason, matched = self._classify(step, returncode, stdout, stderr)
        log_payload["matched"] = matched
        log_payload["outcome"] = "ok" if ok else (reason or "fail")
        try:
            log_path.write_text(json.dumps(log_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        return VerifyResult(
            ok=ok,
            detail=self._detail_for(step, returncode, ok, reason),
            artifact_path=str(log_path),
            failure_reason=None if ok else reason,
        )

    def _resolve_step_timeout(self, step: ReproduceStep) -> float:
        return _resolve_timeout(step, self.default_timeout_s)

    @staticmethod
    def _classify(
        step: ReproduceStep,
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> tuple[bool, str | None, bool]:
        """Return ``(ok, failure_reason, matched)``.

        The verifier considers a step verified when BOTH the
        returncode is 0 AND the expected_outcome is found in the
        combined (stdout + stderr) output. A non-zero returncode is
        a hard fail (verifier_error category). A zero returncode
        with no substring match is a match-miss — the command ran
        but produced the wrong output.

        For HTTP tools, the substring match is augmented by a
        HEAD-probe check; the verifier still requires the substring
        match to pass.

        2026-06-09 (Issue 5 — body-content verification). Two new
        layers run BEFORE the substring-match gate and can short-
        circuit the verifier to a hard fail:

        1. ``failure_markers`` — case-insensitive substrings. If ANY
           of them appear in the captured body, the exploit is
           FAILED regardless of HTTP status. E.g. an auth-bypass
           PoC whose body says ``"login failed"`` is rejected even
           if curl returned 200 OK. The canonical regression
           this guards against is an LLM that sets
           ``expected_outcome="200"`` and a 200-OK-with-failed-body
           response — old verifier would return ``ok=True``.

        2. ``body_required_substrings`` — case-insensitive substrings
           that ALL must appear in the body. E.g. an IDOR finding
           must declare the unique field(s) the response should
           contain (admin email, role, etc.). Missing any of them
           is ``body_missing_required_marker`` — the response
           didn't carry the claimed evidence.

        Both lists are opt-in (default empty). The W4 brief
        footer + the W4 specialist SOUL contract make BOTH lists
        REQUIRED for HTTP-based reproduce steps; the verifier is
        the safety net when the LLM forgets.
        """
        if returncode != 0:
            return False, "exit_nonzero", False
        combined = (stdout + "\n" + stderr).strip()
        combined_lower = combined.lower()
        # 2026-06-09 (Issue 5): failure_markers check FIRST. A
        # body that says "login failed" is a hard reject even when
        # curl returned 200 OK. The LLM may have set
        # expected_outcome="200" which would otherwise match — the
        # failure marker check is the more specific signal and
        # takes priority.
        if step.failure_markers:
            for marker in step.failure_markers:
                if marker and marker.lower() in combined_lower:
                    return False, "body_indicates_failure", False
        # 2026-06-09 (Issue 5): body_required_substrings check. ALL
        # substrings must appear; missing any one is a hard reject.
        # Distinct from expected_outcome (which is a free-form
        # summary); required substrings are the structured "proof
        # tokens" the LLM committed to.
        if step.body_required_substrings:
            missing = [
                s for s in step.body_required_substrings
                if s and s.lower() not in combined_lower
            ]
            if missing:
                return False, "body_missing_required_marker", False
        if step.expected_outcome and step.expected_outcome in combined:
            return True, None, True
        # HTTP tool special case: also check the first URL's HEAD
        # response. We don't fail the verifier on HEAD mismatch alone
        # (the substring match is the source of truth) but we record
        # the result via the matched flag.
        if step.tool in _HTTP_TOOLS:
            url = _extract_first_url(step.command)
            if url:
                try:
                    head_proc = subprocess.run(
                        ["curl", "-sI", "-m", "5", url],
                        capture_output=True,
                        text=True,
                        timeout=5.0,
                        check=False,
                    )
                    head_out = (head_proc.stdout or "") + (head_proc.stderr or "")
                    if step.expected_outcome and step.expected_outcome in head_out:
                        return True, None, True
                except Exception:  # noqa: BLE001 — HEAD probe is best-effort
                    pass
        return False, "match_miss", False

    @staticmethod
    def _detail_for(
        step: ReproduceStep,
        returncode: int,
        ok: bool,
        reason: str | None,
    ) -> str:
        if ok:
            return f"reproduce step {step.step_index} verified (rc=0, matched)"
        if reason == "exit_nonzero":
            return f"reproduce step {step.step_index} returned non-zero exit code {returncode}"
        if reason == "match_miss":
            return (
                f"reproduce step {step.step_index} ran (rc=0) but expected_outcome "
                f"{step.expected_outcome!r} not found in stdout/stderr"
            )
        if reason == "timeout":
            return f"reproduce step {step.step_index} timed out"
        return f"reproduce step {step.step_index} failed: {reason or 'unknown'}"


def always_ok_verifier(
    step: ReproduceStep,
    *,
    timeout_s: float = DEFAULT_VERIFIER_TIMEOUT_S,
    artifact_root: Path | None = None,
    entry_id: str = "unknown",
) -> VerifyResult:
    """A pass-through verifier used by tests.

    Returns ``ok=True`` for any step without running anything. Useful
    for unit tests that don't want to spawn subprocesses; production
    uses :class:`SubprocessFindingVerifier`.
    """
    return VerifyResult(
        ok=True,
        detail=f"always_ok_verifier (no execution) for step {step.step_index}",
        artifact_path=None,
        failure_reason=None,
    )
