"""Threat taxonomy helpers shared by Threat and Finding."""

import re

STRIDE = (
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
)
UNASSIGNED = "unassigned"
IMPACT_LEVELS = ("negligible", "low", "moderate", "major", "catastrophic")

_CAPEC = re.compile(r"capec\.mitre\.org/data/definitions/(\d+)|\bCAPEC-(\d+)", re.I)
_CWE = re.compile(r"cwe\.mitre\.org/data/definitions/(\d+)|\bCWE-(\d+)", re.I)


def _choice(value: str, allowed: tuple, label: str) -> str:
    """Normalise ``value`` ("Information Disclosure") and check it is allowed."""
    normalised = re.sub(r"[\s_]+", "-", (value or "").strip().lower())
    if normalised and normalised not in allowed:
        raise ValueError(f"{label} must be one of: {', '.join(allowed)}")
    return normalised


def check_stride(value: str) -> str:
    """Validate a STRIDE category; empty means ``"unassigned"``."""
    return _choice(value, (*STRIDE, UNASSIGNED), "stride") or UNASSIGNED


def check_impact(value: str) -> str:
    """Validate a TM-BOM impact level."""
    return _choice(value, IMPACT_LEVELS, "impact")


def capec_ids(references: str) -> list[int]:
    """CAPEC ids mentioned in a references string, in order, without repeats."""
    return _ids(_CAPEC, references)


def cwe_ids(references: str) -> list[int]:
    """CWE ids mentioned in a references string, in order, without repeats."""
    return _ids(_CWE, references)


def _ids(pattern: "re.Pattern[str]", text: str) -> list[int]:
    found = [int(a or b) for a, b in pattern.findall(text or "")]
    return list(dict.fromkeys(found))
