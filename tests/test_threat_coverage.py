"""Every threat in the library needs a positive and a negative test.

The negative tests (``test_threat_negatives_*.py``) show that a threat's
condition can be false. Without one, a condition that is always true still
passes the positive test, so a new threat must come with both.
"""

import ast
import json
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent
THREATS = TESTS.parent / "pytm" / "threatlib" / "threats.json"
SID = re.compile(r"[A-Z]{2,3}\d{2}")


def library_sids() -> set[str]:
    return {t["SID"] for t in json.loads(THREATS.read_text())}


def sids_in(path: Path) -> set[str]:
    """SIDs a test file refers to, as string literals or in test names."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if SID.fullmatch(node.value):
                found.add(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            found.update(SID.findall(node.name))
    return found


def test_library_has_threats() -> None:
    # Guards the checks below against passing because nothing was found.
    assert len(library_sids()) > 100


def test_every_threat_has_a_positive_test() -> None:
    positive = {
        name.removeprefix("test_")
        for name in (
            node.name
            for node in ast.walk(ast.parse((TESTS / "test_pytmfunc.py").read_text()))
            if isinstance(node, ast.FunctionDef)
        )
        if SID.fullmatch(name.removeprefix("test_"))
    }
    missing = sorted(library_sids() - positive)
    assert not missing, f"no test_<SID> in test_pytmfunc.py for: {missing}"


def test_every_threat_has_a_negative_test() -> None:
    negative: set[str] = set()
    files = sorted(TESTS.glob("test_threat_negatives_*.py"))
    assert files, "no tests/test_threat_negatives_*.py files found"
    for path in files:
        negative |= sids_in(path)
    missing = sorted(library_sids() - negative)
    assert not missing, (
        f"no negative test in tests/test_threat_negatives_*.py for: {missing}"
    )
