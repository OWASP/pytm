"""Documentation stays in step with the code."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def readme_threat_ids() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Currently supported threats", 1)[1]
    block = section.split("```text", 1)[1].split("```", 1)[0]
    return re.findall(r"^([A-Z]+\d+) - ", block, flags=re.MULTILINE)


def test_readme_lists_every_shipped_threat():
    shipped = [t["SID"] for t in json.loads(
        (ROOT / "pytm/threatlib/threats.json").read_text(encoding="utf-8")
    )]
    listed = readme_threat_ids()
    assert sorted(listed) == sorted(shipped)


@pytest.mark.parametrize("name", ["basic_template", "advanced_template", "reveal"])
def test_templates_reference_the_diagram_the_docs_produce(name):
    text = (ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8")
    assert "![](dfd.png)" in text
