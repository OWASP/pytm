"""Regression tests for the --describe CLI option."""

import subprocess
import sys
from pathlib import Path

import pytest

from pytm import Controls


@pytest.mark.parametrize("target", ["Controls", "Server Controls"])
def test_describe_controls(target):
    result = subprocess.run(
        [sys.executable, "tm.py", "--describe", target],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "Controls class attributes:" in result.stdout
    controls_output = result.stdout.split("Controls class attributes:", 1)[1]
    for name, field in Controls.model_fields.items():
        assert f"  {name} " in controls_output
        assert f"default: {field.default!r}" in controls_output
        if field.description:
            assert field.description in controls_output
    for name in (
        "authenticatesSource",
        "authorizesSource",
        "checksInputBounds",
        "sanitizesInput",
        "usesStrongSessionIdentifiers",
        "validatesInput",
    ):
        assert Controls.model_fields[name].description
    if target == "Server Controls":
        assert "Server class attributes:" in result.stdout
        assert "sourceFiles" in result.stdout


def test_describe_unknown_class():
    result = subprocess.run(
        [sys.executable, "tm.py", "--describe", "UnknownClass"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "No such class to describe: UnknownClass" in result.stderr
