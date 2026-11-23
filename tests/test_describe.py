"""Regression tests for the --describe CLI option."""

import subprocess
import sys
from pathlib import Path

import pytest

import pytm
from pytm import Assumption, Controls


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


def test_describe_assumption():
    result = subprocess.run(
        [sys.executable, "tm.py", "--describe", "Assumption"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Assumption class attributes:" in result.stdout
    for name, field in Assumption.model_fields.items():
        assert f"  {name} " in result.stdout
        assert field.description in result.stdout


def test_describe_accepts_every_exported_class():
    # var is the legacy attribute descriptor, not a model class
    exported = [
        name
        for name in pytm.__all__
        if isinstance(getattr(pytm, name), type) and name != "var"
    ]
    result = subprocess.run(
        [sys.executable, "tm.py", "--describe", " ".join(exported)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    for name in exported:
        assert f"{name} class attributes:" in result.stdout
