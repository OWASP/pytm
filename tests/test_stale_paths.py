"""CLI staleness checks use the path of the invoked model once."""

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "model_name,absolute",
    [
        ("models/model.py", False),
        ("./models/model.py", False),
        ("nested/models/model.py", False),
        ("model directory/model.py", False),
        ("model.py", False),
        ("models/model.py", True),
    ],
)
def test_stale_days_reads_invoked_model(tmp_path, model_name, absolute):
    model = tmp_path / model_name
    model.parent.mkdir(parents=True, exist_ok=True)
    model.write_text(
        "from pytm import TM, Server\n"
        "tm = TM('Staleness')\n"
        "Server('API', sourceFiles=['source.py'])\n"
        "tm.process()\n"
    )
    source = model.parent / "source.py"
    source.write_text("# Source newer than its model\n")
    os.utime(model, (1_700_000_000, 1_700_000_000))
    os.utime(source, (1_700_259_200, 1_700_259_200))
    invocation = str(model) if absolute else model_name

    result = subprocess.run(
        [sys.executable, invocation, "--stale_days", "2"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stderr == ""
    assert "[ERROR]" not in result.stdout
    assert "This model is 3 days older than" in result.stdout
    assert "source.py" in result.stdout


def test_stale_days_ignores_source_less_than_a_day_older(tmp_path):
    model = tmp_path / "model.py"
    model.write_text(
        "from pytm import TM, Server\n"
        "tm = TM('Staleness')\n"
        "Server('API', sourceFiles=['source.py'])\n"
        "tm.process()\n"
    )
    source = tmp_path / "source.py"
    source.write_text("# Source one minute older than its model\n")
    os.utime(model, (1_700_000_000, 1_700_000_000))
    os.utime(source, (1_699_999_940, 1_699_999_940))

    result = subprocess.run(
        [sys.executable, "model.py", "--stale_days", "1"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stderr == ""
    assert "Checking for code 1 days older than this model." in result.stdout
    assert "days newer than" not in result.stdout
    assert "days older than source.py" not in result.stdout
