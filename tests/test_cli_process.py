"""CLI argument parsing and ``TM.process`` dispatch behaviour."""

import json
import os
import re
import sys
from pathlib import Path

import pytest

from pytm import TM, Actor, Boundary, Dataflow, Datastore, Server, pytm
from pytm.pytm import var

MODEL_SOURCE = "src.py"


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()
    yield
    TM.reset()


def build_model(levels: bool = False) -> TM:
    """Create a small three-element model with two flows."""
    tm = TM("Demo", description="demo description", isOrdered=True)
    tm.assumptions = ["only trusted users"]
    net = Boundary("Net")
    user = Actor("User", inBoundary=net)
    web = Server("Web", sourceFiles=[MODEL_SOURCE])
    db = Datastore("DB")
    if levels:
        user.levels = {0}
        web.levels = {0, 1}
        db.levels = {1}
    Dataflow(user, web, "Login")
    Dataflow(web, db, "Query")
    return tm


def run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *args: str,
    levels: bool = False,
) -> TM:
    """Build the model and run ``process`` as if invoked from the command line."""
    script = tmp_path / "model.py"
    script.write_text("# model\n")
    monkeypatch.setattr(sys, "argv", [str(script), *args])
    tm = build_model(levels=levels)
    tm.process()
    return tm


class TestGetArgs:
    def parse(self, monkeypatch: pytest.MonkeyPatch, *args: str):
        monkeypatch.setattr(sys, "argv", ["model.py", *args])
        return pytm.get_args()

    def test_defaults(self, monkeypatch):
        ns = self.parse(monkeypatch)
        assert vars(ns) == {
            "debug": False,
            "dfd": False,
            "report": None,
            "exclude": None,
            "seq": False,
            "list": False,
            "colormap": False,
            "describe": None,
            "list_elements": False,
            "json": None,
            "levels": None,
            "stale_days": None,
        }

    def test_each_flag(self, monkeypatch):
        ns = self.parse(
            monkeypatch,
            "--debug",
            "--dfd",
            "--report",
            "t.md",
            "--exclude",
            "INP01,AA01",
            "--seq",
            "--list",
            "--colormap",
            "--describe",
            "Server Actor",
            "--list-elements",
            "--json",
            "out.json",
            "--levels",
            "0",
            "2",
            "--stale_days",
            "7",
        )
        assert ns.debug and ns.dfd and ns.seq and ns.list and ns.colormap
        assert ns.list_elements is True
        assert ns.report == "t.md"
        assert ns.exclude == "INP01,AA01"
        assert ns.describe == "Server Actor"
        assert ns.json == "out.json"
        assert ns.levels == [0, 2]
        assert ns.stale_days == 7

    @pytest.mark.parametrize(
        "args",
        [["--bogus"], ["--stale_days", "soon"], ["--levels", "a"], ["--json"]],
    )
    def test_invalid_arguments_exit_with_usage_error(self, monkeypatch, args, capsys):
        with pytest.raises(SystemExit) as exc:
            self.parse(monkeypatch, *args)
        assert exc.value.code == 2
        assert "usage:" in capsys.readouterr().err


class TestOutputModes:
    def test_no_flags_prints_nothing(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path)
        assert capsys.readouterr().out == ""

    def test_dfd(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--dfd")
        out = capsys.readouterr().out
        assert out.startswith("digraph tm {")
        assert "label = <<i>Net</i>>" in out
        for name in ("User", "Web", "DB", "Login", "Query"):
            assert name in out
        assert "darkgreen" not in out

    def test_dfd_colormap_colours_by_risk(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--dfd", "--colormap")
        out = capsys.readouterr().out
        assert 'fillcolor="#' in out
        assert "style=filled" in out

    def test_dfd_levels_filters_elements(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--dfd", "--levels", "1", levels=True)
        out = capsys.readouterr().out
        assert "Web" in out and "DB" in out and "Query" in out
        assert "User" not in out and "Login" not in out

    def test_seq(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--seq")
        lines = capsys.readouterr().out.splitlines()
        assert lines[0] == "@startuml"
        assert lines[-1] == "@enduml"
        assert any(
            line.endswith(": (1) Login") and line.split()[0].startswith("actor_User")
            for line in lines
        )
        assert any(line.endswith(": (2) Query") for line in lines)

    def test_json_written_after_resolve(self, monkeypatch, tmp_path, capsys):
        target = tmp_path / "out.json"
        run(monkeypatch, tmp_path, "--json", str(target))
        assert capsys.readouterr().out == ""
        data = json.loads(target.read_text(encoding="utf8"))
        assert data["name"] == "Demo"
        assert data["description"] == "demo description"
        assert [a["name"] for a in data["actors"]] == ["User"]
        assert {f["name"] for f in data["flows"]} == {"Login", "Query"}
        assert data["findings"], "resolve() must run before serialising"
        assert {f["target"] for f in data["findings"]} <= {
            "User",
            "Web",
            "DB",
            "Login",
            "Query",
        }

    def test_json_unwritable_path_exits_127(self, monkeypatch, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            run(monkeypatch, tmp_path, "--json", str(tmp_path))
        assert exc.value.code == 127
        err = capsys.readouterr().err
        assert err.startswith("Failed to execute\n")
        assert f"while trying to write to the result file ({tmp_path})" in err

    def test_report_renders_template(self, monkeypatch, tmp_path, capsys):
        template = tmp_path / "t.md"
        template.write_text("# {tm.name}\n{tm.description}\n")
        run(monkeypatch, tmp_path, "--report", str(template))
        assert capsys.readouterr().out.splitlines()[:2] == [
            "# Demo",
            "demo description",
        ]

    def test_list_prints_every_loaded_threat(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--list")
        lines = capsys.readouterr().out.splitlines()
        assert lines == [f"{t.id} - {t.description}" for t in TM._threats]
        assert lines[0] == "INP01 - Buffer Overflow via Environment Variables"

    def test_list_elements(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--list-elements")
        out = capsys.readouterr().out
        # Docstrings can contain "Attributes:" too (Python 3.13 dedents them),
        # so only accept the header that is followed by a printed entry.
        elements, attributes = re.split(r"\n\nAttributes:\n(?=\w+ +-- )", out)
        assert elements.startswith("Elements:\n")
        element_names = [
            line.split(" -- ")[0].strip()
            for line in elements.splitlines()
            if " -- " in line
        ]
        assert element_names == sorted(element_names)
        assert {"Actor", "Server", "Dataflow", "Boundary"} <= set(element_names)
        for name in ("Data", "Action", "Lifetime", "Classification"):
            assert any(line.startswith(f"{name} ") for line in attributes.splitlines())

    def test_describe_multiple_classes(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--describe", "Lifetime Datastore")
        out = capsys.readouterr().out
        assert "Lifetime class attributes:\n  NONE\n" in out
        assert "Datastore class attributes:\n" in out
        assert out.index("Lifetime class") < out.index("Datastore class")
        assert "  isSQL" in out

    def test_describe_non_model_class_lists_plain_attributes(
        self, monkeypatch, tmp_path, capsys
    ):
        run(monkeypatch, tmp_path, "--describe", "UIError")
        assert capsys.readouterr().out == "UIError class attributes:\n  args\n\n"

    def test_describe_marks_required_and_defaults(self, monkeypatch, tmp_path, capsys):
        run(monkeypatch, tmp_path, "--describe", "Finding")
        out = capsys.readouterr().out
        assert "  condition    Threat condition\n               required\n" in out
        assert "  cvss         The CVSS score and/or vector\n" in out
        assert "               default: ''\n" in out

    def test_describe_unknown_exits_1(self, monkeypatch, tmp_path, caplog):
        with pytest.raises(SystemExit) as exc:
            run(monkeypatch, tmp_path, "--describe", "Server Nope")
        assert exc.value.code == 1
        assert "No such class to describe: Nope" in caplog.text

    def test_debug_sets_logger_level(self, monkeypatch, tmp_path):
        import logging

        from pytm.tm import logger

        logger.setLevel(logging.INFO)
        run(monkeypatch, tmp_path, "--debug")
        assert logger.level == logging.DEBUG


class TestExclude:
    @staticmethod
    def finding_ids(tm: TM) -> set[str]:
        return {f.threat_id for f in tm.findings}

    def test_exclude_removes_given_sids(self, monkeypatch, tmp_path):
        baseline = run(monkeypatch, tmp_path, "--json", str(tmp_path / "a.json"))
        before = self.finding_ids(baseline)
        assert {"INP03", "AA01"} <= before
        TM.reset()
        tm = run(
            monkeypatch,
            tmp_path,
            "--exclude",
            "INP03, AA01",
            "--json",
            str(tmp_path / "b.json"),
        )
        after = self.finding_ids(tm)
        assert after == before - {"INP03", "AA01"}
        assert TM._threatsExcluded == ["INP03", "AA01"]

    def test_exclude_ignores_empty_tokens(self, monkeypatch, tmp_path):
        run(monkeypatch, tmp_path, "--exclude", ",INP03,, ")
        assert TM._threatsExcluded == ["INP03"]

    def test_excluded_ids_not_in_json(self, monkeypatch, tmp_path):
        target = tmp_path / "o.json"
        run(monkeypatch, tmp_path, "--exclude", "INP03", "--json", str(target))
        data = json.loads(target.read_text())
        assert "INP03" not in {f["threat_id"] for f in data["findings"]}
        assert data["threatsExcluded"] == ["INP03"]


class TestStaleDays:
    def prepare(self, tmp_path: Path, src_offset_days: float) -> Path:
        script = tmp_path / "model.py"
        script.write_text("# model\n")
        src = tmp_path / MODEL_SOURCE
        src.write_text("# src\n")
        base = 1_700_000_000
        os.utime(script, (base, base))
        shifted = base + int(src_offset_days * 86400)
        os.utime(src, (shifted, shifted))
        return script

    def run_stale(self, monkeypatch, script: Path) -> None:
        monkeypatch.setattr(sys, "argv", [str(script), "--stale_days", "2"])
        build_model().process()

    def test_source_much_newer_than_model(self, monkeypatch, tmp_path, capsys):
        script = self.prepare(tmp_path, 3)
        self.run_stale(monkeypatch, script)
        out = capsys.readouterr().out.splitlines()
        assert out[0] == "Checking for code 2 days older than this model."
        assert out[1] == (f"This model is 3 days older than {tmp_path / MODEL_SOURCE}.")
        assert out[-1] == ""  # the empty report string is printed

    def test_model_much_newer_than_source(self, monkeypatch, tmp_path, capsys):
        script = self.prepare(tmp_path, -3)
        self.run_stale(monkeypatch, script)
        out = capsys.readouterr().out
        assert (
            f"Model script {script} is only 3 days newer than source code file "
            f"{tmp_path / MODEL_SOURCE}"
        ) in out

    def test_within_threshold_reports_nothing(self, monkeypatch, tmp_path, capsys):
        script = self.prepare(tmp_path, 1)
        self.run_stale(monkeypatch, script)
        out = capsys.readouterr().out.splitlines()
        assert out == ["Checking for code 2 days older than this model.", ""]

    def test_missing_source_goes_to_stderr(self, monkeypatch, tmp_path, capsys):
        script = tmp_path / "model.py"
        script.write_text("# model\n")
        self.run_stale(monkeypatch, script)
        captured = capsys.readouterr()
        assert f"{script} - " in captured.err
        assert MODEL_SOURCE in captured.err
        assert "days" not in captured.out.replace("Checking for code 2 days", "")

    def test_missing_model_script_returns_error(self, monkeypatch, tmp_path, capsys):
        script = tmp_path / "gone.py"
        monkeypatch.setattr(sys, "argv", [str(script), "--stale_days", "2"])
        build_model().process()
        captured = capsys.readouterr()
        assert captured.out == "[ERROR]\n"
        assert captured.err.startswith(f"{script} - ")

    def test_stale_days_zero_still_runs(self, monkeypatch, tmp_path, capsys):
        script = self.prepare(tmp_path, 0)
        monkeypatch.setattr(sys, "argv", [str(script), "--stale_days", "0"])
        build_model().process()
        out = capsys.readouterr().out
        assert out.startswith("Checking for code 0 days older than this model.")
        assert "This model is 0 days older than" in out


class TestVarDescriptor:
    def make(self, on_set=None):
        class Holder:
            attr = var(5, doc="five", onSet=on_set)

        return Holder

    def test_class_access_returns_descriptor(self):
        holder = self.make()
        assert isinstance(holder.attr, var)
        assert holder.attr.default == 5
        assert holder.attr.doc == "five"
        assert holder.attr.required is False

    def test_instance_default_then_override(self):
        holder = self.make()
        obj = holder()
        assert obj.attr == 5
        obj.attr = 9
        assert obj.attr == 9
        assert holder().attr == 5

    def test_on_set_called_with_instance_and_value(self):
        calls: list[tuple[object, int]] = []
        holder = self.make(on_set=lambda inst, val: calls.append((inst, val)))
        obj = holder()
        obj.attr = 7
        assert calls == [(obj, 7)]
        assert obj.attr == 7
