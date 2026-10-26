import builtins
from unittest.mock import patch

from pytm import TM


def test_report_reads_utf8_template_with_legacy_locale(tmp_path):
    template = tmp_path / "template.md"
    template.write_text("Résumé — “{tm.name}”", encoding="utf-8")
    TM.reset()
    tm = TM("example")

    # Model the default text encoding on Windows without UTF-8 mode.
    def legacy_open(path, mode="r", **kwargs):
        kwargs.setdefault("encoding", "cp1252")
        return builtins.open(path, mode, **kwargs)

    try:
        with patch("pytm.tm.open", side_effect=legacy_open, create=True):
            assert tm.report(template) == "Résumé — “example”"
    finally:
        TM.reset()
