import random
import sqlite3
from pathlib import Path

import pytest

from pytm import Boundary, Server, Threat, TM


@pytest.fixture
def sample_tm():
    TM.reset()
    random.seed(0)
    tm = TM("sql dump tm", description="desc")

    internet = Boundary("Internet")
    server_db = Boundary("Server/DB", inBoundary=internet)
    Server("Web Server", inBoundary=server_db)

    TM._threats = [
        Threat(
            SID="SRV001",
            description="Server threat",
            severity="High",
            target="Server",
        )
    ]

    tm.resolve()
    assert tm.findings, "Expected at least one finding for sqlDump tests"
    return tm


def _open_connection(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "sqldump" / "test.db"
    return sqlite3.connect(db_path)


def test_sql_dump_creates_serialized_columns(sample_tm, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    sample_tm.sqlDump("test.db")

    with _open_connection(tmp_path) as conn:
        column_names = {
            column_info[1].lower()
            for column_info in conn.execute("PRAGMA table_info(Boundary)")
        }

    assert {"name", "inscope", "inboundary"}.issubset(column_names)


def test_sql_dump_persists_element_and_finding_data(sample_tm, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    sample_tm.sqlDump("test.db")

    with _open_connection(tmp_path) as conn:
        boundary_rows = conn.execute(
            "SELECT name, inBoundary FROM Boundary ORDER BY id"
        ).fetchall()
        server_rows = conn.execute(
            "SELECT name, inBoundary FROM Server ORDER BY id"
        ).fetchall()
        finding_rows = conn.execute(
            "SELECT threat_id FROM Finding ORDER BY id"
        ).fetchall()

    assert ("Internet", None) in boundary_rows
    assert ("Server/DB", "Internet") in boundary_rows
    assert ("Web Server", "Server/DB") in server_rows
    assert [row[0] for row in finding_rows] == ["SRV001"]
