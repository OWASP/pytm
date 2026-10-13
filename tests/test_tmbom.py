"""Tests for the CycloneDX 2.0 TM-BOM output (``--tmbom``)."""

import json
import pathlib
import sys

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from pytm import (
    TM,
    Actor,
    ActorKind,
    Assumption,
    Boundary,
    Classification,
    Control,
    ControlCategory,
    ControlStatus,
    Data,
    Dataflow,
    Datastore,
    Server,
    Threat,
    TLSVersion,
    loads,
)
from pytm.pytm import to_serializable
from pytm.tmbom import build_tmbom

HERE = pathlib.Path(__file__).parent
SCHEMA_DIR = HERE / "schemas" / "cyclonedx-2.0"
GOLDEN = HERE / "tmbom_output.json"
SERIAL = "urn:uuid:00000000-0000-4000-8000-000000000000"
STAMP = "2026-01-01T00:00:00+00:00"

REF_KEYS = {
    "zone",
    "parent",
    "source",
    "destination",
    "zones",
    "affectedAssets",
    "affects",
    "relatedThreats",
    "relatedAssets",
    "dataSets",
    "dataStore",
    "controls",
    "mitigations",
    "attackPatterns",
    "ref",
    "associates",
}


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    if not (SCHEMA_DIR / "cyclonedx-2.0.schema.json").exists():
        pytest.skip("run tests/fetch_cyclonedx_schema.sh to enable schema validation")
    registry = Registry()
    for path in SCHEMA_DIR.rglob("*.schema.json"):
        registry = registry.with_resource(
            path.name, Resource.from_contents(json.loads(path.read_text()))
        )
    schema = json.loads((SCHEMA_DIR / "cyclonedx-2.0.schema.json").read_text())
    return Draft202012Validator(schema, registry=registry)


def make_model() -> TM:
    tm = TM("my test tm", description="aaa", threatsFile="pytm/threatlib/threats.json")
    tm.isOrdered = True
    tm.assumptions = [Assumption("Tokens are rotated", exclude=["AA01"])]
    internet = Boundary("Internet")
    vpc = Boundary("VPC", inBoundary=internet)
    user = Actor("User", inBoundary=internet, kind=ActorKind.PERSON)
    web = Server("Web Server", inBoundary=vpc)
    db = Datastore("SQL Database", inBoundary=vpc)
    db.controls.isEncryptedAtRest = True
    cookie = Data(
        name="auth cookie",
        description="auth cookie description",
        classification=Classification.PUBLIC,
        isCredentials=True,
        isStored=True,
    )
    Dataflow(
        user,
        web,
        "Request",
        protocol="HTTPS",
        tlsVersion=TLSVersion.TLSv12,
        data=cookie,
    )
    query = Dataflow(web, db, "Query", note="ccc", data=cookie, usesSessionTokens=True)
    Dataflow(db, web, "Query", responseTo=query)  # duplicate name on purpose
    Control(
        "Parameterised queries",
        category=ControlCategory.PREVENTIVE,
        status=ControlStatus.IMPLEMENTED,
        mitigates=["INP03"],
        appliesTo=[web],
        effectiveness="good",
    )
    return tm


def build(tm: TM) -> dict:
    assert tm.check()
    tm.resolve()
    return build_tmbom(tm, serial=SERIAL, timestamp=STAMP, tool_version="test")


def collect_refs(node, found: set, wanted: list) -> None:
    """Collect defined bom-refs and every reference-valued field in ``node``."""
    if isinstance(node, list):
        for item in node:
            collect_refs(item, found, wanted)
    elif isinstance(node, dict):
        is_flow = "destination" in node
        for key, value in node.items():
            if key == "bom-ref":
                found.add(value)
            elif key in REF_KEYS and (key != "source" or is_flow):
                items = value if isinstance(value, list) else [value]
                wanted.extend(i for i in items if isinstance(i, str))
                collect_refs(
                    [i for i in items if not isinstance(i, str)], found, wanted
                )
            else:
                collect_refs(value, found, wanted)


def test_validates_against_schema(validator):
    doc = build(make_model())
    assert list(validator.iter_errors(doc)) == []


def test_validator_rejects_bad_documents(validator):
    doc = build(make_model())
    doc["blueprints"][0]["flows"][0]["type"] = 12
    assert list(validator.iter_errors(doc))


def test_refs_resolve_and_are_unique(validator):
    doc = build(make_model())
    defined: set = set()
    referenced: list = []
    collect_refs(doc, defined, referenced)
    assert referenced
    assert set(referenced) <= defined
    assert json.dumps(doc).count('"bom-ref"') == len(defined)


def test_flow_endpoints_are_assets_or_actors():
    """Diagram tools draw flows only between assets, so stores must be assets."""
    blueprint = build(make_model())["blueprints"][0]
    nodes = {a["bom-ref"] for a in blueprint["assets"] + blueprint["actors"]}
    for flow in blueprint["flows"]:
        assert flow["source"] in nodes and flow["destination"] in nodes


def test_datastore_is_asset_and_detail_record(validator):
    blueprint = build(make_model())["blueprints"][0]
    (asset,) = [a for a in blueprint["assets"] if a["name"] == "SQL Database"]
    (detail,) = [d for d in blueprint["dataStores"] if d["name"] == "SQL Database"]
    assert asset["type"] == "data-store"
    assert asset["bom-ref"] != detail["bom-ref"]
    assert {"ref": asset["bom-ref"], "associates": [detail["bom-ref"]]} in blueprint[
        "relationships"
    ]


def test_duplicate_flow_names_get_distinct_refs():
    flows = build(make_model())["blueprints"][0]["flows"]
    refs = [f["bom-ref"] for f in flows if f["name"] == "Query"]
    assert len(refs) == 2 and len(set(refs)) == 2


def test_zones_parents_and_boundaries():
    blueprint = build(make_model())["blueprints"][0]
    zones = {z["name"]: z for z in blueprint["zones"]}
    assert zones["VPC"]["parent"] == zones["Internet"]["bom-ref"]
    assert [b["zones"] for b in blueprint["boundaries"]] == [
        sorted([zones["Internet"]["bom-ref"], zones["VPC"]["bom-ref"]])
    ]


def test_excluded_findings_become_accepted_risks():
    doc = build(make_model())
    excluded = [r for r in doc["risks"]["risks"] if "excluded" in r["bom-ref"]]
    assert excluded
    assert all(r["status"] == "accepted" for r in excluded)
    assert any(t["bom-ref"] == "threat-aa01" for t in doc["threats"]["threats"])


def test_flow_encryption_only_when_known():
    flows = {f["name"]: f for f in build(make_model())["blueprints"][0]["flows"]}
    assert flows["Request"]["encrypted"] is True
    assert "encrypted" not in flows["Query"]


def test_explicit_is_encrypted_wins_over_tls():
    tm = TM("enc", description="d", threatsFile="pytm/threatlib/threats.json")
    a, b = Server("A"), Server("B")
    Dataflow(a, b, "plain", tlsVersion=TLSVersion.TLSv13, isEncrypted=False)
    Dataflow(b, a, "secret", isEncrypted=True)
    flows = {f["name"]: f for f in build(tm)["blueprints"][0]["flows"]}
    assert flows["plain"]["encrypted"] is False
    assert flows["secret"]["encrypted"] is True


def test_actor_kind_goes_to_actors_section(validator):
    doc = build(make_model())
    blueprint = doc["blueprints"][0]
    (actor,) = blueprint["actors"]
    assert actor["party"]["person"] == {"name": "User"}
    assert "User" not in [a["name"] for a in blueprint["assets"]]
    request = next(f for f in blueprint["flows"] if f["name"] == "Request")
    assert request["source"] == actor["bom-ref"]


def test_actor_without_kind_stays_asset():
    tm = TM("k", description="d", threatsFile="pytm/threatlib/threats.json")
    Dataflow(Actor("Anon"), Server("S"), "x")
    blueprint = build(tm)["blueprints"][0]
    assert "actors" not in blueprint
    assert "Anon" in [a["name"] for a in blueprint["assets"]]


@pytest.mark.parametrize("kind", [k for k in ActorKind if k != ActorKind.UNKNOWN])
def test_every_actor_kind_validates(kind, validator):
    tm = TM("k", description="d", threatsFile="pytm/threatlib/threats.json")
    Dataflow(Actor("Who", kind=kind, isAdmin=True), Server("S"), "x")
    assert list(validator.iter_errors(build(tm))) == []


def test_data_placements_and_credentials_life():
    blueprint = build(make_model())["blueprints"][0]
    cookie = next(d for d in blueprint["dataSets"] if d["name"] == "auth cookie")
    store = next(s for s in blueprint["dataStores"] if s["name"] == "SQL Database")
    assert cookie["placements"] == [{"dataStore": store["bom-ref"], "encrypted": True}]


def test_session_tokens_and_response_flow_fields():
    flows = build(make_model())["blueprints"][0]["flows"]
    query = [f for f in flows if f["name"] == "Query"]
    request = next(f for f in query if f.get("synchronous"))
    response = next(f for f in query if not f.get("synchronous"))
    assert request["authentication"][0]["name"] == "session-token"
    assert "authentication" not in response
    assert "synchronous" not in next(f for f in flows if f["name"] == "Request")


def test_unassigned_stride_exports_no_category():
    doc = build(make_model())
    assert all("categories" not in t for t in doc["threats"]["threats"])


def test_assigned_stride_exports_category(validator):
    tm = make_model()
    tm.check()
    tm.resolve()
    for f in tm.findings:
        if f.threat_id == "INP03":
            f.stride = "tampering"
    doc = build_tmbom(tm, serial=SERIAL, timestamp=STAMP, tool_version="test")
    threat = next(
        t for t in doc["threats"]["threats"] if t["bom-ref"] == "threat-inp03"
    )
    assert threat["categories"] == [{"taxonomy": "STRIDE", "category": "tampering"}]
    assert list(validator.iter_errors(doc)) == []


def test_capec_cwe_on_threats():
    doc = build(make_model())
    threat = next(
        t for t in doc["threats"]["threats"] if t["bom-ref"] == "threat-inp03"
    )
    patterns = {p["bom-ref"]: p for p in doc["threats"]["attackPatterns"]}
    assert threat["attackPatterns"] and set(threat["attackPatterns"]) <= set(patterns)
    assert all(w["cweId"] > 0 for w in threat["weaknesses"])


def test_impact_reaches_risk_rating():
    tm = make_model()
    tm.check()
    tm.resolve()
    for f in tm.findings:
        f.impact = "major"
    doc = build_tmbom(tm, serial=SERIAL, timestamp=STAMP, tool_version="test")
    assert {
        r["inherentRisk"]["impact"]["level"]
        for r in doc["risks"]["risks"]
        if "excluded" not in r["bom-ref"]
    } == {"major"}


def test_control_links_threat_and_risk(validator):
    doc = build(make_model())
    (control,) = doc["controls"]
    assert control["category"] == "preventive" and control["status"] == "implemented"
    assert control["effectiveness"] == {"rating": "good"}
    threat = next(
        t for t in doc["threats"]["threats"] if t["bom-ref"] == "threat-inp03"
    )
    assert threat["mitigations"] == [control["bom-ref"]]
    linked = [
        r
        for r in doc["risks"]["risks"]
        if r.get("responses")
        and control["bom-ref"] in r["responses"][0].get("controls", [])
    ]
    assert linked and all(r["relatedThreats"] == ["threat-inp03"] for r in linked)
    assert all(r["responses"][0]["strategy"] == "reduce" for r in linked)


def test_control_scoped_to_other_element_is_not_linked():
    tm = make_model()
    tm.check()
    tm.resolve()
    other = Server("Elsewhere")
    ctl = Control("Scoped", mitigates="INP03", appliesTo=other)
    finding = next(f for f in tm.findings if f.threat_id == "INP03")
    from pytm.tmbom import _protecting

    assert _protecting(finding, [ctl]) == []


def test_model_without_boundaries(validator):
    tm = TM("plain", description="d", threatsFile="pytm/threatlib/threats.json")
    Dataflow(Actor("User"), Server("Web"), "Hit")
    doc = build(tm)
    blueprint = doc["blueprints"][0]
    assert "zones" not in blueprint and "boundaries" not in blueprint
    assert list(validator.iter_errors(doc)) == []


def test_unbounded_zone_added_for_unplaced_elements(validator):
    tm = TM("mixed", description="d", threatsFile="pytm/threatlib/threats.json")
    outside = Boundary("Outside")
    Dataflow(Actor("User", inBoundary=outside), Server("Web"), "Hit")
    doc = build(tm)
    names = [z["name"] for z in doc["blueprints"][0]["zones"]]
    assert names == ["Outside", "Unbounded"]
    assert list(validator.iter_errors(doc)) == []


def test_output_matches_golden():
    text = json.dumps(build(make_model()), indent=2, sort_keys=True)
    assert text == GOLDEN.read_text().strip()


def test_cli_prints_valid_json(monkeypatch, capsys, validator):
    tm = make_model()
    monkeypatch.setattr(sys, "argv", ["tm.py", "--tmbom"])
    tm.process()
    doc = json.loads(capsys.readouterr().out)
    assert doc["specVersion"] == "2.0"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert list(validator.iter_errors(doc)) == []


def test_threat_parses_taxonomy_from_references():
    threat = Threat(
        SID="X1",
        stride="Information Disclosure",
        references="https://capec.mitre.org/data/definitions/10.html, CWE-79, "
        "http://cwe.mitre.org/data/definitions/119.html, CAPEC-10",
    )
    assert threat.stride == "information-disclosure"
    assert threat.capec == [10]
    assert threat.cwe == [79, 119]


@pytest.mark.parametrize("field", ["stride", "impact"])
def test_threat_rejects_unknown_category(field):
    with pytest.raises(ValueError):
        Threat(SID="X1", **{field: "bogus"})


def test_stride_defaults_to_unassigned():
    assert Threat(SID="X1").stride == "unassigned"
    assert Threat(SID="X1", stride="").stride == "unassigned"
    tm = TM("lib", description="d")  # loads the default threat library
    assert tm._threats and {t.stride for t in tm._threats} == {"unassigned"}


def test_control_json_round_trip():
    tm = TM("rt", description="d", threatsFile="pytm/threatlib/threats.json")
    web, db = Server("Web"), Datastore("DB")
    Dataflow(web, db, "Write")
    Control("WAF", status=ControlStatus.PLANNED, mitigates=["INP03"], appliesTo=web)
    tm.check()
    dumped = json.dumps(tm, default=to_serializable)
    TM.reset()
    loaded = loads(dumped)
    (control,) = TM._controls
    assert control.name == "WAF"
    assert control.status == ControlStatus.PLANNED
    assert control.mitigates == ["INP03"]
    assert [e.name for e in control.appliesTo] == ["Web"]
    assert loaded.name == "rt"
