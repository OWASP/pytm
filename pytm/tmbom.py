"""CycloneDX 2.0 TM-BOM (threat model bill of materials) output.

The document layout follows the CycloneDX 2.0 draft schema, pinned to
``CycloneDX/specification`` commit :data:`SCHEMA_COMMIT`:

* ``blueprints``: zones (pytm ``Boundary``), boundaries crossed by flows, assets,
  actors, data stores, data sets, flows and assumptions.
* ``threats``: one entry per threat library SID, pointing at the affected assets,
  plus the CAPEC attack patterns they reference.
* ``risks``: one entry per finding (including findings excluded by assumptions).
* ``controls``: pytm ``Control`` objects, linked from threats and risk responses.

:func:`build_tmbom` is pure; :func:`render_tmbom` supplies the serial number,
timestamp and tool version.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from typing import Any

from .actor import Actor
from .asset import LLM, Agent, Asset, ExternalEntity, Lambda, Server
from .boundary import Boundary
from .control import Control
from .data import Data
from .dataflow import Dataflow
from .datastore import Datastore
from .element import Element
from .enums import (
    ActorKind,
    Classification,
    ControlCategory,
    ControlStatus,
    DatastoreType,
    Lifetime,
    TLSVersion,
)
from .process import Process
from .taxonomy import UNASSIGNED

SPEC_VERSION = "2.0"
SCHEMA_COMMIT = "906c57979d786c935787213ae1693a98097858ce"
SCHEMA_URL = (
    "https://raw.githubusercontent.com/CycloneDX/specification/"
    f"{SCHEMA_COMMIT}/schema/2.0/cyclonedx-2.0.schema.json"
)

_PREFIX = "pytm:"
_UNBOUNDED_NAME = "Unbounded"

_ASSET_TYPES: dict[type, str] = {
    Actor: "actor",
    Agent: "agent",
    ExternalEntity: "system",
    Lambda: "function",
    LLM: "model",
    Process: "process",
    Server: "service",
    Asset: "component",
}
_DATASTORE_TYPES: dict[DatastoreType, str] = {
    DatastoreType.FILE_SYSTEM: "file",
    DatastoreType.SQL: "relational",
    DatastoreType.LDAP: "hierarchical",
    DatastoreType.AWS_S3: "object",
}
_CLASSIFICATIONS: dict[Classification, str] = {
    Classification.PUBLIC: "public",
    Classification.RESTRICTED: "restricted",
    Classification.SENSITIVE: "confidential",
    Classification.SECRET: "classified",
    Classification.TOP_SECRET: "classified",
}
_SEVERITY_TO_SCORE: dict[str, str] = {
    "very high": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "very low": "info",
    "info": "info",
}
_LIKELIHOOD_TO_LEVEL: dict[str, str] = {
    "very high": "very-high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "very low": "very-low",
}
# Finding.response -> (risk response strategy, risk status)
_PARTY_ROLES = {False: "end-user", True: "operator"}
_PERSONA_ARCHETYPES = {False: "end-user", True: "administrator"}
_RESPONSES: dict[str, tuple[str, str]] = {
    "mitigated": ("reduce", "mitigated"),
    "transferred": ("transfer", "transferred"),
    "avoided": ("avoid", "retired"),
    "accepted": ("accept", "accepted"),
}


def _slug(text: str) -> str:
    """Lowercase ``text`` and collapse anything non-alphanumeric to dashes."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unnamed"


def _clean(obj: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` and empty string/list/dict values (keeps ``False`` and 0)."""
    return {
        k: v
        for k, v in obj.items()
        if v is not None and v != "" and v != [] and v != {}
    }


def _props(**values: Any) -> list[dict[str, str]]:
    """Build namespaced CycloneDX properties, skipping unset values."""
    props = []
    for key, value in values.items():
        if value is None or value == "" or value == []:
            continue
        text = str(value).lower() if isinstance(value, bool) else str(value)
        props.append({"name": f"{_PREFIX}{key}", "value": text})
    return props


def _unused_ref(base: str, used: set[str]) -> str:
    """``base``, or ``base-2``, ``base-3``... whichever is not in ``used``."""
    ref, n = base, 1
    while ref in used:
        n += 1
        ref = f"{base}-{n}"
    return ref


class _Refs:
    """Stable ``bom-ref`` values for pytm objects, unique within the document."""

    def __init__(self) -> None:
        self._by_id: dict[int, str] = {}
        self._used: set[str] = set()

    def reserve(self, ref: str) -> None:
        """Mark ``ref`` as taken so generated refs never collide with it."""
        self._used.add(ref)

    def add(self, kind: str, obj: Any, name: str) -> str:
        """Return the ref for ``obj``, creating one from ``kind`` and ``name``."""
        existing = self._by_id.get(id(obj))
        if existing is not None:
            return existing
        ref = _unused_ref(f"{kind}-{_slug(name)}", self._used)
        self._used.add(ref)
        self._by_id[id(obj)] = ref
        return ref

    def get(self, obj: Any) -> str | None:
        """Return the ref previously assigned to ``obj``, if any."""
        return self._by_id.get(id(obj))


def _unique(items: Iterable[Any]) -> list[Any]:
    """Deduplicate by identity, preserving order."""
    seen: set[int] = set()
    out = []
    for item in items:
        if id(item) not in seen:
            seen.add(id(item))
            out.append(item)
    return out


def _asset_type(element: Element) -> str:
    """Map a pytm element class to a TM-BOM asset type."""
    for cls in type(element).__mro__:
        if cls in _ASSET_TYPES:
            return _ASSET_TYPES[cls]
    return "component"


def _control_props(element: Element) -> list[dict[str, str]]:
    """Expose enabled controls of ``element`` as properties."""
    controls = getattr(element, "controls", None)
    if controls is None:
        return []
    return _props(
        **{
            f"controls.{name}": value
            for name, value in sorted(controls.model_dump().items())
            if value not in (False, "", None)
        }
    )


def _element_props(element: Element) -> list[dict[str, str]]:
    """Properties shared by assets, data stores and actors."""
    port = getattr(element, "port", -1)
    return _props(
        inScope=element.inScope,
        protocol=getattr(element, "protocol", ""),
        port=port if port >= 0 else None,
        isAdmin=getattr(element, "isAdmin", None) or None,
        OS=getattr(element, "OS", ""),
    ) + _control_props(element)


def _classification(value: Classification) -> str | None:
    """Map a pytm classification to the TM-BOM data classification enum."""
    return _CLASSIFICATIONS.get(value)


def _sorted_data(items: Iterable[Data]) -> list[Data]:
    """Order ``Data`` deterministically (they live in unordered sets)."""
    return sorted(items, key=lambda d: (d.name, d.description))


def _zone_ref(element: Element, refs: _Refs, unbounded: str | None) -> str | None:
    """Zone ref of the boundary ``element`` lives in."""
    boundary = element.inBoundary
    return refs.get(boundary) if boundary is not None else unbounded


def _build_zones(
    boundaries: list[Boundary], refs: _Refs, unbounded: str | None
) -> list[dict[str, Any]]:
    """One trust zone per boundary, plus the implicit unbounded zone."""
    zones = [
        _clean(
            {
                "bom-ref": refs.get(b),
                "name": b.name,
                "description": b.description,
                "type": "trust",
                "parent": refs.get(b.inBoundary) if b.inBoundary else None,
                "properties": _props(inScope=b.inScope),
            }
        )
        for b in boundaries
    ]
    if unbounded:
        zones.append({"bom-ref": unbounded, "name": _UNBOUNDED_NAME, "type": "trust"})
    return zones


def _build_boundaries(
    boundaries: list[Boundary],
    flows: list[Dataflow],
    refs: _Refs,
    unbounded: str | None,
) -> list[dict[str, Any]]:
    """One trust boundary per pair of zones that a flow crosses."""
    pairs: dict[tuple[str, str], None] = {}
    for flow in flows:
        a = _zone_ref(flow.source, refs, unbounded)
        b = _zone_ref(flow.sink, refs, unbounded)
        if a and b and a != b:
            pairs[tuple(sorted((a, b)))] = None
    names = {refs.get(b): b.name for b in boundaries}
    if unbounded:
        names[unbounded] = _UNBOUNDED_NAME
    return [
        {
            "bom-ref": f"boundary-{a.removeprefix('zone-')}-{b.removeprefix('zone-')}",
            "name": f"{names[a]} <-> {names[b]}",
            "type": "trust",
            "zones": [a, b],
        }
        for a, b in pairs
    ]


def _build_asset(element: Element, refs: _Refs, unbounded: str | None) -> dict:
    """Asset entry for an Actor or Asset element."""
    classification = _classification(element.maxClassification)
    return _clean(
        {
            "bom-ref": refs.get(element),
            "type": _asset_type(element),
            "name": element.name,
            "description": element.description,
            "zone": _zone_ref(element, refs, unbounded),
            "classification": (
                {"classification": classification} if classification else None
            ),
            "properties": _element_props(element),
        }
    )


def _build_actor(actor: Actor, refs: _Refs, unbounded: str | None) -> dict:
    """``actors[]`` entry for an Actor whose ``kind`` says which party it is.

    The schema's actor has no name, so system and persona parties (which have
    none either) carry it in the description.
    """
    admin = actor.isAdmin
    identity = {
        ActorKind.PERSON: {"person": {"name": actor.name}},
        ActorKind.ORGANIZATION: {"organization": {"name": actor.name}},
        ActorKind.SYSTEM: {"system": {"kind": "software-system"}},
        ActorKind.PERSONA: {
            "persona": {
                "description": actor.description or actor.name,
                "archetype": _PERSONA_ARCHETYPES[admin],
            }
        },
    }[actor.kind]
    nameless = actor.kind in (ActorKind.SYSTEM, ActorKind.PERSONA)
    description = actor.description
    if nameless and description != actor.name:
        description = f"{actor.name}: {description}" if description else actor.name
    return _clean(
        {
            "bom-ref": refs.get(actor),
            "party": {"roles": [{"role": _PARTY_ROLES[admin]}], **identity},
            "description": description,
            "zone": _zone_ref(actor, refs, unbounded),
            "properties": _props(name=actor.name, kind=actor.kind.value)
            + _element_props(actor),
        }
    )


def _build_data_store(
    store: Datastore,
    flows: list[Dataflow],
    refs: _Refs,
    unbounded: str | None,
) -> dict:
    """Data store entry; data sets are those carried by flows into the store."""
    store_type = _DATASTORE_TYPES.get(store.type)
    carried = _unique(d for f in flows if f.sink is store for d in f.data)
    return _clean(
        {
            "bom-ref": refs.get(store),
            "name": store.name,
            "description": store.description,
            "type": store_type or {"name": "unknown"},
            "zone": _zone_ref(store, refs, unbounded),
            "dataSets": [r for d in carried if (r := refs.get(d))],
            "properties": _props(
                isSQL=store.isSQL,
                isShared=store.isShared,
                onRDS=store.onRDS,
            )
            + _element_props(store),
        }
    )


def _placements(data: Data, flows: list[Dataflow], refs: _Refs) -> list[dict]:
    """Where ``data`` rests: stores it flows into (if stored) or out of."""
    encrypted: dict[int, bool] = {}
    stores: dict[int, Datastore] = {}
    for flow in flows:
        if data not in flow.data:
            continue
        if isinstance(flow.sink, Datastore) and data.isStored:
            stores[id(flow.sink)] = flow.sink
            encrypted[id(flow.sink)] = encrypted.get(id(flow.sink), False) or bool(
                data.isDestEncryptedAtRest
            )
        if isinstance(flow.source, Datastore):
            stores[id(flow.source)] = flow.source
            encrypted[id(flow.source)] = encrypted.get(id(flow.source), False) or bool(
                data.isSourceEncryptedAtRest
            )
    return [
        _clean({"dataStore": refs.get(store), "encrypted": encrypted[key] or None})
        for key, store in stores.items()
    ]


def _build_data_set(data: Data, flows: list[Dataflow], refs: _Refs) -> dict:
    """Data set entry for a pytm ``Data``."""
    return _clean(
        {
            "bom-ref": refs.get(data),
            "name": data.name,
            "description": data.description or data.name,
            "placements": _placements(data, flows, refs),
            "properties": _props(
                classification=_classification(data.classification),
                format=data.format,
                isPII=data.isPII or None,
                isCredentials=data.isCredentials or None,
                credentialsLife=(
                    data.credentialsLife.name
                    if data.credentialsLife != Lifetime.NONE
                    else None
                ),
                isStored=data.isStored or None,
            ),
        }
    )


def _build_flow(flow: Dataflow, refs: _Refs, unbounded: str | None) -> dict[str, Any]:
    """Flow entry for a ``Dataflow``."""
    encrypted = flow.isEncrypted
    if encrypted is None and flow.tlsVersion != TLSVersion.NONE:
        encrypted = True
    return _clean(
        {
            "bom-ref": refs.get(flow),
            "name": flow.name,
            "description": flow.description,
            "type": "data",
            "source": refs.get(flow.source),
            "destination": refs.get(flow.sink),
            "encrypted": encrypted,
            "synchronous": True if flow.response is not None else None,
            "authentication": (
                [{"name": "session-token", "description": "pytm usesSessionTokens"}]
                if flow.usesSessionTokens
                else []
            ),
            "protocols": [flow.protocol] if flow.protocol else [],
            "dataObjects": [
                _clean({"name": d.name, "description": d.description})
                for d in _sorted_data(flow.data)
            ],
            "sequence": flow.order if flow.order >= 0 else None,
            "properties": _props(
                isResponse=flow.isResponse or None,
                responseTo=(
                    refs.get(flow.responseTo) if flow.responseTo is not None else None
                ),
                srcPort=flow.srcPort if flow.srcPort >= 0 else None,
                dstPort=flow.dstPort if flow.dstPort >= 0 else None,
                tlsVersion=(
                    flow.tlsVersion.name if flow.tlsVersion != TLSVersion.NONE else None
                ),
                note=flow.note,
                usesVPN=flow.usesVPN or None,
                inScope=flow.inScope,
            )
            + _control_props(flow),
        }
    )


def _build_assumptions(
    tm: Any, elements: list[Element], refs: _Refs
) -> list[dict[str, Any]]:
    """Global assumptions plus those attached to individual elements."""
    owners: list[tuple[Any, Element | None]] = [(a, None) for a in tm.assumptions]
    owners += [(a, e) for e in elements for a in getattr(e, "assumptions", None) or []]
    out, used = [], set()
    for assumption, element in owners:
        text = (
            f"{assumption.name}: {assumption.description}"
            if assumption.name and assumption.description
            else assumption.description or assumption.name
        )
        if not text:
            continue
        ref = _unused_ref(f"assumption-{_slug(assumption.name or text)}", used)
        used.add(ref)
        excluded = ", ".join(sorted(assumption.exclude))
        out.append(
            _clean(
                {
                    "bom-ref": ref,
                    "description": text,
                    "relatedAssets": (
                        [r] if element and (r := refs.get(element)) else []
                    ),
                    "impact": f"Excludes threats: {excluded}" if excluded else "",
                }
            )
        )
    return out


def _urls(references: str) -> list[dict[str, str]]:
    """External references for the http(s) links in a threat's references."""
    links = [r.strip() for r in references.split(",")]
    return [
        {"url": u, "type": "other"}
        for u in links
        if u.startswith(("http://", "https://"))
    ]


def _capec_ref(capec_id: int) -> str:
    """``bom-ref`` of the attack pattern for a CAPEC id."""
    return f"capec-{capec_id}"


def _build_attack_patterns(all_findings: list[Any]) -> list[dict[str, Any]]:
    """One attack pattern per CAPEC id mentioned by any finding's threat."""
    ids = dict.fromkeys(i for f in all_findings for i in f.capec)
    return [{"bom-ref": _capec_ref(i), "capecId": i, "name": f"CAPEC-{i}"} for i in ids]


def _mitigating(sid: str, controls: list[Control]) -> list[Control]:
    """Controls declared to mitigate the threat ``sid``."""
    return [c for c in controls if sid in c.mitigates]


def _protecting(finding: Any, controls: list[Control]) -> list[Control]:
    """Controls mitigating ``finding``'s threat on its element."""
    return [
        c
        for c in _mitigating(finding.threat_id, controls)
        if not c.appliesTo or any(a is finding.element for a in c.appliesTo)
    ]


def _build_control(control: Control, refs: _Refs) -> dict[str, Any]:
    """Control entry for a pytm ``Control``."""
    applies = [r for a in control.appliesTo if (r := refs.get(a))]
    return _clean(
        {
            "bom-ref": refs.get(control),
            "name": control.name,
            "description": control.description,
            "category": (
                control.category.value
                if control.category != ControlCategory.UNKNOWN
                else None
            ),
            "status": (
                control.status.value
                if control.status != ControlStatus.UNKNOWN
                else None
            ),
            "appliesTo": applies,
            "effectiveness": (
                {"rating": control.effectiveness} if control.effectiveness else None
            ),
            "properties": _props(mitigates=",".join(sorted(control.mitigates))),
        }
    )


def _build_threats(
    all_findings: list[Any],
    refs: _Refs,
    threat_refs: dict[str, str],
    controls: list[Control],
) -> list[dict[str, Any]]:
    """One threat per threat library SID."""
    groups: dict[str, list[Any]] = {}
    for finding in all_findings:
        groups.setdefault(finding.threat_id, []).append(finding)
    threats = []
    for sid, group in groups.items():
        first = group[0]
        affected = [r for e in _unique(f.element for f in group) if (r := refs.get(e))]
        threats.append(
            _clean(
                {
                    "bom-ref": threat_refs[sid],
                    "name": first.description or sid,
                    "description": first.details,
                    "source": "pytm",
                    "categories": (
                        [{"taxonomy": "STRIDE", "category": first.stride}]
                        if first.stride != UNASSIGNED
                        else []
                    ),
                    "weaknesses": [{"cweId": i} for i in first.cwe],
                    "attackPatterns": [_capec_ref(i) for i in first.capec],
                    "affectedAssets": affected,
                    "mitigations": [
                        r for c in _mitigating(sid, controls) if (r := refs.get(c))
                    ],
                    "externalReferences": _urls(first.references),
                    "properties": _props(
                        sid=sid,
                        severity=first.severity,
                        likelihood=first.likelihood,
                        condition=first.condition,
                        mitigations=first.mitigations,
                        example=first.example,
                        references=first.references,
                    ),
                }
            )
        )
    return threats


def _build_risk(
    finding: Any,
    ref: str,
    refs: _Refs,
    threat_refs: dict[str, str],
    controls: list[Control],
    excluded: bool,
) -> dict[str, Any]:
    """Risk entry for a finding; excluded findings are accepted by assumption."""
    strategy, status = _RESPONSES.get(finding.response.lower(), (None, "identified"))
    if excluded:
        strategy, status = "accept", "accepted"
    score = _SEVERITY_TO_SCORE.get(str(finding.severity).lower())
    likelihood = _LIKELIHOOD_TO_LEVEL.get(str(finding.likelihood).lower())
    linked = [] if excluded else _protecting(finding, controls)
    if linked and not strategy:
        strategy = "reduce"
    rating = _clean(
        {
            "likelihood": {"level": likelihood} if likelihood else None,
            "impact": {"level": finding.impact} if finding.impact else None,
            "score": {"level": score} if score else None,
        }
    )
    assumption = finding.assumption
    return _clean(
        {
            "bom-ref": ref,
            "name": f"{finding.description} ({finding.target})",
            "statement": finding.details or finding.description,
            "description": (
                f"Excluded by assumption: {assumption.name}" if assumption else ""
            ),
            "domains": [{"type": "security"}],
            "affects": [r for r in [refs.get(finding.element)] if r],
            "relatedThreats": [threat_refs[finding.threat_id]],
            "inherentRisk": rating,
            "responses": (
                [
                    _clean(
                        {
                            "bom-ref": f"response-{ref}",
                            "strategy": strategy,
                            "description": finding.mitigations if not excluded else "",
                            "controls": [r for c in linked if (r := refs.get(c))],
                        }
                    )
                ]
                if strategy
                else []
            ),
            "status": status,
            "properties": _props(cvss=finding.cvss, findingId=finding.id),
        }
    )


def build_tmbom(tm: Any, *, serial: str, timestamp: str, tool_version: str) -> dict:
    """Build the CycloneDX 2.0 TM-BOM document for a resolved threat model.

    Args:
        tm: The ``TM`` instance; ``tm.resolve()`` should already have run so
            findings are populated.
        serial: BOM serial number (``urn:uuid:...``).
        timestamp: RFC 3339 creation time.
        tool_version: Version of pytm to record in the metadata.

    Returns:
        A JSON-serializable dict.
    """
    state = type(tm)
    flows: list[Dataflow] = _unique(state._flows)
    boundaries: list[Boundary] = _unique(state._boundaries)
    endpoints = [e for f in flows for e in (f.source, f.sink)]
    nodes = _unique(
        e
        for e in [*state._elements, *endpoints]
        if isinstance(e, (Actor, Asset)) and not isinstance(e, Datastore)
    )
    actors = [e for e in nodes if isinstance(e, Actor) and e.kind != ActorKind.UNKNOWN]
    assets = [e for e in nodes if e not in actors]
    controls: list[Control] = _unique(state._controls)
    stores = _unique(
        e for e in [*state._elements, *endpoints] if isinstance(e, Datastore)
    )
    data = _unique([*state._data, *(d for f in flows for d in _sorted_data(f.data))])

    placed = [*nodes, *stores]
    needs_unbounded = bool(boundaries) and any(e.inBoundary is None for e in placed)
    unbounded = "zone-unbounded" if needs_unbounded else None

    refs = _Refs()
    if unbounded:
        refs.reserve(unbounded)
    for b in boundaries:
        refs.add("zone", b, b.name)
    for e in actors:
        refs.add("actor", e, e.name)
    for e in assets:
        refs.add("asset", e, e.name)
    for s in stores:
        refs.add("datastore", s, s.name)
    for d in data:
        refs.add("dataset", d, d.name)
    for f in flows:
        refs.add("flow", f, f.name)
    for c in controls:
        refs.add("control", c, c.name)

    findings = list(tm.findings)
    excluded = list(tm.excluded_findings)
    for element in _unique(f.element for f in [*findings, *excluded]):
        refs.add("element", element, element.name)
    threat_refs = {
        f.threat_id: f"threat-{_slug(f.threat_id)}" for f in [*findings, *excluded]
    }

    blueprint = _clean(
        {
            "bom-ref": f"blueprint-{_slug(tm.name)}",
            "name": tm.name,
            "description": tm.description,
            "modelTypes": ["data-flow"],
            "zones": _build_zones(boundaries, refs, unbounded),
            "boundaries": _build_boundaries(boundaries, flows, refs, unbounded),
            "actors": [_build_actor(e, refs, unbounded) for e in actors],
            "assets": [_build_asset(e, refs, unbounded) for e in assets],
            "dataStores": [
                _build_data_store(s, flows, refs, unbounded) for s in stores
            ],
            "dataSets": [_build_data_set(d, flows, refs) for d in data],
            "flows": [_build_flow(f, refs, unbounded) for f in flows],
            "assumptions": _build_assumptions(tm, [*placed, *flows], refs),
        }
    )

    threats = _build_threats([*findings, *excluded], refs, threat_refs, controls)
    patterns = _build_attack_patterns([*findings, *excluded])
    risks = [
        _build_risk(f, f"risk-{f.id}", refs, threat_refs, controls, excluded=False)
        for f in findings
    ] + [
        _build_risk(
            f, f"risk-excluded-{f.id}", refs, threat_refs, controls, excluded=True
        )
        for f in excluded
    ]

    return _clean(
        {
            "$schema": SCHEMA_URL,
            "specFormat": "CycloneDX",
            "specVersion": SPEC_VERSION,
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        _clean(
                            {
                                "type": "application",
                                "name": "pytm",
                                "version": tool_version,
                            }
                        )
                    ]
                },
                "component": _clean(
                    {
                        "type": "application",
                        "bom-ref": f"component-{_slug(tm.name)}",
                        "name": tm.name,
                        "description": tm.description,
                    }
                ),
            },
            "blueprints": [blueprint],
            "threats": (
                _clean({"threats": threats, "attackPatterns": patterns})
                if threats
                else None
            ),
            "risks": {"risks": risks} if risks else None,
            "controls": [_build_control(c, refs) for c in controls],
        }
    )


def _tool_version() -> str:
    """Installed pytm version, or empty when running from a source tree."""
    try:
        return importlib_metadata.version("pytm")
    except importlib_metadata.PackageNotFoundError:
        return ""


def render_tmbom(tm: Any) -> str:
    """Render ``tm`` as an indented TM-BOM JSON string (stamps now/new UUID)."""
    document = build_tmbom(
        tm,
        serial=f"urn:uuid:{uuid.uuid4()}",
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=_tool_version(),
    )
    return json.dumps(document, indent=2)
