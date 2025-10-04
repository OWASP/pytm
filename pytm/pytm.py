import argparse
import html
import copy
import inspect
import logging
import re
import sys

from dataclasses import dataclass, field
from typing import ClassVar

from pydantic import ValidationError
from pydantic.fields import PydanticUndefined

from collections import defaultdict
from collections.abc import Iterable, Mapping
from functools import singledispatch

# Import all the new Pydantic models
from .enums import Action, Classification, DatastoreType, Lifetime, TLSVersion, OrderedEnum
from .base import Assumption, Controls, DataSet
from .element import Element, sev_to_color
from .data import Data
from .threat import Threat
from .finding import Finding
from .asset import Asset, Lambda, Server, ExternalEntity
from .datastore import Datastore
from .actor import Actor
from .process import Process, SetOfProcesses
from .dataflow import Dataflow
from .boundary import Boundary
from .tm import TM, UIError

logger = logging.getLogger(__name__)

# Legacy aliases for backward compatibility
varString = str
varStrings = list
varBoundary = object
varBool = bool
varInt = int
varInts = set
varElement = object
varElements = list
varFindings = list
varAction = Action
varClassification = Classification
varLifetime = Lifetime
varDatastoreType = DatastoreType
varTLSVersion = TLSVersion
varData = list
varControls = Controls
varAssumptions = list
varAssumption = Assumption

# Essential helper functions preserved from original
def _sort(flows, addOrder=False):
    """Sort flows by order."""
    ordered = sorted(flows, key=lambda flow: flow.order)
    if not addOrder:
        return ordered
    for i, flow in enumerate(ordered):
        if flow.order != -1:
            break
        ordered[i].order = i + 1
    return ordered


def _sort_elem(elements):
    """Sort elements."""
    if len(elements) == 0:
        return elements
    orders = {}
    for e in elements:
        try:
            order = e.order
        except AttributeError:
            continue
        if e.source not in orders or orders[e.source] > order:
            orders[e.source] = order
    m = max(orders.values()) + 1
    return sorted(
        elements,
        key=lambda e: (
            orders.get(e, m),
            e.__class__.__name__,
            getattr(e, "order", 0),
            str(e),
        ),
    )


def _iter_subclasses(cls):
    """Yield all subclasses of *cls*, recursively."""
    seen = set()
    stack = [cls]

    while stack:
        current = stack.pop()
        for subclass in getattr(current, "__subclasses__", lambda: [])():
            if subclass in seen:
                continue
            seen.add(subclass)
            yield subclass
            stack.append(subclass)


def _list_elements():
    """List all elements usable in a threat model along with their descriptions."""

    def _print_components(classes):
        entries = sorted(classes, key=lambda cls: cls.__name__)
        if not entries:
            return

        name_width = max(len(entry.__name__) for entry in entries)
        for entry in entries:
            doc = entry.__doc__ or ""
            print(f"{entry.__name__:<{name_width}} -- {doc}")

    print("Elements:")
    _print_components(list(_iter_subclasses(Element)))

    print("\nAtributes:")
    enumerated = set(_iter_subclasses(OrderedEnum))
    enumerated.update({Data, Action, Lifetime})
    _print_components(list(enumerated))


def _describe_classes(class_names):
    """Describe available classes and their attributes for CLI users."""

    registry = {
        name: obj for name, obj in globals().items() if inspect.isclass(obj)
    }

    for cls in _iter_subclasses(Element):
        registry.setdefault(cls.__name__, cls)

    for name in class_names:
        klass = registry.get(name)
        if klass is None:
            logger.error("No such class to describe: %s", name)
            sys.exit(1)

        print(f"{name} class attributes:")

        model_fields = getattr(klass, "model_fields", None)
        if model_fields:
            field_names = sorted(model_fields.keys())
            if not field_names:
                print("  (no attributes)")
            else:
                longest = len(max(field_names, key=len)) + 2
                lpadding = f'\n{" ":<{longest+2}}'
                for field_name in field_names:
                    field_info = model_fields[field_name]
                    docs: list[str] = []
                    description = field_info.description or ""
                    if description:
                        docs.extend(description.split("\n"))
                    if field_info.is_required():
                        docs.append("required")
                    default = field_info.default
                    if default is not PydanticUndefined:
                        docs.append(f"default: {default!r}")
                    elif field_info.default_factory is not None:
                        factory = field_info.default_factory
                        factory_name = getattr(factory, "__name__", repr(factory))
                        docs.append(f"default factory: {factory_name}")

                    if docs:
                        print(f"  {field_name:<{longest}}{lpadding.join(docs)}")
                    else:
                        print(f"  {field_name}")
        elif hasattr(klass, "__members__"):
            members = getattr(klass, "__members__", {})
            if not members:
                print("  (no members)")
            else:
                for member in members:
                    print(f"  {member}")
        else:
            attrs = [
                attr
                for attr in dir(klass)
                if not attr.startswith("_") and not callable(getattr(klass, attr))
            ]
            if not attrs:
                print("  (no attributes)")
            else:
                longest = len(max(attrs, key=len)) + 2
                lpadding = f'\n{" ":<{longest+2}}'
                for attr in sorted(attrs):
                    value = getattr(klass, attr)
                    docs = []
                    doc_attr = getattr(value, "__doc__", None)
                    if isinstance(doc_attr, str):
                        stripped = doc_attr.strip()
                        if stripped:
                            docs.append(stripped)
                    if docs:
                        print(f"  {attr:<{longest}}{lpadding.join(docs)}")
                    else:
                        print(f"  {attr}")

        print()


def _match_responses(flows):
    """Ensure that responses are pointing to requests."""
    index = defaultdict(list)
    for e in flows:
        key = (e.source, e.sink)
        index[key].append(e)
    for e in flows:
        if e.responseTo is not None:
            if not e.isResponse:
                e.isResponse = True
            if e.responseTo.response is None:
                e.responseTo.response = e
        if e.response is not None:
            if not e.response.isResponse:
                e.response.isResponse = True
            if e.response.responseTo is None:
                e.response.responseTo = e

    for e in flows:
        if not e.isResponse or e.responseTo is not None:
            continue
        key = (e.sink, e.source)
        if len(index[key]) == 1:
            e.responseTo = index[key][0]
            index[key][0].response = e

    return flows


def _add_data(container, value):
    """Attach Data objects to a container supporting add/append semantics."""
    if container is None or value is None:
        return

    if isinstance(value, Data):
        items = [value]
    elif hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
        items = list(value)
    else:
        items = [value]

    for item in items:
        if item is None:
            continue
        if hasattr(container, 'add'):
            container.add(item)
        elif hasattr(container, 'append'):
            container.append(item)


@dataclass
class _FlowDefaultsBuilder:
    """Collect and apply default relationships for data flows."""

    inputs: defaultdict[Element, list[Dataflow]] = field(default_factory=lambda: defaultdict(list))
    outputs: defaultdict[Element, list[Dataflow]] = field(default_factory=lambda: defaultdict(list))
    carriers: defaultdict[Data, set[Dataflow]] = field(default_factory=lambda: defaultdict(set))
    processors: defaultdict[Data, set[Element]] = field(default_factory=lambda: defaultdict(set))

    assignment_errors: ClassVar[tuple[type[Exception], ...]] = (ValueError, AttributeError, TypeError, ValidationError)

    def seed_data_relationships(self, data_items: Iterable[Data]) -> None:
        """Ensure data instances are referenced by existing carriers."""
        for datum in data_items:
            for flow in getattr(datum, 'carriedBy', []):
                _add_data(getattr(flow, 'data', None), datum)

    def process_flow(self, flow: Dataflow) -> None:
        """Apply defaults and collect relationships for a single flow."""
        self._inherit_source_data(flow)
        self._index_flow_relationships(flow)
        self._sync_levels(flow)
        self._merge_overrides(flow)

        if getattr(flow, 'isResponse', False):
            self._apply_response_defaults(flow)
            return

        self._apply_forward_defaults(flow)
        self._enrich_data_attributes(flow)
        self.inputs[flow.sink].append(flow)
        self.outputs[flow.source].append(flow)

    def finalize_assets(self) -> None:
        """Populate inputs/outputs on elements once all flows are processed."""
        for asset, flow_list in self.inputs.items():
            self._set_sequence(asset, 'inputs', flow_list)

        for asset, flow_list in self.outputs.items():
            self._set_sequence(asset, 'outputs', flow_list)

    def finalize_data_relationships(self) -> None:
        """Attach carrier and processor metadata to data objects."""
        for datum, flow_list in self.carriers.items():
            ordered = sorted(flow_list, key=lambda f: f.name)
            try:
                setattr(datum, 'carriedBy', list(ordered))
            except self.assignment_errors:
                for flow in ordered:
                    existing = getattr(datum, 'carriedBy', [])
                    if flow not in existing:
                        existing.append(flow)

        for datum, elements in self.processors.items():
            ordered = sorted(elements, key=lambda el: el.name)
            try:
                setattr(datum, 'processedBy', list(ordered))
            except self.assignment_errors:
                for element in ordered:
                    existing = getattr(datum, 'processedBy', [])
                    if element not in existing:
                        existing.append(element)

    def _inherit_source_data(self, flow: Dataflow) -> None:
        source_data = getattr(flow.source, 'data', None)
        if source_data:
            _add_data(getattr(flow, 'data', None), source_data)

    def _index_flow_relationships(self, flow: Dataflow) -> None:
        for datum in list(getattr(flow, 'data', [])):
            self.carriers[datum].add(flow)
            self.processors[datum].add(flow.source)
            self.processors[datum].add(flow.sink)

    @staticmethod
    def _sync_levels(flow: Dataflow) -> None:
        try:
            level_intersection = flow.source.levels & flow.sink.levels
        except TypeError:
            level_intersection = set()
        if level_intersection:
            flow._safeset("levels", level_intersection)

    def _merge_overrides(self, flow: Dataflow) -> None:
        try:
            sink_overrides = list(getattr(flow.sink, 'overrides', []))
            source_overrides = list(getattr(flow.source, 'overrides', []))
            combined = list(sink_overrides)
            existing_ids = {getattr(finding, 'threat_id', None) for finding in combined}
            for finding in source_overrides:
                sid = getattr(finding, 'threat_id', None)
                if sid not in existing_ids:
                    combined.append(finding)
                    existing_ids.add(sid)
            flow.overrides = combined
        except self.assignment_errors:
            pass

    def _apply_response_defaults(self, flow: Dataflow) -> None:
        flow._safeset("protocol", getattr(flow.source, 'protocol', getattr(flow, 'protocol', "")))
        flow._safeset("srcPort", getattr(flow.source, 'port', getattr(flow, 'srcPort', -1)))
        if hasattr(flow.source, 'controls'):
            flow.controls._safeset("isEncrypted", getattr(flow.source.controls, 'isEncrypted', False))

    def _apply_forward_defaults(self, flow: Dataflow) -> None:
        flow._safeset("protocol", getattr(flow.sink, 'protocol', getattr(flow, 'protocol', "")))
        flow._safeset("dstPort", getattr(flow.sink, 'port', getattr(flow, 'dstPort', -1)))
        if hasattr(flow.sink, 'controls'):
            flow.controls._safeset("isEncrypted", getattr(flow.sink.controls, 'isEncrypted', False))
        if hasattr(flow.source, 'controls'):
            flow.controls._safeset(
                "authenticatesDestination",
                getattr(flow.source.controls, 'authenticatesDestination', False),
            )
            flow.controls._safeset(
                "checksDestinationRevocation",
                getattr(flow.source.controls, 'checksDestinationRevocation', False),
            )

    def _enrich_data_attributes(self, flow: Dataflow) -> None:
        for datum in list(getattr(flow, 'data', [])):
            if getattr(datum, 'isStored', False):
                if hasattr(flow.sink, 'controls') and hasattr(flow.sink.controls, 'isEncryptedAtRest'):
                    datum._safeset('isDestEncryptedAtRest', flow.sink.controls.isEncryptedAtRest)
                if hasattr(flow.source, 'controls') and hasattr(flow.source.controls, 'isEncryptedAtRest'):
                    datum._safeset('isSourceEncryptedAtRest', flow.source.controls.isEncryptedAtRest)

            if getattr(datum, 'credentialsLife', Lifetime.NONE) != Lifetime.NONE and not getattr(datum, 'isCredentials', False):
                datum._safeset('isCredentials', True)
            if getattr(datum, 'isCredentials', False) and getattr(datum, 'credentialsLife', Lifetime.NONE) == Lifetime.NONE:
                datum._safeset('credentialsLife', Lifetime.UNKNOWN)

    def _set_sequence(self, obj: Element, attr: str, values: Iterable[Dataflow]) -> None:
        if not hasattr(obj, attr):
            return
        ordered = list(values)
        try:
            setattr(obj, attr, ordered)
        except self.assignment_errors:
            existing = getattr(obj, attr)
            try:
                existing[:] = ordered
            except TypeError:
                if hasattr(existing, 'clear') and hasattr(existing, 'extend'):
                    existing.clear()
                    existing.extend(ordered)
                else:
                    for item in ordered:
                        if item not in existing:
                            existing.append(item)


def _apply_defaults(flows, data):
    """Apply default values to flows and data."""
    builder = _FlowDefaultsBuilder()
    builder.seed_data_relationships(data)

    for flow in flows:
        builder.process_flow(flow)

    builder.finalize_assets()
    builder.finalize_data_relationships()



def _get_elements_and_boundaries(flows):
    """Get elements and boundaries used in flows."""
    elements = set()
    boundaries = set()

    for flow in flows:
        elements.add(flow)
        elements.add(flow.source)
        elements.add(flow.sink)

        source_boundary = getattr(flow.source, 'inBoundary', None)
        if source_boundary is not None:
            boundaries.add(source_boundary)
            for parent in getattr(source_boundary, 'parents', lambda: [])():
                elements.add(parent)
                boundaries.add(parent)

        sink_boundary = getattr(flow.sink, 'inBoundary', None)
        if sink_boundary is not None:
            boundaries.add(sink_boundary)
            for parent in getattr(sink_boundary, 'parents', lambda: [])():
                elements.add(parent)
                boundaries.add(parent)

    return list(elements), list(boundaries)


@singledispatch
def to_serializable(val):
    """Used by default."""
    return str(val)


@to_serializable.register(TM)
def ts_tm(obj):
    """Serialize TM object."""
    return serialize(obj, nested=True)


@to_serializable.register(Controls)
@to_serializable.register(Data)
@to_serializable.register(Threat)
@to_serializable.register(Element)
@to_serializable.register(Finding)
def ts_element(obj):
    """Serialize element objects."""
    return serialize(obj, nested=False)


def serialize(obj, nested=False):
    """Used if *obj* is an instance of TM, Element, Threat or Finding."""

    result = {}
    klass = obj.__class__

    if isinstance(obj, (Actor, Asset)):
        result["__class__"] = klass.__name__

    attribute_names = set()

    if hasattr(obj, '__dict__'):
        attribute_names.update(
            name for name in obj.__dict__.keys() if not name.startswith('__')
        )

    model_fields = getattr(klass, 'model_fields', {})
    attribute_names.update(model_fields.keys())

    computed_fields = getattr(klass, 'model_computed_fields', {})
    attribute_names.update(computed_fields.keys())

    if isinstance(obj, TM):
        attribute_names.update(
            {
                '_actors',
                '_assets',
                '_elements',
                '_flows',
                '_data',
                '_boundaries',
                'assumptions',
                'findings',
                'excluded_findings',
                '_threatsExcluded',
            }
        )

    skip_attrs = {
        '_sf',
        '_duplicate_ignored_attrs',
        '_threats',
        'model_fields',
        'model_computed_fields',
        'model_config',
        'model_post_init',
        'model_extra',
        'model_json_schema',
        'schema',
        'copy',
        'dict',
        'json',
        'parse_file',
        'parse_obj',
        'parse_raw',
        'construct',
        'model_copy',
        'validate',
        'abc_impl',
        'register',
    }

    for attr_name in sorted(attribute_names):
        if attr_name in skip_attrs:
            continue

        if isinstance(obj, Element) and attr_name in {'uuid', '_is_drawn', 'is_drawn'}:
            continue
        if isinstance(obj, Finding) and attr_name == 'element':
            continue

        try:
            value = getattr(obj, attr_name)
        except AttributeError:
            continue

        key = attr_name.lstrip('_')

        if isinstance(obj, TM) and attr_name == '_elements':
            value = [e for e in value if isinstance(e, (Actor, Asset))]

        if value is None:
            result[key] = None
            continue

        if isinstance(value, (Element, Data)):
            value = value.name
        elif hasattr(value, 'model_dump') and not isinstance(value, TM):
            value = value.model_dump()
        elif isinstance(obj, Threat) and attr_name == 'target':
            coerced_targets = []
            for target in value:
                if hasattr(target, '__name__'):
                    coerced_targets.append(target.__name__)
                else:
                    coerced_targets.append(str(target))
            value = coerced_targets
        elif attr_name in {'levels', 'sourceFiles', 'assumptions'}:
            value = list(value)
        elif (
            not nested
            and not isinstance(value, (str, bytes))
            and isinstance(value, Iterable)
            and not isinstance(value, Mapping)
        ):
            coerced = []
            for item in value:
                if isinstance(item, Finding):
                    coerced.append(item.id)
                elif isinstance(item, (Element, Data)):
                    coerced.append(item.name)
                else:
                    coerced.append(item)
            value = coerced

        result[key] = value

    return result


def encode_element_threat_data(obj):
    """Encode element threat data."""
    result = []
    if hasattr(obj, '__iter__'):
        for item in obj:
            if hasattr(item, 'model_dump'):
                result.append(item.model_dump())
            else:
                result.append(serialize(item))
    return result


def encode_threat_data(obj):
    """HTML-encode threat data while preserving attribute access."""
    encoded_threat_data = []

    if obj is None:
        return encoded_threat_data

    if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes)):
        candidates = list(obj)
    else:
        candidates = [obj]

    attrs = [
        "description",
        "details",
        "severity",
        "mitigations",
        "example",
        "id",
        "threat_id",
        "references",
        "condition",
        "cvss",
        "response",
    ]

    from .finding import Finding

    if candidates and isinstance(candidates[0], Finding):
        attrs.append("target")

    def _escape_markdown(text: str) -> str:
        return re.sub(r"(?<!\\)\$", r"\\$", text)

    for entry in candidates:
        if entry is None:
            continue

        clone = copy.deepcopy(entry)

        for attr in attrs:
            try:
                value = getattr(entry, attr)
            except AttributeError:
                continue

            if value is None:
                continue

            if isinstance(value, str):
                value = _escape_markdown(value)
                escaped = html.escape(value)
            else:
                escaped = value
            try:
                setattr(clone, attr, escaped)
            except AttributeError:
                pass

        encoded_threat_data.append(clone)

    return encoded_threat_data


def get_args():
    """Get command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sqldump",
        help=(
            "dumps all threat model elements and findings into the named sqlite file "
            "(erased if exists)"
        ),
    )
    parser.add_argument("--debug", action="store_true", help="print debug messages")
    parser.add_argument("--dfd", action="store_true", help="output DFD")
    parser.add_argument(
        "--report",
        help=(
            "output report using the named template file (sample template file is under docs/template.md)"
        ),
    )
    parser.add_argument("--exclude", help="specify threat IDs to be ignored")
    parser.add_argument("--seq", action="store_true", help="output sequential diagram")
    parser.add_argument("--list", action="store_true", help="list all available threats")
    parser.add_argument("--colormap", action="store_true", help="color the risk in the diagram")
    parser.add_argument(
        "--describe", help="describe the properties available for a given element"
    )
    parser.add_argument(
        "--list-elements",
        dest="list_elements",
        action="store_true",
        help="list all elements which can be part of a threat model",
    )
    parser.add_argument("--json", help="output a JSON file")
    parser.add_argument(
        "--levels",
        type=int,
        nargs="+",
        help="Select levels to be drawn in the threat model (int separated by comma).",
    )
    parser.add_argument(
        "--stale_days",
        type=int,
        help=(
            "checks if the delta between the TM script and the code described by it is "
            "bigger than the specified value in days"
        ),
    )
    return parser.parse_args()

# Backward compatibility: export var descriptor classes that are no longer used
# but might be referenced in existing code
class var:
    """Legacy var descriptor for backward compatibility."""
    def __init__(self, default, required=False, doc="", onSet=None):
        self.default = default
        self.required = required
        self.doc = doc
        self.onSet = onSet

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return getattr(instance, '_value', self.default)

    def __set__(self, instance, value):
        setattr(instance, '_value', value)
        if self.onSet is not None:
            self.onSet(instance, value)