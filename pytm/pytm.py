"""Main pytm module - now using Pydantic models."""

import argparse
import errno
import inspect
import json
import logging
import os
import random
import sys
import uuid as uuid_module
import html
import copy

from pydantic import ValidationError

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from enum import Enum
from functools import lru_cache, singledispatch
from hashlib import sha224
from itertools import combinations
from shutil import rmtree
from textwrap import indent, wrap
from weakref import WeakKeyDictionary
from datetime import datetime

from .template_engine import SuperFormatter

# Import all the new Pydantic models
from .enums import Action, Classification, DatastoreType, Lifetime, TLSVersion
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


def _apply_defaults(flows, data):
    """Apply default values to flows and data."""
    inputs = defaultdict(list)
    outputs = defaultdict(list)
    carriers = defaultdict(set)
    processors = defaultdict(set)

    ASSIGNMENT_ERRORS = (ValueError, AttributeError, TypeError, ValidationError)

    def _add_data(container, value):
        if container is None or value is None:
            return

        from .data import Data  # avoid circular import at module load

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

    for d in data:
        for e in getattr(d, 'carriedBy', []):
            _add_data(getattr(e, 'data', None), d)

    for e in flows:
        source_data = getattr(e.source, 'data', None)
        if source_data:
            _add_data(getattr(e, 'data', None), source_data)

        for d in list(getattr(e, 'data', [])):
            carriers[d].add(e)
            processors[d].add(e.source)
            processors[d].add(e.sink)

        try:
            level_intersection = e.source.levels & e.sink.levels
        except TypeError:
            level_intersection = set()
        if level_intersection:
            e._safeset("levels", level_intersection)

        try:
            sink_overrides = list(getattr(e.sink, 'overrides', []))
            source_overrides = list(getattr(e.source, 'overrides', []))
            combined = list(sink_overrides)
            existing_ids = {getattr(f, 'threat_id', None) for f in combined}
            for finding in source_overrides:
                sid = getattr(finding, 'threat_id', None)
                if sid not in existing_ids:
                    combined.append(finding)
                    existing_ids.add(sid)
            e.overrides = combined
        except ASSIGNMENT_ERRORS:
            pass

        if getattr(e, 'isResponse', False):
            e._safeset("protocol", getattr(e.source, 'protocol', getattr(e, 'protocol', "")))
            e._safeset("srcPort", getattr(e.source, 'port', getattr(e, 'srcPort', -1)))
            if hasattr(e.source, 'controls'):
                e.controls._safeset("isEncrypted", getattr(e.source.controls, 'isEncrypted', False))
            continue

        e._safeset("protocol", getattr(e.sink, 'protocol', getattr(e, 'protocol', "")))
        e._safeset("dstPort", getattr(e.sink, 'port', getattr(e, 'dstPort', -1)))
        if hasattr(e.sink, 'controls'):
            e.controls._safeset("isEncrypted", getattr(e.sink.controls, 'isEncrypted', False))
        if hasattr(e.source, 'controls'):
            e.controls._safeset(
                "authenticatesDestination",
                getattr(e.source.controls, 'authenticatesDestination', False),
            )
            e.controls._safeset(
                "checksDestinationRevocation",
                getattr(e.source.controls, 'checksDestinationRevocation', False),
            )

        for d in list(getattr(e, 'data', [])):
            if getattr(d, 'isStored', False):
                if hasattr(e.sink, 'controls') and hasattr(e.sink.controls, 'isEncryptedAtRest'):
                    d._safeset('isDestEncryptedAtRest', e.sink.controls.isEncryptedAtRest)
                if hasattr(e.source, 'controls') and hasattr(e.source.controls, 'isEncryptedAtRest'):
                    d._safeset('isSourceEncryptedAtRest', e.source.controls.isEncryptedAtRest)
            if getattr(d, 'credentialsLife', Lifetime.NONE) != Lifetime.NONE and not getattr(d, 'isCredentials', False):
                d._safeset('isCredentials', True)
            if getattr(d, 'isCredentials', False) and getattr(d, 'credentialsLife', Lifetime.NONE) == Lifetime.NONE:
                d._safeset('credentialsLife', Lifetime.UNKNOWN)

        inputs[e.sink].append(e)
        outputs[e.source].append(e)

    for asset, flow_list in inputs.items():
        if hasattr(asset, 'inputs'):
            try:
                asset.inputs = flow_list
            except ASSIGNMENT_ERRORS:
                asset.inputs[:] = list(flow_list)

    for asset, flow_list in outputs.items():
        if hasattr(asset, 'outputs'):
            try:
                asset.outputs = flow_list
            except ASSIGNMENT_ERRORS:
                asset.outputs[:] = list(flow_list)

    for d, flow_list in carriers.items():
        ordered_flows = sorted(flow_list, key=lambda f: f.name)
        try:
            setattr(d, 'carriedBy', list(ordered_flows))
        except ASSIGNMENT_ERRORS:
            for flow in ordered_flows:
                if flow not in getattr(d, 'carriedBy', []):
                    d.carriedBy.append(flow)

    for d, elements in processors.items():
        ordered_elements = sorted(elements, key=lambda el: el.name)
        try:
            setattr(d, 'processedBy', list(ordered_elements))
        except ASSIGNMENT_ERRORS:
            for element in ordered_elements:
                if element not in getattr(d, 'processedBy', []):
                    d.processedBy.append(element)



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
            value = [v.__name__ for v in value]
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

            escaped = html.escape(value) if isinstance(value, str) else value
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
        '--describe',
        action='store_true',
        help='describe the available classes and their properties'
    )
    parser.add_argument(
        '--list',
        action='store_true', 
        help='list elements in the model'
    )
    parser.add_argument(
        '--json',
        help='output to JSON file'
    )
    parser.add_argument(
        '--dfd',
        help='output DFD to file'
    )
    parser.add_argument(
        '--seq',
        help='output sequence diagram to file'
    )
    parser.add_argument(
        '--report',
        help='output report using template'
    )
    parser.add_argument(
        '--exclude',
        action='append',
        default=[],
        help='exclude certain threats'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='enable debug output'
    )
    return parser.parse_args()


logger = logging.getLogger(__name__)

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