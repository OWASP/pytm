"""TM (Threat Model) - the main container for all threat model elements."""

import copy
import os
import json
import random
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from itertools import combinations
from textwrap import indent
from typing import ClassVar, Dict, List, Optional, TYPE_CHECKING
from html import escape as html_escape

from pydantic import BaseModel, Field, ConfigDict, field_validator

from .enums import Action
from .base import Assumption
from .template_engine import SuperFormatter

if TYPE_CHECKING:
    from .element import Element
    from .asset import Asset
    from .actor import Actor
    from .dataflow import Dataflow
    from .boundary import Boundary
    from .data import Data
    from .threat import Threat
    from .finding import Finding


class UIError(Exception):
    """Exception for UI-related errors."""
    def __init__(self, e, context):
        self.error = e
        self.context = context


@dataclass
class TMState:
    """Mutable registry for TM-owned collections."""

    flows: List['Dataflow'] = field(default_factory=list)
    elements: List['Element'] = field(default_factory=list)
    actors: List['Actor'] = field(default_factory=list)
    assets: List['Asset'] = field(default_factory=list)
    threats: List['Threat'] = field(default_factory=list)
    boundaries: List['Boundary'] = field(default_factory=list)
    data: List['Data'] = field(default_factory=list)
    threats_excluded: List[str] = field(default_factory=list)


class _StateAttribute:
    """Descriptor that proxies attribute access to the shared TM state."""

    def __init__(self, field_name: str):
        self.field_name = field_name
        self.owner: type['TM'] | None = None

    def __set_name__(self, owner, name):
        self.owner = owner
        register = getattr(owner, '_register_state_attribute', None)
        if callable(register):
            register(name, self)

    def __get__(self, instance, owner=None):
        owner = owner or self.owner
        if owner is None:
            raise AttributeError("State attribute descriptor is unbound")
        return getattr(owner._state, self.field_name)

    def __set__(self, instance, value):
        owner = self.owner if instance is None else type(instance)
        if owner is None:
            raise AttributeError("State attribute descriptor is unbound")
        setattr(owner._state, self.field_name, value)


class TMModelMetaclass(type(BaseModel)):
    """Metaclass that keeps TM state descriptors intact on class assignment."""

    def __setattr__(cls, name, value):
        state_attrs = getattr(cls, '_state_attributes', None)
        if state_attrs and name in state_attrs:
            descriptor = state_attrs[name]
            descriptor.__set__(None, value)
            return
        super().__setattr__(name, value)


class TM(BaseModel, metaclass=TMModelMetaclass):
    """Describes the threat model administratively, and holds all details during a run."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )

    _state: ClassVar[TMState] = TMState()
    _state_attributes: ClassVar[Dict[str, _StateAttribute]] = {}

    @classmethod
    def _register_state_attribute(cls, name: str, descriptor: _StateAttribute) -> None:
        cls._state_attributes[name] = descriptor
    _flows: ClassVar[_StateAttribute] = _StateAttribute('flows')
    _elements: ClassVar[_StateAttribute] = _StateAttribute('elements')
    _actors: ClassVar[_StateAttribute] = _StateAttribute('actors')
    _assets: ClassVar[_StateAttribute] = _StateAttribute('assets')
    _threats: ClassVar[_StateAttribute] = _StateAttribute('threats')
    _boundaries: ClassVar[_StateAttribute] = _StateAttribute('boundaries')
    _data: ClassVar[_StateAttribute] = _StateAttribute('data')
    _threatsExcluded: ClassVar[_StateAttribute] = _StateAttribute('threats_excluded')

    @classmethod
    def _get_state(cls) -> TMState:
        """Return the mutable shared state for this TM class."""
        return cls._state
    
    name: str = Field(description="Model name")
    description: str = Field(description="Model description")
    threatsFile: str = Field(
        default_factory=lambda: os.path.dirname(__file__) + "/threatlib/threats.json",
        description="JSON file with custom threats"
    )
    isOrdered: bool = Field(default=False, description="Automatically order all Dataflows")
    mergeResponses: bool = Field(default=False, description="Merge response edges in DFDs")
    ignoreUnused: bool = Field(
        default=False,
        description="Ignore elements not used in any Dataflow"
    )
    findings: List['Finding'] = Field(
        default_factory=list,
        description="Threats found for elements of this model"
    )
    excluded_findings: List['Finding'] = Field(
        default_factory=list,
        description="Threats found for elements of this model, that were excluded on a per-element basis, using the Assumptions class"
    )
    onDuplicates: Action = Field(
        default=Action.NO_ACTION,
        description="How to handle duplicate Dataflow with same properties, except name and notes"
    )
    assumptions: List[Assumption] = Field(
        default_factory=list,
        description="A list of assumptions about the design/model"
    )
    colormap: bool = Field(default=False, exclude=True)

    def __init__(self, name: str, description: str = "", **data):
        """Initialize the threat model."""
        data.update({
            'name': name,
            'description': description
        })

        object.__setattr__(self, "_initializing_tm", True)
        super().__init__(**data)
        object.__setattr__(self, "_initializing_tm", False)

        self._sf = SuperFormatter()
        random.seed(0)

        try:
            self._init_threats()
        except UIError as e:
            raise e
        finally:
            if hasattr(self, "_initializing_tm"):
                object.__delattr__(self, "_initializing_tm")

    def __setattr__(self, name, value):
        if name == "threatsFile" and not getattr(self, "_initializing_tm", False):
            current_value = getattr(self, "threatsFile", None)
            if current_value == value:
                return super().__setattr__(name, value)

            super().__setattr__(name, value)
            try:
                self._init_threats()
            except UIError as e:
                object.__setattr__(self, "_initializing_tm", True)
                try:
                    super().__setattr__(name, current_value)
                finally:
                    object.__setattr__(self, "_initializing_tm", False)

                if current_value is not None:
                    try:
                        self._init_threats()
                    except UIError:
                        TM._get_state().threats.clear()
                raise e
            return

        super().__setattr__(name, value)

    @classmethod
    def reset(cls):
        """Reset all class variables."""
        cls._state = TMState()

    def _init_threats(self):
        """Initialize threats from file."""
        TM._get_state().threats.clear()
        self._add_threats()

    def _add_threats(self):
        """Add threats from the threats file."""
        try:
            with open(self.threatsFile, "r", encoding="utf8") as threat_file:
                threats_json = json.load(threat_file)
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            raise UIError(
                e, f"while trying to open the threat file ({self.threatsFile})."
            )
        
        from .threat import Threat
        active_threats = (threat for threat in threats_json if "DEPRECATED" not in threat)
        for threat in active_threats:
            TM._threats.append(Threat(**threat))
    
    def check(self):
        """Check the threat model for consistency and completeness."""
        if self.description is None:
            raise ValueError(
                """Every threat model should have at least
a brief description of the system being modeled."""
            )

        from . import pytm as pytm_module

        state = TM._get_state()
        state.flows = pytm_module._match_responses(
            pytm_module._sort(state.flows, getattr(self, 'isOrdered', False))
        )

        self._check_duplicates(state.flows)

        pytm_module._apply_defaults(state.flows, state.data)

        for element in state.elements:
            top = Counter(
                getattr(f, 'threat_id', None) for f in getattr(element, 'overrides', [])
            ).most_common(1)
            if not top:
                continue
            threat_id, count = top[0]
            if count != 1:
                raise ValueError(
                    f"Finding {threat_id} have more than one override in {element}"
                )

        if getattr(self, 'ignoreUnused', False):
            elements, boundaries = pytm_module._get_elements_and_boundaries(state.flows)
            state.elements = elements
            state.boundaries = boundaries

        result = True
        for element in state.elements:
            if not element.check():
                result = False

        if getattr(self, 'ignoreUnused', False):
            state.elements = pytm_module._sort_elem(state.elements)

        return result
    
    def resolve(self):
        """Resolve threats and generate findings."""
        from .finding import Finding
        from collections import defaultdict
        
        finding_count = 0
        excluded_finding_count = 0
        findings = []
        excluded_findings = []
        
        # Get global assumptions with exclusions
        global_assumptions = [a for a in self.assumptions if len(a.exclude) > 0]
        elements = defaultdict(list)
        
        for e in TM._elements:
            if not getattr(e, 'inScope', True):
                e.findings = findings
                continue

            override_ids = set(f.threat_id for f in getattr(e, 'overrides', []))
            
            # Filter out overrides from source and sink for dataflows
            try:
                source_overrides = set(f.threat_id for f in getattr(e.source, 'overrides', []))
                sink_overrides = set(f.threat_id for f in getattr(e.sink, 'overrides', []))
                override_ids -= source_overrides | sink_overrides
            except AttributeError:
                pass

            for t in TM._threats:
                if not t.apply(e) and t.id not in override_ids:
                    continue

                if t.id in TM._threatsExcluded:
                    continue

                _continue = False
                element_assumptions = getattr(e, 'assumptions', [])
                for assumption in element_assumptions + global_assumptions:
                    if hasattr(assumption, 'exclude') and t.id in assumption.exclude:
                        excluded_finding_count += 1
                        f = Finding(e, id=str(excluded_finding_count), threat=t, assumption=assumption)
                        excluded_findings.append(f)
                        _continue = True
                        break
                if _continue:
                    continue

                finding_count += 1
                f = Finding(e, id=str(finding_count), threat=t)
                findings.append(f)
                elements[e].append(f)
                
                # Set severity on element
                if hasattr(e, '_set_severity'):
                    e._set_severity(getattr(f, 'severity', 0))
        
        self.findings = findings
        self.excluded_findings = excluded_findings
        
        for e, findings in elements.items():
            e.findings = findings
    
    def _dfd_template(self):
        """Template for DFD generation."""
        return (
            "digraph tm {{\n"
            "    graph [\n"
            "        fontname = Arial;\n"
            "        fontsize = 14;\n"
            "    ]\n"
            "    node [\n"
            "        fontname = Arial;\n"
            "        fontsize = 14;\n"
            "        rankdir = lr;\n"
            "    ]\n"
            "    edge [\n"
            "        shape = none;\n"
            "        arrowtail = onormal;\n"
            "        fontname = Arial;\n"
            "        fontsize = 12;\n"
            "    ]\n"
            "    labelloc = \"t\";\n"
            "    fontsize = 20;\n"
            "    nodesep = 1;\n"
            "\n"
            "{edges}\n"
            "\n"
            "}}"
        )

    def dfd(self, **kwargs):
        """Generate Data Flow Diagram."""
        from collections import defaultdict
        from .boundary import Boundary
        
        if "levels" in kwargs:
            levels = kwargs["levels"]
            if not hasattr(levels, '__iter__') or isinstance(levels, str):
                kwargs["levels"] = [levels]
            kwargs["levels"] = set(kwargs["levels"])

        edges = []
        # Since boundaries can be nested sort them by level and start from top
        parents = set(b.inBoundary for b in TM._boundaries if b.inBoundary)

        # Collect boundary levels
        boundary_levels = defaultdict(set)
        max_level = 0
        for b in TM._boundaries:
            if b in parents:
                continue
            boundary_levels[0].add(b)
            for i, p in enumerate(getattr(b, 'parents', lambda: [])(), 1):
                boundary_levels[i].add(p)
                if i > max_level:
                    max_level = i

        # Draw boundaries from highest level to lowest
        for i in range(max_level, -1, -1):
            for b in sorted(boundary_levels[i], key=lambda b: b.name):
                edges.append(b.dfd(**kwargs))

        # Handle response merging
        if getattr(self, 'mergeResponses', False):
            for e in TM._flows:
                if getattr(e, 'response', None) is not None:
                    e.response.is_drawn = True
        kwargs["mergeResponses"] = getattr(self, 'mergeResponses', False)
        
        # Draw elements that are not boundaries and not inside boundaries
        for e in TM._elements:
            if not getattr(e, 'is_drawn', False) and not isinstance(e, Boundary) and getattr(e, 'inBoundary', None) is None:
                edges.append(e.dfd(**kwargs))

        def indent(text, prefix):
            """Add prefix to each line of text."""
            return '\n'.join(prefix + line if line.strip() else line for line in text.splitlines())

        return self._dfd_template().format(
            edges=indent("\n".join(filter(len, edges)), "    ")
        )

    def _seq_template(self):
        """Template for sequence diagram generation."""
        return """@startuml
{participants}

{messages}
@enduml"""

    def seq(self):
        """Generate sequence diagram."""
        from .actor import Actor
        from .datastore import Datastore
        from .boundary import Boundary
        from .dataflow import Dataflow
        
        participants = []
        for e in TM._elements:
            if isinstance(e, Actor):
                participants.append(
                    'actor {0} as "{1}"'.format(e._uniq_name(), getattr(e, 'display_name', lambda: e.name)())
                )
            elif isinstance(e, Datastore):
                participants.append(
                    'database {0} as "{1}"'.format(e._uniq_name(), getattr(e, 'display_name', lambda: e.name)())
                )
            elif not isinstance(e, (Dataflow, Boundary)):
                participants.append(
                    'entity {0} as "{1}"'.format(e._uniq_name(), getattr(e, 'display_name', lambda: e.name)())
                )

        messages = []
        for e in TM._flows:
            message = "{0} -> {1}: {2}".format(
                e.source._uniq_name(), e.sink._uniq_name(), getattr(e, 'display_name', lambda: e.name)()
            )
            note = ""
            if getattr(e, 'note', '') != "":
                note = "\nnote left\n{}\nend note".format(e.note)
            messages.append("{}{}".format(message, note))

        return self._seq_template().format(
            participants="\n".join(participants), messages="\n".join(messages)
        )

    def report(self, template_path):
        """Generate report from template."""

        try:
            with open(template_path) as file:
                template = file.read()
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            from .pytm import UIError
            raise UIError(
                e, f"while trying to open the report template file ({template_path})."
            )

        def _clone(obj):
            copy_method = getattr(obj, 'model_copy', None)
            if callable(copy_method):
                return copy_method(deep=True)
            return copy.deepcopy(obj)

        def encode_threat_data(obj):
            """Encode threat data for HTML output."""
            encoded_threat_data = []
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

            items = obj if isinstance(obj, list) else [obj]

            for entry in items:
                if entry is None:
                    continue

                clone = _clone(entry)

                for attr in attrs:
                    value = getattr(entry, attr, None)
                    if isinstance(value, str):
                        setattr(clone, attr, html_escape(value))

                encoded_threat_data.append(clone)
            return encoded_threat_data

        def encode_element_threat_data(elements):
            """Encode element threat data for HTML output."""
            from .base import DataSet

            encoded_elements = []
            for element in elements:
                if element is None:
                    continue

                element_copy = _clone(element)

                attribute_sources = {}

                if hasattr(element, '__dict__'):
                    attribute_sources.update({k: v for k, v in element.__dict__.items() if not k.startswith('_')})

                model_fields = getattr(element.__class__, 'model_fields', {})
                for attr_name in model_fields:
                    attribute_sources.setdefault(attr_name, getattr(element, attr_name, None))

                fields_set = getattr(element_copy, '__pydantic_fields_set__', None)

                for attr_name, original_value in attribute_sources.items():
                    if attr_name == 'findings':
                        findings_value = encode_threat_data(getattr(element, 'findings', []))
                        object.__setattr__(element_copy, 'findings', findings_value)
                        if isinstance(fields_set, set):
                            fields_set.add('findings')
                        continue

                    value = getattr(element, attr_name, None)

                    if isinstance(value, DataSet):
                        if len(value) == 0:
                            value = '[]'
                    elif isinstance(value, set):
                        value = list(value)

                    if isinstance(value, list) and len(value) == 0:
                        value = '[]'

                    object.__setattr__(element_copy, attr_name, value)
                    if isinstance(fields_set, set):
                        fields_set.add(attr_name)

                encoded_elements.append(element_copy)
            return encoded_elements

        threats = encode_threat_data(TM._threats)
        findings = encode_threat_data(getattr(self, 'findings', []))

        elements = encode_element_threat_data(TM._elements)
        assets = encode_element_threat_data(TM._assets)
        actors = encode_element_threat_data(TM._actors)
        boundaries = encode_element_threat_data(TM._boundaries)
        flows = encode_element_threat_data(TM._flows)

        data = {
            "tm": self,
            "dataflows": flows,
            "threats": threats,
            "findings": findings,
            "elements": elements,
            "assets": assets,
            "actors": actors,
            "boundaries": boundaries,
            "data": TM._data,
        }

        if not hasattr(self, '_sf') or self._sf is None:
            self._sf = SuperFormatter()

        return self._sf.format(template, **data)

    def _check_duplicates(self, flows):
        """Ensure duplicate dataflows are handled according to configuration."""
        if getattr(self, 'onDuplicates', Action.NO_ACTION) == Action.NO_ACTION:
            return

        index = defaultdict(list)
        for flow in flows:
            key = (flow.source, flow.sink)
            index[key].append(flow)

        for grouped_flows in index.values():
            for left, right in combinations(grouped_flows, 2):
                left_attrs = left._attr_values()
                right_attrs = right._attr_values()
                for attr in self._duplicate_ignored_attrs:
                    left_attrs.pop(attr, None)
                    right_attrs.pop(attr, None)
                if left_attrs != right_attrs:
                    continue
                left_controls = getattr(left, 'controls', None)
                right_controls = getattr(right, 'controls', None)
                if left_controls is not None and right_controls is not None:
                    if left_controls._attr_values() != right_controls._attr_values():
                        continue
                if self.onDuplicates == Action.IGNORE:
                    right.is_drawn = True
                    continue
                raise ValueError(
                    "Duplicate Dataflow found between {} and {}: {} is same as {}".format(
                        left.source,
                        left.sink,
                        left,
                        right,
                    )
                )

# Initialize class variables
TM.reset()
TM._sf = None
TM._duplicate_ignored_attrs = (
    "name", "note", "order", "response", "responseTo", "controls", "uuid"
)