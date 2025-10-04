"""Element model - base class for all threat model elements."""

import hashlib
import inspect
from typing import List, Set, Optional, Any, TYPE_CHECKING
from pydantic import BaseModel, Field, ConfigDict

from .base import Controls, Assumption, FindingList
from .enums import Classification

if TYPE_CHECKING:
    from .finding import Finding


def sev_to_color(sev: int) -> str:
    """Convert severity to color."""
    colors = ["green", "blue", "yellow", "orange", "red"]
    if sev < 0:
        return "green"
    elif sev >= len(colors):
        return "red"
    else:
        return colors[sev]

import uuid as uuid_module
import random
import inspect
from hashlib import sha224
from textwrap import wrap
from typing import List, Optional, Set, Union, TYPE_CHECKING, ForwardRef
from pydantic import BaseModel, Field, model_validator, ConfigDict, field_validator

from .enums import Classification, TLSVersion
from .base import Controls, Assumption

if TYPE_CHECKING:
    from .finding import Finding
    from .boundary import Boundary


def sev_to_color(sev):
    """Calculate the color depending on the severity."""
    if sev == 5:
        return 'firebrick3; fillcolor="#b2222222"; style=filled '
    elif sev <= 4 and sev >= 2:
        return 'gold; fillcolor="#ffd80022"; style=filled'
    elif sev < 2 and sev >= 0:
        return 'darkgreen; fillcolor="#00630022"; style=filled'
    return "black"


class Element(BaseModel):
    """A generic element in the threat model."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True  # Allow UUID and other types
    )
    
    name: str = Field(description="Name of the element")
    description: str = Field(default="", description="Description of the element")
    inBoundary: Optional['Boundary'] = Field(
        default=None,
        description="Trust boundary this element exists in"
    )
    inScope: bool = Field(default=True, description="Is the element in scope of the threat model")
    maxClassification: Classification = Field(
        default=Classification.UNKNOWN,
        description="Maximum data classification this element can handle"
    )
    minTLSVersion: TLSVersion = Field(
        default=TLSVersion.NONE,
        description="Minimum TLS version required"
    )
    findings: List['Finding'] = Field(
        default_factory=list,
        description="Threats that apply to this element"
    )
    overrides: List['Finding'] = Field(
        default_factory=list,
        description="Overrides to findings, allowing to set a custom response, CVSS score or override other attributes"
    )
    assumptions: List[Assumption] = Field(
        default_factory=list,
        description="Assumptions about the element. These optionally allow to exclude threats with the given SIDs"
    )
    levels: Set[int] = Field(
        default_factory=lambda: {0},
        description="List of levels (0, 1, 2, ...) to be drawn in the model"
    )
    sourceFiles: List[str] = Field(
        default_factory=list,
        description="Location of the source code that describes this element relative to the directory of the model script"
    )
    controls: Controls = Field(default_factory=Controls, description="Security controls for this element")
    severity: int = Field(default=0, description="Severity level of threats affecting this element")
    
    # Internal attributes
    uuid: uuid_module.UUID = Field(default_factory=lambda: uuid_module.UUID(int=random.getrandbits(128)))
    is_drawn: bool = Field(default=False, exclude=True)

    _WRITE_ONCE_FIELDS = {"name"}

    @field_validator('levels', mode='before')
    @classmethod
    def _coerce_levels(cls, value):
        """Normalize level inputs to a set of integers."""
        if value is None:
            return {0}

        if isinstance(value, (set, frozenset)):
            return set(value)

        if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
            return set(value)

        return {value}

    def __setattr__(self, key: str, value):
        if (
            key in self._WRITE_ONCE_FIELDS
            and key in self.__dict__
            and not key.startswith("_")
        ):
            raise ValueError(
                f"cannot overwrite {type(self).__name__}.{key} value"
            )
        super().__setattr__(key, value)

    def __init__(self, name: str = None, **data):
        # Handle positional name argument
        if name is not None:
            data['name'] = name
        super().__init__(**data)
        
        # Register with TM (will be imported when needed)
        # This will be handled by the TM class when it's created
        self._register_with_tm()

    def _register_with_tm(self):
        """Register this element with the TM class."""
        # Import here to avoid circular imports
        try:
            from .tm import TM
            TM._elements.append(self)
        except ImportError:
            # TM might not be available yet during initial setup
            pass

    def __repr__(self):
        return f"<{self.__module__}.{type(self).__name__}({self.name}) at {hex(id(self))}>"

    def __str__(self):
        return f"{type(self).__name__}({self.name})"

    def __hash__(self):
        """Make Element objects hashable for use in sets and as dict keys."""
        return hash((type(self).__name__, self.name, id(self)))

    def _uniq_name(self) -> str:
        """Transform name and uuid into a unique string."""
        h = sha224(str(self.uuid).encode("utf-8")).hexdigest()
        name = "".join(x for x in self.name if x.isalpha())
        return f"{type(self).__name__.lower()}_{name}_{h[:10]}"

    def check(self) -> bool:
        """Check if the element is valid."""
        return True

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """{uniq_name} [
    shape = {shape};
    color = {color};
    fontcolor = black;
    label = "{label}";
    margin = 0.02;
]
"""

    def dfd(self, **kwargs) -> str:
        """Generate DFD representation of this element."""
        self.is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        color = self._color()
        if kwargs.get("colormap", False):
            color = sev_to_color(self.severity)

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=color,
            shape=self._shape(),
        )

    def _color(self) -> str:
        """Get the color for this element."""
        return "black"

    def oneOf(self, *elements):
        """Is self one of a list of Elements."""
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries):
        """Does self (dataflow) cross any of the list of boundaries."""
        if not hasattr(self, 'source') or not hasattr(self, 'sink'):
            return False
            
        if self.source.inBoundary is self.sink.inBoundary:
            return False
        
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if (
                    (
                        isinstance(self.source.inBoundary, boundary)
                        and not isinstance(self.sink.inBoundary, boundary)
                    )
                    or (
                        not isinstance(self.source.inBoundary, boundary)
                        and isinstance(self.sink.inBoundary, boundary)
                    )
                    or self.source.inBoundary is not self.sink.inBoundary
                ):
                    return True
            elif (self.source.inside(boundary) and not self.sink.inside(boundary)) or (
                not self.source.inside(boundary) and self.sink.inside(boundary)
            ):
                return True
        return False

    def enters(self, *boundaries):
        """Does self (dataflow) enter into one of the list of boundaries."""
        if not hasattr(self, 'source') or not hasattr(self, 'sink'):
            return False
        return self.source.inBoundary is None and self.sink.inside(*boundaries)

    def exits(self, *boundaries):
        """Does self (dataflow) exit one of the list of boundaries."""
        if not hasattr(self, 'source') or not hasattr(self, 'sink'):
            return False
        return self.source.inside(*boundaries) and self.sink.inBoundary is None

    def inside(self, *boundaries):
        """Is self inside of one of the list of boundaries."""
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if isinstance(self.inBoundary, boundary):
                    return True
            elif self.inBoundary is boundary:
                return True
        return False

    def _set_severity(self, sev: int):
        """Set the severity of this element."""
        sevs = {
            "Low": 0,
            "Medium": 1,
            "High": 2,
            "Critical": 3
        }
        if sev in sevs:
            self.severity = sevs[sev]
        elif isinstance(sev, int):
            self.severity = sev
        else:
            self.severity = 0

    def display_name(self) -> str:
        """Get display name for this element."""
        return self.name

    def _label(self) -> str:
        """Get label for DFD representation."""
        return "\\n".join(wrap(self.display_name(), 18))

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "square"

    def _safeset(self, attr: str, value) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass

    def oneOf(self, *elements) -> bool:
        """Is self one of a list of Elements."""
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries) -> bool:
        """Does self (dataflow) cross any of the list of boundaries."""
        # This method is primarily for dataflows, but defined here for compatibility
        if hasattr(self, 'source') and hasattr(self, 'sink'):
            if self.source.inBoundary is self.sink.inBoundary:
                return False
            for boundary in boundaries:
                if inspect.isclass(boundary):
                    if (
                        (
                            isinstance(self.source.inBoundary, boundary)
                            and not isinstance(self.sink.inBoundary, boundary)
                        )
                        or (
                            not isinstance(self.source.inBoundary, boundary)
                            and isinstance(self.sink.inBoundary, boundary)
                        )
                        or self.source.inBoundary is not self.sink.inBoundary
                    ):
                        return True
                elif (self.source.inside(boundary) and not self.sink.inside(boundary)) or (
                    not self.source.inside(boundary) and self.sink.inside(boundary)
                ):
                    return True
        return False

    def enters(self, *boundaries) -> bool:
        """Does self (dataflow) enter into one of the list of boundaries."""
        # This method is primarily for dataflows, but defined here for compatibility
        if hasattr(self, 'source') and hasattr(self, 'sink'):
            return self.source.inBoundary is None and self.sink.inside(*boundaries)
        return False

    def exits(self, *boundaries) -> bool:
        """Does self (dataflow) exit one of the list of boundaries."""
        # This method is primarily for dataflows, but defined here for compatibility
        if hasattr(self, 'source') and hasattr(self, 'sink'):
            return self.source.inside(*boundaries) and self.sink.inBoundary is None
        return False

    def inside(self, *boundaries) -> bool:
        """Is self inside of one of the list of boundaries."""
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if isinstance(self.inBoundary, boundary):
                    return True
            elif self.inBoundary is boundary:
                return True
        return False

    def _attr_values(self) -> dict:
        """Return a dictionary of all attribute values."""
        return self.model_dump()

    def checkTLSVersion(self, flows) -> bool:
        """Check if any flows have insufficient TLS version."""
        return any(f.tlsVersion < self.minTLSVersion for f in flows)

    def _set_severity(self, sev: str) -> None:
        """Set severity based on string value."""
        sevs = {
            "very high": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "very low": 1,
            "info": 0,
        }

        if sev.lower() not in sevs.keys():
            return

        if self.severity < sevs[sev.lower()]:
            self.severity = sevs[sev.lower()]