"""Dataflow model - represents data flows between elements."""

from typing import Optional, List, Union, TYPE_CHECKING
from pydantic import Field, field_validator, model_validator

from .element import Element, sev_to_color
from .enums import Classification, TLSVersion
from .base import DataSet

if TYPE_CHECKING:
    from .data import Data


class Dataflow(Element):
    """A data flow from a source to a sink."""

    source: Element = Field(description="Source element of the data flow")
    sink: Element = Field(description="Sink element of the data flow")
    isResponse: bool = Field(default=False, description="Is a response to another data flow")
    response: Optional['Dataflow'] = Field(
        default=None,
        description="Another data flow that is a response to this one"
    )
    responseTo: Optional['Dataflow'] = Field(
        default=None,
        description="Is a response to this data flow"
    )
    srcPort: int = Field(default=-1, description="Source TCP port")
    dstPort: int = Field(default=-1, description="Destination TCP port")
    tlsVersion: TLSVersion = Field(default=TLSVersion.NONE, description="TLS version used")
    protocol: str = Field(default="", description="Protocol used in this data flow")
    data: DataSet = Field(
        default_factory=DataSet,
        description="pytm.Data object(s) in incoming data flows"
    )
    order: int = Field(default=-1, description="Number of this data flow in the threat model")
    implementsCommunicationProtocol: bool = Field(
        default=False,
        description="Does this flow implement a communication protocol"
    )
    note: str = Field(default="", description="Note about this data flow")
    usesVPN: bool = Field(default=False, description="Does this flow use VPN")
    usesSessionTokens: bool = Field(default=False, description="Does this flow use session tokens")
    
    @field_validator('data', mode='before')
    @classmethod
    def validate_data(cls, v):
        """Convert single Data object to DataSet, handle compatibility."""
        from .data import Data
        
        if isinstance(v, str):
            # Handle legacy string assignment
            return DataSet([Data(
                name="undefined",
                description=v,
                classification=Classification.UNKNOWN
            )])
        
        if isinstance(v, Data):
            # Single Data object
            return DataSet([v])
        
        if hasattr(v, '__iter__') and not isinstance(v, (str, bytes)):
            # Iterable of Data objects
            return DataSet(v)
        
        if isinstance(v, DataSet):
            return v
            
        return DataSet([v])
    
    def __setattr__(self, name, value):
        """Handle bidirectional response relationships during assignment."""
        # Set the attribute first
        super().__setattr__(name, value)

        # Skip relationship setup if we're already in the process of linking
        if getattr(self, '_updating_relationships', False):
            return

        # Set up bidirectional relationships for response/responseTo
        if name == 'responseTo' and value is not None:
            self._link_response_to(value)
        elif name == 'response' and value is not None:
            self._link_response_from(value)

    def _link_response_to(self, target: 'Dataflow') -> None:
        """Link this dataflow as a response to the target dataflow."""
        object.__setattr__(self, '_updating_relationships', True)
        try:
            # Mark this as a response
            if not self.isResponse:
                object.__setattr__(self, 'isResponse', True)
            # Set reverse link on target
            if target.response is None:
                object.__setattr__(target, 'response', self)
        finally:
            object.__setattr__(self, '_updating_relationships', False)

    def _link_response_from(self, source: 'Dataflow') -> None:
        """Link the source dataflow as a response to this dataflow."""
        object.__setattr__(self, '_updating_relationships', True)
        try:
            # Mark source as a response
            if not source.isResponse:
                object.__setattr__(source, 'isResponse', True)
            # Set reverse link on source
            if source.responseTo is None:
                object.__setattr__(source, 'responseTo', self)
        finally:
            object.__setattr__(self, '_updating_relationships', False)
    
    @model_validator(mode='after')
    def setup_response_relationships(self) -> 'Dataflow':
        """Set up bidirectional response relationships after validation."""
        # Set up bidirectional response relationship if responseTo is set
        if self.responseTo is not None:
            if not self.isResponse:
                object.__setattr__(self, 'isResponse', True)
            if self.responseTo.response is None:
                object.__setattr__(self.responseTo, 'response', self)

        # Handle reverse relationship
        if self.response is not None:
            if not self.response.isResponse:
                object.__setattr__(self.response, 'isResponse', True)
            if self.response.responseTo is None:
                object.__setattr__(self.response, 'responseTo', self)

        return self

    def __init__(self, source: Element, sink: Element, name: str, **data):
        # Handle positional arguments
        data['source'] = source
        data['sink'] = sink
        data['name'] = name
        super().__init__(**data)
        # Register with TM flows
        self._register_with_tm_flows()

    def _register_with_tm_flows(self):
        """Register this dataflow with the TM class."""
        try:
            from .tm import TM
            TM._flows.append(self)
        except ImportError:
            pass

    def display_name(self) -> str:
        """Get display name for this dataflow."""
        if self.order == -1:
            return self.name
        return f"({self.order}) {self.name}"

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """{source} -> {sink} [
    color = {color};
    fontcolor = {color};
    dir = {direction};
    label = "{label}";
]
"""

    def dfd(self, mergeResponses: bool = False, **kwargs) -> str:
        """Generate DFD representation of this dataflow."""
        self.is_drawn = True

        levels = kwargs.get("levels", None)
        if (
            levels
            and not levels & self.levels
            and not (levels & self.source.levels and levels & self.sink.levels)
        ):
            return ""

        color = self._color()

        if kwargs.get("colormap", False):
            color = sev_to_color(self.severity)

        direction = "forward"
        label = self._label()
        if mergeResponses and self.response is not None:
            direction = "both"
            label += "\n" + self.response._label()

        return self._dfd_template().format(
            source=self.source._uniq_name(),
            sink=self.sink._uniq_name(),
            direction=direction,
            label=label,
            color=color,
        )

    def hasDataLeaks(self) -> bool:
        """Check if this dataflow has data leaks."""
        return any(
            d.classification > self.source.maxClassification
            or d.classification > self.sink.maxClassification
            or d.classification > self.maxClassification
            for d in self.data
        )
