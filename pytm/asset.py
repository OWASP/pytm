"""Asset models - base Asset class and specific asset implementations."""

from typing import List, TYPE_CHECKING

from pydantic import Field, field_validator

from .element import Element, sev_to_color
from .base import DataSet

if TYPE_CHECKING:
    from .data import Data
    from .dataflow import Dataflow


class Asset(Element):
    """An asset with outgoing or incoming dataflows."""

    port: int = Field(default=-1, description="Default TCP port for incoming data flows")
    protocol: str = Field(default="", description="Default network protocol for incoming data flows")
    data: DataSet = Field(
        default_factory=DataSet,
        description="pytm.Data object(s) in incoming data flows"
    )
    inputs: List['Dataflow'] = Field(default_factory=list, description="incoming Dataflows")
    outputs: List['Dataflow'] = Field(default_factory=list, description="outgoing Dataflows")
    onAWS: bool = Field(default=False, description="Is this asset on AWS")
    handlesResources: bool = Field(default=False, description="Does this asset handle resources")
    usesEnvironmentVariables: bool = Field(
        default=False,
        description="Does this asset use environment variables"
    )
    OS: str = Field(default="", description="Operating system")
    
    @field_validator('data', mode='before')
    @classmethod
    def validate_data(cls, v):
        """Coerce incoming values to a DataSet."""
        from .data import Data

        if isinstance(v, DataSet):
            return v

        dataset = DataSet()

        if v is None:
            return dataset

        if isinstance(v, Data):
            dataset.add(v)
            return dataset

        if hasattr(v, '__iter__') and not isinstance(v, (str, bytes)):
            for item in v:
                if item is None:
                    continue
                dataset.add(item)
            return dataset

        dataset.add(v)
        return dataset

    def __init__(self, name: str = None, **data):
        super().__init__(name, **data)
        # Register with TM assets
        self._register_with_tm_assets()

    def _register_with_tm_assets(self):
        """Register this asset with the TM class."""
        try:
            from .tm import TM
            TM._assets.append(self)
        except ImportError:
            pass


class Lambda(Asset):
    """A lambda function running in a Function-as-a-Service (FaaS) environment."""
    
    onAWS: bool = Field(default=True, description="Is this lambda on AWS")
    environment: str = Field(default="", description="Environment for the lambda")
    implementsAPI: bool = Field(default=False, description="Does this lambda implement an API")

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """{uniq_name} [
    shape = {shape};

    color = {color};
    fontcolor = "black";
    label = <
        <table border="0" cellborder="0" cellpadding="2">
            <tr><td><b>{label}</b></td></tr>
        </table>
    >;
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

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "rectangle; style=rounded"


class Server(Asset):
    """An entity processing data."""
    
    usesSessionTokens: bool = Field(default=False, description="Does this server use session tokens")
    usesCache: bool = Field(default=False, description="Does this server use cache")
    usesVPN: bool = Field(default=False, description="Does this server use VPN")
    usesXMLParser: bool = Field(default=False, description="Does this server use XML parser")

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "circle"


class ExternalEntity(Asset):
    """An external entity that interacts with the system."""

    hasPhysicalAccess: bool = Field(
        default=False,
        description="Does this external entity have physical access"
    )


class LLM(Asset):
    """A Large Language Model element, either third-party or self-hosted."""

    isThirdParty: bool = Field(default=True, description="Is this LLM a third-party service")
    isSelfHosted: bool = Field(default=False, description="Is this LLM self-hosted")
    processesPersonalData: bool = Field(default=False, description="Does this LLM process personal data")
    retainsUserData: bool = Field(default=False, description="Does this LLM retain user data")
    hasAgentCapabilities: bool = Field(default=False, description="Does this LLM have agent capabilities")
    hasAccessToSensitiveSystems: bool = Field(default=False, description="Does this LLM have access to sensitive systems")
    executesCode: bool = Field(default=False, description="Does this LLM execute code")
    hasContentFiltering: bool = Field(default=False, description="Does this LLM have content filtering")
    hasSystemPrompt: bool = Field(default=True, description="Does this LLM have a system prompt")
    processesUntrustedInput: bool = Field(default=True, description="Does this LLM process untrusted input")
    hasRAG: bool = Field(default=False, description="Does this LLM use retrieval-augmented generation")
    hasFineTuning: bool = Field(default=False, description="Has this LLM been fine-tuned")

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "hexagon"
