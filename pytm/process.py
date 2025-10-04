"""Process model - represents processes that handle data."""

from typing import TYPE_CHECKING
from pydantic import Field, ConfigDict

from .asset import Asset

if TYPE_CHECKING:
    pass


class Process(Asset):
    """An entity processing data."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    codeType: str = Field(default="Unmanaged", description="Type of code running in this process")
    implementsCommunicationProtocol: bool = Field(
        default=False,
        description="Does this process implement a communication protocol"
    )
    tracksExecutionFlow: bool = Field(
        default=False,
        description="Does this process track execution flow"
    )
    implementsAPI: bool = Field(default=False, description="Does this process implement an API")
    environment: str = Field(default="", description="Environment for this process")
    allowsClientSideScripting: bool = Field(
        default=False,
        description="Does this process allow client-side scripting"
    )

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "circle"


class SetOfProcesses(Process):
    """A set of processes grouped together."""
    
    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "doublecircle"