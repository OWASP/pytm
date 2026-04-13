"""Process model - represents processes that handle data."""

from typing import TYPE_CHECKING
from pydantic import Field

from .asset import Asset

if TYPE_CHECKING:
    pass


class Process(Asset):
    """An entity processing data.

    Attributes:
        port (int): Default TCP port for incoming data flows
        protocol (str): Default network protocol for incoming data flows
        data (DataSet): pytm.Data object(s) in incoming data flows
        inputs (List[Dataflow]): Incoming Dataflows
        outputs (List[Dataflow]): Outgoing Dataflows
        onAWS (bool): Is this asset on AWS?
        handlesResources (bool): Does this asset handle resources?
        usesEnvironmentVariables (bool): Does this asset use environment variables?
        OS (str): Operating system
        codeType (str): Type of code running in this process
        implementsCommunicationProtocol (bool): Does this process implement a communication protocol?
        tracksExecutionFlow (bool): Does this process track execution flow?
        implementsAPI (bool): Does this process implement an API?
        environment (str): Environment for this process
        allowsClientSideScripting (bool): Does this process allow client-side scripting?
    """

    codeType: str = Field(
        default="Unmanaged", description="Type of code running in this process"
    )
    implementsCommunicationProtocol: bool = Field(
        default=False,
        description="Does this process implement a communication protocol?",
    )
    tracksExecutionFlow: bool = Field(
        default=False, description="Does this process track execution flow?"
    )
    implementsAPI: bool = Field(
        default=False, description="Does this process implement an API?"
    )
    environment: str = Field(default="", description="Environment for this process")
    allowsClientSideScripting: bool = Field(
        default=False, description="Does this process allow client-side scripting?"
    )

    def __init__(self, name: str = None, **data):
        """Initialize a Process.

        Args:
            name (str): Name of the process.
            **data: Optional process properties:
                - port (int): Default TCP port for incoming data flows
                - protocol (str): Default network protocol for incoming data flows
                - data (DataSet): pytm.Data object(s) in incoming data flows
                - inputs (List[Dataflow]): Incoming Dataflows
                - outputs (List[Dataflow]): Outgoing Dataflows
                - onAWS (bool): Is this asset on AWS?
                - handlesResources (bool): Does this asset handle resources?
                - usesEnvironmentVariables (bool): Does this asset use environment variables?
                - OS (str): Operating system
                - codeType (str): Type of code running in this process
                - implementsCommunicationProtocol (bool): Does this process implement a communication protocol?
                - tracksExecutionFlow (bool): Does this process track execution flow?
                - implementsAPI (bool): Does this process implement an API?
                - environment (str): Environment for this process
                - allowsClientSideScripting (bool): Does this process allow client-side scripting?
        """
        super().__init__(name, **data)

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "circle"


class SetOfProcesses(Process):
    """A set of processes grouped together.

    Attributes:
        port (int): Default TCP port for incoming data flows
        protocol (str): Default network protocol for incoming data flows
        data (DataSet): pytm.Data object(s) in incoming data flows
        inputs (List[Dataflow]): Incoming Dataflows
        outputs (List[Dataflow]): Outgoing Dataflows
        onAWS (bool): Is this asset on AWS?
        handlesResources (bool): Does this asset handle resources?
        usesEnvironmentVariables (bool): Does this asset use environment variables?
        OS (str): Operating system
        codeType (str): Type of code running in this process
        implementsCommunicationProtocol (bool): Does this process implement a communication protocol?
        tracksExecutionFlow (bool): Does this process track execution flow?
        implementsAPI (bool): Does this process implement an API?
        environment (str): Environment for this process
        allowsClientSideScripting (bool): Does this process allow client-side scripting?
    """

    def __init__(self, name: str = None, **data):
        """Initialize a SetOfProcesses.

        Args:
            name (str): Name of the set of processes.
            **data: Optional properties:
                - port (int): Default TCP port for incoming data flows
                - protocol (str): Default network protocol for incoming data flows
                - data (DataSet): pytm.Data object(s) in incoming data flows
                - inputs (List[Dataflow]): Incoming Dataflows
                - outputs (List[Dataflow]): Outgoing Dataflows
                - onAWS (bool): Is this asset on AWS?
                - handlesResources (bool): Does this asset handle resources?
                - usesEnvironmentVariables (bool): Does this asset use environment variables?
                - OS (str): Operating system
                - codeType (str): Type of code running in this process
                - implementsCommunicationProtocol (bool): Does this process implement a communication protocol?
                - tracksExecutionFlow (bool): Does this process track execution flow?
                - implementsAPI (bool): Does this process implement an API?
                - environment (str): Environment for this process
                - allowsClientSideScripting (bool): Does this process allow client-side scripting?
        """
        super().__init__(name, **data)

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "doublecircle"
