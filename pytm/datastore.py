"""Datastore model - represents data storage elements in the threat model."""

from typing import TYPE_CHECKING
from pydantic import Field

from .asset import Asset
from .enums import DatastoreType

if TYPE_CHECKING:
    pass


class Datastore(Asset):
    """An entity storing data.

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
        onRDS (bool): Is this datastore on RDS?
        storesLogData (bool): Does this datastore store log data?
        storesPII (bool): Personally Identifiable Information is any information relating to an identifiable person
        storesSensitiveData (bool): Does this datastore store sensitive data?
        isSQL (bool): Is this a SQL datastore?
        isShared (bool): Is this datastore shared?
        hasWriteAccess (bool): Does this datastore have write access?
        type (DatastoreType): The type of Datastore
    """

    onRDS: bool = Field(default=False, description="Is this datastore on RDS?")
    storesLogData: bool = Field(
        default=False, description="Does this datastore store log data?"
    )
    storesPII: bool = Field(
        default=False,
        description="Personally Identifiable Information is any information relating to an identifiable person",
    )
    storesSensitiveData: bool = Field(
        default=False, description="Does this datastore store sensitive data?"
    )
    isSQL: bool = Field(default=True, description="Is this a SQL datastore?")
    isShared: bool = Field(default=False, description="Is this datastore shared?")
    hasWriteAccess: bool = Field(
        default=False, description="Does this datastore have write access?"
    )
    type: DatastoreType = Field(
        default=DatastoreType.UNKNOWN, description="The type of Datastore"
    )

    def __init__(self, name: str = None, **data):
        """Initialize a Datastore.

        Args:
            name (str): Name of the datastore.
            **data: Optional datastore properties:
                - port (int): Default TCP port for incoming data flows
                - protocol (str): Default network protocol for incoming data flows
                - data (DataSet): pytm.Data object(s) in incoming data flows
                - inputs (List[Dataflow]): Incoming Dataflows
                - outputs (List[Dataflow]): Outgoing Dataflows
                - onAWS (bool): Is this asset on AWS?
                - handlesResources (bool): Does this asset handle resources?
                - usesEnvironmentVariables (bool): Does this asset use environment variables?
                - OS (str): Operating system
                - onRDS (bool): Is this datastore on RDS?
                - storesLogData (bool): Does this datastore store log data?
                - storesPII (bool): Personally Identifiable Information is any information relating to an identifiable person
                - storesSensitiveData (bool): Does this datastore store sensitive data?
                - isSQL (bool): Is this a SQL datastore?
                - isShared (bool): Is this datastore shared?
                - hasWriteAccess (bool): Does this datastore have write access?
                - type (DatastoreType): The type of Datastore
        """
        super().__init__(name, **data)

    def _shape(self) -> str:
        """Get shape for DFD representation.

        Graphviz draws the cylinder natively, so it renders the same way in PNG,
        SVG and every other output format, and follows the colormap colours.
        """
        return "cylinder"
