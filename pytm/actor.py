"""Actor model - represents entities that initiate actions."""

from typing import TYPE_CHECKING, List
from pydantic import Field, field_validator

from .element import Element
from .base import DataSet

if TYPE_CHECKING:
    from .dataflow import Dataflow


class Actor(Element):
    """An entity usually initiating actions.

    Actors represent users or external systems that initiate
    interactions with the system being modeled.

    Attributes:
        port (int): Default TCP port for outgoing data flows
        protocol (str): Default network protocol for outgoing data flows
        data (DataSet): pytm.Data object(s) in outgoing data flows
        inputs (List[Dataflow]): Incoming Dataflows
        outputs (List[Dataflow]): Outgoing Dataflows
        isAdmin (bool): Indicates whether the actor has administrative privileges
    """

    port: int = Field(
        default=-1, description="Default TCP port for outgoing data flows"
    )
    protocol: str = Field(
        default="", description="Default network protocol for outgoing data flows"
    )
    data: DataSet = Field(
        default_factory=DataSet,
        description="pytm.Data object(s) in outgoing data flows",
    )
    inputs: List["Dataflow"] = Field(
        default_factory=list, description="Incoming Dataflows"
    )
    outputs: List["Dataflow"] = Field(
        default_factory=list, description="Outgoing Dataflows"
    )
    isAdmin: bool = Field(
        default=False,
        description="Indicates whether the actor has administrative privileges",
    )

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_dataset(cls, v):
        """Ensure actor data is stored as a DataSet."""
        from .data import Data  # Local import to avoid circular dependency

        if isinstance(v, DataSet):
            return v

        dataset = DataSet()

        if v is None:
            return dataset

        if isinstance(v, Data):
            dataset.add(v)
            return dataset

        if hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            for item in v:
                if item is None:
                    continue
                dataset.add(item)
            return dataset

        dataset.add(v)
        return dataset

    def __init__(self, name: str = None, **data):
        """
        Initialize an Actor.

        Args:
            name (str): Name of the actor.
            **data: Optional actor properties:
                - port (int): Default TCP port for outgoing data flows
                - protocol (str): Default network protocol for outgoing data flows
                - data (DataSet): pytm.Data object(s) in outgoing data flows
                - inputs (List[Dataflow]): Incoming Dataflows
                - outputs (List[Dataflow]): Outgoing Dataflows
                - isAdmin (bool): Indicates whether the actor has administrative privileges
        """
        super().__init__(name, **data)
        # Register with TM actors
        self._register_with_tm_actors()

    def _register_with_tm_actors(self):
        """Register this actor with the TM class."""
        try:
            from .tm import TM

            TM._actors.append(self)
        except ImportError:
            pass
