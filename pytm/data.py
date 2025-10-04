"""Data model - represents data that traverses the threat model."""

from typing import List, TYPE_CHECKING
from pydantic import BaseModel, Field, ConfigDict

from .enums import Classification, Lifetime

if TYPE_CHECKING:
    from .element import Element
    from .dataflow import Dataflow


class Data(BaseModel):
    """Represents a single piece of data that traverses the system."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True
    )
    
    name: str = Field(description="Name of the data")
    description: str = Field(default="", description="Description of the data")
    format: str = Field(default="", description="Format of the data")
    classification: Classification = Field(
        default=Classification.UNKNOWN,
        description="Level of classification for this piece of data"
    )
    isPII: bool = Field(
        default=False,
        description="Does the data contain personally identifiable information. Should always be encrypted both in transmission and at rest."
    )
    isCredentials: bool = Field(
        default=False,
        description="Does the data contain authentication information, like passwords or cryptographic keys, with or without expiration date. Should always be encrypted in transmission. If stored, they should be hashed using a cryptographic hash function."
    )
    credentialsLife: Lifetime = Field(
        default=Lifetime.NONE,
        description="Credentials lifetime, describing if and how credentials can be revoked"
    )
    isStored: bool = Field(
        default=False,
        description="Is the data going to be stored by the target or only processed. If only derivative data is stored (a hash) it can be set to False."
    )
    isDestEncryptedAtRest: bool = Field(
        default=False,
        description="Is data encrypted at rest at dest"
    )
    isSourceEncryptedAtRest: bool = Field(
        default=False,
        description="Is data encrypted at rest at source"
    )
    carriedBy: List['Dataflow'] = Field(
        default_factory=list,
        description="Dataflows that carries this piece of data"
    )
    processedBy: List['Element'] = Field(
        default_factory=list,
        description="Elements that store/process this piece of data"
    )

    def __init__(self, name: str = None, **data):
        # Handle positional name argument
        if name is not None:
            data['name'] = name
        super().__init__(**data)
        
        # Register with TM
        self._register_with_tm()

    def _register_with_tm(self):
        """Register this data with the TM class."""
        try:
            from .tm import TM
            TM._data.append(self)
        except ImportError:
            # TM might not be available yet during initial setup
            pass

    def __repr__(self):
        return f"<{self.__module__}.{type(self).__name__}({self.name}) at {hex(id(self))}>"

    def __str__(self):
        return f"Data({self.name})"

    def __hash__(self):
        """Make Data objects hashable for use in sets."""
        return hash((self.name, self.description, self.format, self.classification))

    def _safeset(self, attr: str, value) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass