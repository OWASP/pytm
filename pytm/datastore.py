"""Datastore model - represents data storage elements in the threat model."""

import os
from typing import TYPE_CHECKING
from pydantic import Field, ConfigDict

from .asset import Asset
from .enums import DatastoreType

if TYPE_CHECKING:
    pass


class Datastore(Asset):
    """An entity storing data."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    onRDS: bool = Field(default=False, description="Is this datastore on RDS")
    storesLogData: bool = Field(default=False, description="Does this datastore store log data")
    storesPII: bool = Field(
        default=False,
        description="Personally Identifiable Information is any information relating to an identifiable person"
    )
    storesSensitiveData: bool = Field(
        default=False,
        description="Does this datastore store sensitive data"
    )
    isSQL: bool = Field(default=True, description="Is this a SQL datastore")
    isShared: bool = Field(default=False, description="Is this datastore shared")
    hasWriteAccess: bool = Field(default=False, description="Does this datastore have write access")
    type: DatastoreType = Field(
        default=DatastoreType.UNKNOWN,
        description="The type of Datastore"
    )

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """{uniq_name} [
    shape = {shape};
    fixedsize = shape;
    image = "{image}";
    imagescale = true;
    color = {color};
    fontcolor = black;
    xlabel = "{label}";
    label = "";
]
"""

    def _shape(self) -> str:
        """Get shape for DFD representation."""
        return "none"

    def dfd(self, **kwargs) -> str:
        """Generate DFD representation of this element."""
        from .element import sev_to_color
        
        self.is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        color = self._color()
        color_file = "black"

        if kwargs.get("colormap", False):
            color = sev_to_color(self.severity)
            color_file = color.split(";")[0]

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=color,
            shape=self._shape(),
            image=os.path.join(
                os.path.dirname(__file__), "images", f"datastore_{color_file}.png"
            ),
        )