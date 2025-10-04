"""Boundary model - represents trust boundaries in the threat model."""

from typing import List, TYPE_CHECKING
from textwrap import indent
from pydantic import Field, ConfigDict

from .element import Element

if TYPE_CHECKING:
    pass


class Boundary(Element):
    """Trust boundary groups elements and data with the same trust level."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )

    def __init__(self, name: str = None, **data):
        super().__init__(name, **data)
        # Register with TM boundaries
        self._register_with_tm_boundaries()

    def _register_with_tm_boundaries(self):
        """Register this boundary with the TM class."""
        try:
            from .tm import TM
            if self.name not in TM._boundaries:
                TM._boundaries.append(self)
        except ImportError:
            pass

    def _dfd_template(self) -> str:
        """Template for DFD representation."""
        return """subgraph cluster_{uniq_name} {{
    graph [
        fontsize = 10;
        fontcolor = black;
        style = dashed;
        color = {color};
        label = <<i>{label}</i>>;
    ]

{edges}
}}
"""

    def dfd(self, **kwargs) -> str:
        """Generate DFD representation of this boundary."""
        if self.is_drawn:
            return ""

        self.is_drawn = True

        edges = []
        try:
            from .tm import TM
            for e in TM._elements:
                if e.inBoundary != self or e.is_drawn:
                    continue
                # The content to draw can include Boundary objects
                edges.append(e.dfd(**kwargs))
        except ImportError:
            pass

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(**kwargs),
            edges=indent("\n".join(edges), "    "),
        )

    def _color(self, **kwargs) -> str:
        """Get color for DFD representation."""
        if kwargs.get("colormap", False):
            return "black"
        else:
            return "firebrick2"

    def parents(self) -> List['Boundary']:
        """Get parent boundaries."""
        result = []
        parent = self.inBoundary
        while parent is not None:
            result.append(parent)
            parent = parent.inBoundary
        return result