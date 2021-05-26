from pytm.element import Element
from pytm.pytm import TM
from pytm.helper import Logger, var
from textwrap import indent


class varBoundary(var):
    def __set__(self, instance, value):
        if not isinstance(value, Boundary):
            raise ValueError("expecting a Boundary value, got a {}".format(type(value)))
        super().__set__(instance, value)


class Boundary(Element):
    """Trust boundary groups elements and data with the same trust level."""

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        if name not in TM._boundaries:
            TM._boundaries.append(self)

    def _dfd_template(self):
        return """subgraph cluster_{uniq_name} {{
    graph [
        fontsize = 10;
        fontcolor = {color};
        style = dashed;
        color = {color};
        label = <<i>{label}</i>>;
    ]

{edges}
}}
"""

    def dfd(self, **kwargs):
        if self._is_drawn:
            return ""

        self._is_drawn = True

        Logger.debug("Now drawing boundary " + self.name)
        edges = []
        for e in TM._elements:
            if e.inBoundary != self or e._is_drawn:
                continue
            # The content to draw can include Boundary objects
            Logger.debug("Now drawing content {}".format(e.name))
            edges.append(e.dfd(**kwargs))
        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            edges=indent("\n".join(edges), "    "),
        )

    def _color(self):
        return "firebrick2"

    def parents(self):
        result = []
        parent = self.inBoundary
        while parent is not None:
            result.append(parent)
            parent = parent.inBoundary
        return result
