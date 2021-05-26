import inspect
import uuid
import random
from hashlib import sha224
from textwrap import wrap

from pytm.helper import (
    var,
    varString,
    varBool,
    varClassification,
    Classification,
    varFindings,
    varInts,
    varStrings,
    varTLSVersion,
    TLSVersion,
)

from pytm.boundary import varBoundary
from pytm.tm import TM


class varElement(var):
    def __set__(self, instance, value):
        if not isinstance(value, Element):
            raise ValueError(
                "expecting an Element (or inherited) "
                "value, got a {}".format(type(value))
            )
        super().__set__(instance, value)


class varElements(var):
    def __set__(self, instance, value):
        for i, e in enumerate(value):
            if not isinstance(e, Element):
                raise ValueError(
                    "expecting a list of Elements, item number {} is a {}".format(
                        i, type(e)
                    )
                )
        super().__set__(instance, list(value))


class Element:
    """A generic element"""

    name = varString("", required=True)
    description = varString("")
    inBoundary = varBoundary(None, doc="Trust boundary this element exists in")
    inScope = varBool(True, doc="Is the element in scope of the threat model")
    maxClassification = varClassification(
        Classification.UNKNOWN,
        required=False,
        doc="Maximum data classification this element can handle.",
    )
    minTLSVersion = varTLSVersion(
        TLSVersion.NONE,
        required=False,
        doc="""Minimum TLS version required.""",
    )
    findings = varFindings([], doc="Threats that apply to this element")
    overrides = varFindings(
        [],
        doc="""Overrides to findings, allowing to set
a custom response, CVSS score or override other attributes.""",
    )
    levels = varInts({0}, doc="List of levels (0, 1, 2, ...) to be drawn in the model.")
    sourceFiles = varStrings(
        [],
        required=False,
        doc="Location of the source code that describes this element relative to the directory of the model script.",
    )

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        self.uuid = uuid.UUID(int=random.getrandbits(128))
        self._is_drawn = False
        TM._elements.append(self)

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.name, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def _uniq_name(self):
        """ transform name and uuid into a unique string """
        h = sha224(str(self.uuid).encode("utf-8")).hexdigest()
        name = "".join(x for x in self.name if x.isalpha())
        return "{0}_{1}_{2}".format(type(self).__name__.lower(), name, h[:10])

    def check(self):
        return True

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};
    color = {color};
    fontcolor = {color};
    label = "{label}";
    margin = 0.02;
]
"""

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
        )

    def _color(self):
        if self.inScope is True:
            return "black"
        else:
            return "grey69"

    def display_name(self):
        return self.name

    def _label(self):
        return "\\n".join(wrap(self.display_name(), 18))

    def _shape(self):
        return "square"

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass

    def oneOf(self, *elements):
        """ Is self one of a list of Elements """
        for element in elements:
            if inspect.isclass(element):
                if isinstance(self, element):
                    return True
            elif self is element:
                return True
        return False

    def crosses(self, *boundaries):
        """ Does self (dataflow) cross any of the list of boundaries """
        if self.source.inBoundary is self.sink.inBoundary:
            return False
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if (
                    (
                        isinstance(self.source.inBoundary, boundary)
                        and not isinstance(self.sink.inBoundary, boundary)
                    )
                    or (
                        not isinstance(self.source.inBoundary, boundary)
                        and isinstance(self.sink.inBoundary, boundary)
                    )
                    or self.source.inBoundary is not self.sink.inBoundary
                ):
                    return True
            elif (self.source.inside(boundary) and not self.sink.inside(boundary)) or (
                not self.source.inside(boundary) and self.sink.inside(boundary)
            ):
                return True
        return False

    def enters(self, *boundaries):
        """ does self (dataflow) enter into one of the list of boundaries """
        return self.source.inBoundary is None and self.sink.inside(*boundaries)

    def exits(self, *boundaries):
        """ does self (dataflow) exit one of the list of boundaries """
        return self.source.inside(*boundaries) and self.sink.inBoundary is None

    def inside(self, *boundaries):
        """ is self inside of one of the list of boundaries """
        for boundary in boundaries:
            if inspect.isclass(boundary):
                if isinstance(self.inBoundary, boundary):
                    return True
            elif self.inBoundary is boundary:
                return True
        return False

    def _attr_values(self):
        klass = self.__class__
        result = {}
        for i in dir(klass):
            if i.startswith("_") or callable(getattr(klass, i)):
                continue
            attr = getattr(klass, i, {})
            if isinstance(attr, var):
                value = attr.data.get(self, attr.default)
            else:
                value = getattr(self, i)
            result[i] = value
        return result

    def checkTLSVersion(self, flows):
        return any(f.tlsVersion < self.minTLSVersion for f in flows)
