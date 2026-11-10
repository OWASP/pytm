"""Control model - a safeguard that mitigates one or more threats."""

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .base import Attributes
from .element import Element
from .enums import ControlCategory, ControlStatus

EFFECTIVENESS = ("ineffective", "marginal", "adequate", "good", "excellent")

AttributeRef = tuple[Element, str]


class Control(BaseModel):
    """A safeguard or countermeasure that mitigates threats.

    A ``Control`` is a named object that is declared once, says which threats
    (by SID) it mitigates and which elements it protects. It can point at the
    element attributes (``element.attributes``, e.g. ``sanitizesInput``) that
    realise it, as ``(element, "attributeName")`` pairs.

    Attributes:
        name (str): Name of the control
        description (str): Description of the control
        category (ControlCategory): preventive, detective, corrective, ...
        status (ControlStatus): Implementation status
        mitigates (List[str]): SIDs of the threats this control mitigates
        appliesTo (List[Element]): Elements protected; defaults to the elements
            referenced by ``attributes``, and to the whole model if there are none
        attributes (List[Tuple[Element, str]]): Element attributes that realise
            this control, e.g. ``[(web, "sanitizesInput")]``
        effectiveness (str): ineffective, marginal, adequate, good or excellent
    """

    model_config = ConfigDict(
        extra="allow", validate_assignment=True, arbitrary_types_allowed=True
    )

    name: str = Field(description="Name of the control")
    description: str = Field(default="", description="Description of the control")
    category: ControlCategory = Field(
        default=ControlCategory.UNKNOWN, description="Category of the control"
    )
    status: ControlStatus = Field(
        default=ControlStatus.UNKNOWN, description="Implementation status"
    )
    mitigates: list[str] = Field(
        default_factory=list, description="SIDs of the threats this control mitigates"
    )
    appliesTo: list[Element] = Field(
        default_factory=list,
        description="Elements protected by this control; empty means the whole model",
    )
    attributes: list[AttributeRef] = Field(
        default_factory=list,
        description="(element, attribute name) pairs that realise this control",
    )
    effectiveness: str = Field(
        default="",
        description="Assessed effectiveness: " + ", ".join(EFFECTIVENESS),
    )

    @field_validator("effectiveness")
    @classmethod
    def _check_effectiveness(cls, value: str) -> str:
        value = value.strip().lower()
        if value and value not in EFFECTIVENESS:
            raise ValueError(f"effectiveness must be one of {', '.join(EFFECTIVENESS)}")
        return value

    @field_validator("mitigates", mode="before")
    @classmethod
    def _coerce_mitigates(cls, value):
        """Accept a single SID or Threat objects as well as a list of SIDs."""
        if isinstance(value, str):
            return [value]
        return [getattr(v, "id", v) for v in value or []]

    @field_validator("appliesTo", mode="before")
    @classmethod
    def _coerce_applies_to(cls, value):
        if value is None:
            return []
        return [value] if isinstance(value, Element) else list(value)

    @field_validator("attributes", mode="before")
    @classmethod
    def _coerce_attributes(cls, value):
        """Accept one ``(element, name)`` pair as well as a list of them."""
        if value is None:
            return []
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], Element):
            return [value]
        return list(value)

    @field_validator("attributes")
    @classmethod
    def _check_attributes(cls, value: list[AttributeRef]) -> list[AttributeRef]:
        known = set(Attributes.model_fields)
        for element, attr in value:
            extra = element.attributes.model_extra or {}
            if attr not in known and attr not in extra:
                raise ValueError(f"{element.name} has no attribute {attr!r}")
        return value

    @model_validator(mode="after")
    def _default_applies_to(self) -> "Control":
        """Referenced elements are protected unless appliesTo says otherwise."""
        if self.attributes and not self.appliesTo:
            seen: list[Element] = []
            for element, _ in self.attributes:
                if element not in seen:
                    seen.append(element)
            self.__dict__["appliesTo"] = seen
        return self

    @property
    def satisfied(self) -> bool:
        """True when every referenced attribute is set (False if none are)."""
        return bool(self.attributes) and all(
            getattr(element.attributes, attr, False) for element, attr in self.attributes
        )

    def __init__(self, name: str = None, **data):
        if name is not None:
            data["name"] = name
        super().__init__(**data)
        self._register_with_tm()

    def _register_with_tm(self) -> None:
        """Register this control with the TM class."""
        try:
            from .tm import TM

            TM._controls.append(self)
        except ImportError:
            pass

    def __repr__(self) -> str:
        return f"<{self.__module__}.{type(self).__name__}({self.name})>"

    def __str__(self) -> str:
        return f"Control({self.name})"
