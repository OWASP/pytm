"""Base models and utilities for pytm Pydantic models."""

from typing import Any, Iterable, List, Set, Union, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from .element import Element
    from .data import Data
    from .threat import Threat
    from .finding import Finding


class DataSet(set):
    """Custom set for Data objects with string lookup capability."""

    __slots__ = ("_names",)

    def __init__(self, values: Iterable['Data'] | None = None):
        super().__init__()
        self._names: Set[str] = set()
        if values is not None:
            self.update(values)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return item in self._names
        return super().__contains__(item)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, set):
            return super().__eq__(other)
        if isinstance(other, str):
            return other in self
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, set):
            return super().__ne__(other)
        if isinstance(other, str):
            return other not in self
        return NotImplemented

    def __str__(self) -> str:
        return ", ".join(sorted(self._names))

    def add(self, element: Any) -> None:  # type: ignore[override]
        super().add(element)
        self._register(element)

    def update(self, *others: Iterable[Any]) -> None:  # type: ignore[override]
        for iterable in others:
            for element in iterable:
                super().add(element)
                self._register(element)

    def discard(self, element: Any) -> None:  # type: ignore[override]
        if super().__contains__(element):
            super().discard(element)
            self._unregister(element)

    def remove(self, element: Any) -> None:  # type: ignore[override]
        super().remove(element)
        self._unregister(element)

    def pop(self) -> Any:  # type: ignore[override]
        element = super().pop()
        self._unregister(element)
        return element

    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        self._names.clear()

    def _register(self, element: 'Data') -> None:
        name = getattr(element, 'name', None)
        if isinstance(name, str):
            self._names.add(name)

    def _unregister(self, element: 'Data') -> None:
        name = getattr(element, 'name', None)
        if isinstance(name, str):
            self._names.discard(name)


class Controls(BaseModel):
    """Controls implemented by/on an Element."""
    
    model_config = ConfigDict(extra='allow')
    
    authenticatesDestination: bool = Field(
        default=False,
        description="Verifies the identity of the destination, for example by verifying the authenticity of a digital certificate."
    )
    authenticatesSource: bool = False
    authenticationScheme: str = ""
    authorizesSource: bool = False
    checksDestinationRevocation: bool = Field(
        default=False,
        description="Correctly checks the revocation status of credentials used to authenticate the destination"
    )
    checksInputBounds: bool = False
    definesConnectionTimeout: bool = False
    disablesDTD: bool = False
    disablesiFrames: bool = False
    encodesHeaders: bool = False
    encodesOutput: bool = False
    encryptsCookies: bool = False
    encryptsSessionData: bool = False
    handlesCrashes: bool = False
    handlesInterruptions: bool = False
    handlesResourceConsumption: bool = False
    hasAccessControl: bool = False
    implementsAuthenticationScheme: bool = False
    implementsCSRFToken: bool = False
    implementsNonce: bool = Field(
        default=False,
        description="Nonce is an arbitrary number that can be used just once in a cryptographic communication."
    )
    implementsPOLP: bool = Field(
        default=False,
        description="The principle of least privilege (PoLP) requires that every module must be able to access only the information and resources that are necessary for its legitimate purpose."
    )
    implementsServerSideValidation: bool = False
    implementsStrictHTTPValidation: bool = False
    invokesScriptFilters: bool = False
    isEncrypted: bool = Field(default=False, description="Requires incoming data flow to be encrypted")
    isEncryptedAtRest: bool = Field(default=False, description="Stored data is encrypted at rest")
    isHardened: bool = False
    isResilient: bool = False
    providesConfidentiality: bool = False
    providesIntegrity: bool = False
    sanitizesInput: bool = False
    tracksExecutionFlow: bool = False
    usesCodeSigning: bool = False
    usesEncryptionAlgorithm: str = ""
    usesMFA: bool = Field(
        default=False,
        description="Multi-factor authentication is an authentication method in which a computer user is granted access only after successfully presenting two or more pieces of evidence."
    )
    usesParameterizedInput: bool = False
    usesSecureFunctions: bool = False
    usesStrongSessionIdentifiers: bool = False
    usesVPN: bool = False
    validatesContentType: bool = False
    validatesHeaders: bool = False
    validatesInput: bool = False
    verifySessionIdentifiers: bool = False

    def _attr_values(self) -> dict:
        """Return a dictionary of all attribute values."""
        return self.model_dump()

    def _safeset(self, attr: str, value: Any) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass


class Assumption(BaseModel):
    """Assumption used by an Element. Used to exclude threats on a per-element basis."""
    
    model_config = ConfigDict(extra='allow')
    
    name: str = Field(description="Name of the assumption")
    exclude: Set[str] = Field(
        default_factory=set,
        description="A set of threat SIDs to exclude for this assumption. For example: INP01"
    )
    description: str = Field(default="", description="An additional description of the assumption")

    def __init__(self, name: str = None, exclude: Union[List[str], Set[str]] = None, **kwargs):
        """Initialize with optional positional arguments for backward compatibility."""
        if name is not None:
            kwargs['name'] = name
        if exclude is not None:
            # Convert list to set if needed
            kwargs['exclude'] = set(exclude) if isinstance(exclude, list) else exclude
        super().__init__(**kwargs)

    def __str__(self):
        return self.name


# Type aliases for complex field types that reference forward declarations
ElementList = List['Element']
DataList = List['Data']
ThreatList = List['Threat']
FindingList = List['Finding']
ControlsType = Controls
AssumptionList = List[Assumption]