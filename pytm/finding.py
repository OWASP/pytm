"""Finding model - represents a finding linking an element to a threat."""

from typing import Optional, TYPE_CHECKING
from pydantic import BaseModel, Field, ConfigDict

from .base import Assumption

if TYPE_CHECKING:
    from .element import Element
    from .threat import Threat


class Finding(BaseModel):
    """Represents a Finding - the element in question and a description of the finding."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    element: 'Element' = Field(description="Element this finding applies to")
    target: str = Field(description="Name of the element this finding applies to")
    description: str = Field(description="Threat description")
    details: str = Field(description="Threat details")
    severity: str = Field(description="Threat severity")
    mitigations: str = Field(description="Threat mitigations")
    example: str = Field(description="Threat example")
    id: str = Field(description="Finding ID")
    threat_id: str = Field(description="Threat ID")
    references: str = Field(description="Threat references")
    condition: str = Field(description="Threat condition")
    assumption: Optional[Assumption] = Field(
        default=None,
        description="The assumption that caused this finding to be excluded"
    )
    response: str = Field(
        default="",
        description="Describes how this threat matching this particular asset or dataflow is being handled. Can be one of: mitigated, transferred, avoided, accepted"
    )
    cvss: str = Field(default="", description="The CVSS score and/or vector")

    def __init__(self, *args, **kwargs):
        # Handle positional element argument
        if args:
            element = args[0]
            kwargs['element'] = element
        
        # Get element from kwargs
        element = kwargs.get('element')
        if element is None:
            # Create a dummy element if none provided
            from .element import Element
            element = Element(name="invalid")
            kwargs['element'] = element
        
        # Set target from element name
        kwargs['target'] = element.name
        
        # Handle threat data
        threat = kwargs.pop('threat', None)
        if threat:
            kwargs['threat_id'] = getattr(threat, 'id', '')
            # Copy threat attributes
            threat_attrs = [
                'description', 'details', 'severity', 'mitigations',
                'example', 'references', 'condition'
            ]
            for attr in threat_attrs:
                if attr not in kwargs:  # Don't override explicit values
                    kwargs[attr] = getattr(threat, attr, '')
        
        # Handle overrides from element
        threat_id = kwargs.get('threat_id', None)
        if hasattr(element, 'overrides') and threat_id:
            for override in element.overrides:
                if getattr(override, 'threat_id', None) == threat_id:
                    # Apply override values
                    override_dict = override.model_dump() if hasattr(override, 'model_dump') else {}
                    for key, value in override_dict.items():
                        if key not in ('element', 'target') and value is not None:
                            kwargs[key] = value
                    break
        
        # Ensure all required fields have values
        required_fields = ['description', 'details', 'severity', 'mitigations', 
                          'example', 'id', 'threat_id', 'references', 'condition']
        for field in required_fields:
            if field not in kwargs:
                kwargs[field] = ''
        
        super().__init__(**kwargs)

    def _safeset(self, attr: str, value) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass

    def __repr__(self):
        return f"<{self.__module__}.{type(self).__name__}({self.id}) at {hex(id(self))}>"

    def __str__(self):
        return f"'{self.target}': {self.description}\n{self.details}\n{self.severity}"