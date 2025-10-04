"""Threat model - represents possible threats in the system."""

import sys
from typing import Tuple, Union, List
from collections.abc import Iterable
from pydantic import BaseModel, Field, ConfigDict, field_validator

from .enums import Classification, TLSVersion


class Threat(BaseModel):
    """Represents a possible threat."""
    
    model_config = ConfigDict(
        extra='allow',
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    id: str = Field(description="Threat identifier (SID)")
    description: str = Field(default="", description="Description of the threat")
    condition: str = Field(
        default="True",
        description="A Python expression that should evaluate to a boolean True or False"
    )
    details: str = Field(default="", description="Detailed information about the threat")
    likelihood: str = Field(default="", description="Likelihood of the threat occurring")
    severity: str = Field(default="", description="Severity level of the threat")
    mitigations: str = Field(default="", description="Possible mitigations for the threat")
    prerequisites: str = Field(default="", description="Prerequisites for the threat")
    example: str = Field(default="", description="Example of the threat")
    references: str = Field(default="", description="References for the threat")
    target: Tuple = Field(default=(), description="Target classes for this threat")

    def __init__(self, **kwargs):
        # Handle the original threat format
        threat_data = {}
        threat_data['id'] = kwargs.get('SID', kwargs.get('id', ''))
        threat_data['description'] = kwargs.get('description', '')
        threat_data['likelihood'] = kwargs.get('Likelihood Of Attack', '')
        threat_data['condition'] = kwargs.get('condition', 'True')
        
        # Handle target
        target = kwargs.get('target', 'Element')
        if not isinstance(target, str) and isinstance(target, Iterable):
            target = tuple(target)
        else:
            target = (target,)
        
        # Convert target names to actual classes
        target_classes = []
        for target_name in target:
            try:
                # Try to get the class from the current module
                target_class = getattr(sys.modules.get('pytm.element'), target_name, None)
                if target_class is None:
                    # Fallback to string representation
                    target_classes.append(target_name)
                else:
                    target_classes.append(target_class)
            except (AttributeError, KeyError):
                target_classes.append(target_name)
        
        threat_data['target'] = tuple(target_classes)
        threat_data['details'] = kwargs.get('details', '')
        threat_data['severity'] = kwargs.get('severity', '')
        threat_data['mitigations'] = kwargs.get('mitigations', '')
        threat_data['prerequisites'] = kwargs.get('prerequisites', '')
        threat_data['example'] = kwargs.get('example', '')
        threat_data['references'] = kwargs.get('references', '')
        
        # Add any additional fields
        for key, value in kwargs.items():
            if key not in threat_data:
                threat_data[key] = value
        
        super().__init__(**threat_data)

    def _safeset(self, attr: str, value) -> None:
        """Safely set an attribute value."""
        try:
            setattr(self, attr, value)
        except (ValueError, TypeError):
            pass

    def __repr__(self):
        return f"<{self.__module__}.{type(self).__name__}({self.id}) at {hex(id(self))}>"

    def __str__(self):
        return f"{type(self).__name__}({self.id})"

    def apply(self, target):
        """Apply the threat condition to a target."""
        # Check if target matches any of the target types
        if self.target:
            target_matches = False
            for target_type in self.target:
                if isinstance(target_type, str):
                    # String comparison for backward compatibility
                    if target_type == type(target).__name__:
                        target_matches = True
                        break
                elif isinstance(target_type, type):
                    # Class type comparison
                    if isinstance(target, target_type):
                        target_matches = True
                        break
            
            if not target_matches:
                return None
        
        try:
            # Create namespace for eval with all necessary classes
            import pytm
            namespace = {
                'target': target,
                'Actor': pytm.Actor,
                'Asset': pytm.Asset,
                'Boundary': pytm.Boundary,
                'Dataflow': pytm.Dataflow,
                'Datastore': pytm.Datastore,
                'DatastoreType': pytm.DatastoreType,
                'Element': pytm.Element,
                'ExternalEntity': pytm.ExternalEntity,
                'Lambda': pytm.Lambda,
                'Process': pytm.Process,
                'Server': pytm.Server,
                'TM': pytm.TM,
                'TLSVersion': pytm.TLSVersion,
                'Classification': pytm.Classification,
                'Action': pytm.Action,
                'Lifetime': pytm.Lifetime,
                'any': any,
                'all': all,
                'len': len,
                'isinstance': isinstance,
                'hasattr': hasattr,
                'getattr': getattr,
            }
            return eval(self.condition, namespace)
        except Exception:
            return False