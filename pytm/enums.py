"""Enums used throughout the pytm package."""

from enum import Enum


class Action(Enum):
    """Action taken when validating a threat model."""

    NO_ACTION = "NO_ACTION"
    RESTRICT = "RESTRICT"
    IGNORE = "IGNORE"


class OrderedEnum(Enum):
    """Base enum class that supports ordering operations."""
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class Classification(OrderedEnum):
    """Data classification levels."""
    
    UNKNOWN = 0
    PUBLIC = 1
    RESTRICTED = 2
    SENSITIVE = 3
    SECRET = 4
    TOP_SECRET = 5


class Lifetime(Enum):
    """Credential lifetime categories."""
    
    # not applicable
    NONE = "NONE"
    # unknown lifetime
    UNKNOWN = "UNKNOWN"
    # relatively short expiration date (time to live)
    SHORT = "SHORT_LIVED"
    # long or no expiration date
    LONG = "LONG_LIVED"
    # no expiration date but revoked/invalidated automatically in some conditions
    AUTO = "AUTO_REVOKABLE"
    # no expiration date but can be invalidated manually
    MANUAL = "MANUALLY_REVOKABLE"
    # cannot be invalidated at all
    HARDCODED = "HARDCODED"

    def label(self):
        return self.value.lower().replace("_", " ")


class DatastoreType(Enum):
    """Types of datastores."""
    
    UNKNOWN = "UNKNOWN"
    FILE_SYSTEM = "FILE_SYSTEM"
    SQL = "SQL"
    LDAP = "LDAP"
    AWS_S3 = "AWS_S3"

    def label(self):
        return self.value.lower().replace("_", " ")


class TLSVersion(OrderedEnum):
    """TLS/SSL version levels."""
    
    NONE = 0
    SSLv1 = 1
    SSLv2 = 2
    SSLv3 = 3
    TLSv10 = 4
    TLSv11 = 5
    TLSv12 = 6
    TLSv13 = 7