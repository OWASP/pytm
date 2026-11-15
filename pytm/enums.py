"""Enums used throughout the pytm package."""

from enum import Enum


class FlexibleEnumMixin:
    """Also accept member names and their str() form ("ClassName.MEMBER").

    Serialized threat models store enums as str(member), so this lets
    Classification("Classification.SECRET") and Classification("SECRET")
    resolve alongside the regular by-value lookup.
    """

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, str):
            return None
        name = value.removeprefix(f"{cls.__name__}.")
        try:
            return cls[name]
        except KeyError:
            return None


class Action(FlexibleEnumMixin, Enum):
    """Action taken when validating a threat model."""

    NO_ACTION = "NO_ACTION"
    RESTRICT = "RESTRICT"
    IGNORE = "IGNORE"


class OrderedEnum(FlexibleEnumMixin, Enum):
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


class Lifetime(FlexibleEnumMixin, Enum):
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


class DatastoreType(FlexibleEnumMixin, Enum):
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


class ActorKind(FlexibleEnumMixin, Enum):
    """What kind of party an Actor represents (maps to a TM-BOM party)."""

    UNKNOWN = "unknown"
    PERSON = "person"
    ORGANIZATION = "organization"
    SYSTEM = "system"
    PERSONA = "persona"


class ControlCategory(FlexibleEnumMixin, Enum):
    """How a Control acts on a threat."""

    UNKNOWN = "unknown"
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"
    DETERRENT = "deterrent"
    RECOVERY = "recovery"


class ControlStatus(FlexibleEnumMixin, Enum):
    """Implementation status of a Control."""

    UNKNOWN = "unknown"
    RECOMMENDED = "recommended"
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    PLANNED = "planned"
    IN_PROGRESS = "in-progress"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    DECOMMISSIONED = "decommissioned"
