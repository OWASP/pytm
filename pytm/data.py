from pytm.element import Element
from pytm.pytm import TM
from pytm.helper import varInt, varString, varData, varElements, varBool


class Data:
    """Represents a single piece of data that traverses the system"""

    name = varString("", required=True)
    description = varString("")
    format = varString("")
    classification = varClassification(
        Classification.UNKNOWN,
        required=True,
        doc="Level of classification for this piece of data",
    )
    isPII = varBool(
        False,
        doc="""Does the data contain personally identifyable information.
Should always be encrypted both in transmission and at rest.""",
    )
    isCredentials = varBool(
        False,
        doc="""Does the data contain authentication information,
like passwords or cryptographic keys, with or without expiration date.
Should always be encrypted in transmission. If stored, they should be hashed
using a cryptographic hash function.""",
    )
    credentialsLife = varLifetime(
        Lifetime.NONE,
        doc="""Credentials lifetime, describing if and how
credentials can be revoked. One of:
* NONE - not applicable
* UNKNOWN - unknown lifetime
* SHORT - relatively short expiration date, with an allowed maximum
* LONG - long or no expiration date
* AUTO - no expiration date but can be revoked/invalidated automatically
  in some conditions
* MANUAL - no expiration date but can be revoked/invalidated manually
* HARDCODED - cannot be invalidated at all""",
    )
    isStored = varBool(
        False,
        doc="""Is the data going to be stored by the target or only processed.
If only derivative data is stored (a hash) it can be set to False.""",
    )
    isDestEncryptedAtRest = varBool(False, doc="Is data encrypted at rest at dest")
    isSourceEncryptedAtRest = varBool(False, doc="Is data encrypted at rest at source")
    carriedBy = varElements([], doc="Dataflows that carries this piece of data")
    processedBy = varElements([], doc="Elements that store/process this piece of data")

    def __init__(self, name, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.name = name
        TM._data.append(self)

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.name, hex(id(self))
        )

    def __str__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def _safeset(self, attr, value):
        try:
            setattr(self, attr, value)
        except ValueError:
            pass
