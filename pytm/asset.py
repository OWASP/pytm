from pytm.element import Element
from pytm.pytm import TM
from pytm.helper import varInt, varString, varData, varElements, varBool


class Asset(Element):
    """An asset with outgoing or incoming dataflows"""

    port = varInt(-1, doc="Default TCP port for incoming data flows")
    isEncrypted = varBool(False, doc="Requires incoming data flow to be encrypted")
    protocol = varString("", doc="Default network protocol for incoming data flows")
    data = varData([], doc="pytm.Data object(s) in incoming data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
    onAWS = varBool(False)
    isHardened = varBool(False)
    implementsAuthenticationScheme = varBool(False)
    implementsNonce = varBool(
        False,
        doc="""Nonce is an arbitrary number
that can be used just once in a cryptographic communication.
It is often a random or pseudo-random number issued in an authentication protocol
to ensure that old communications cannot be reused in replay attacks.
They can also be useful as initialization vectors and in cryptographic
hash functions.""",
    )
    handlesResources = varBool(False)
    definesConnectionTimeout = varBool(False)
    authenticatesDestination = varBool(
        False,
        doc="""Verifies the identity of the destination,
for example by verifying the authenticity of a digital certificate.""",
    )
    checksDestinationRevocation = varBool(
        False,
        doc="""Correctly checks the revocation status
of credentials used to authenticate the destination""",
    )
    authenticatesSource = varBool(False)
    authorizesSource = varBool(False)
    hasAccessControl = varBool(False)
    validatesInput = varBool(False)
    sanitizesInput = varBool(False)
    checksInputBounds = varBool(False)
    encodesOutput = varBool(False)
    handlesResourceConsumption = varBool(False)
    authenticationScheme = varString("")
    usesEnvironmentVariables = varBool(False)
    OS = varString("")
    providesIntegrity = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        TM._assets.append(self)
