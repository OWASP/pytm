from pytm.element import Element
from pytm.tm import TM
from pytm.helper import varInt, varString, varData, varElements, varBool


class Actor(Element):
    """An entity usually initiating actions"""

    port = varInt(-1, doc="Default TCP port for outgoing data flows")
    protocol = varString("", doc="Default network protocol for outgoing data flows")
    data = varData([], doc="pytm.Data object(s) in outgoing data flows")
    inputs = varElements([], doc="incoming Dataflows")
    outputs = varElements([], doc="outgoing Dataflows")
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
    isAdmin = varBool(False)
    # should not be settable, but accessible
    providesIntegrity = False

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        TM._actors.append(self)
