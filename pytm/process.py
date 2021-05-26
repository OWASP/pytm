class Process(Asset):
    """An entity processing data"""

    codeType = varString("Unmanaged")
    implementsCommunicationProtocol = varBool(False)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    isResilient = varBool(False)
    tracksExecutionFlow = varBool(False)
    implementsCSRFToken = varBool(False)
    handlesResourceConsumption = varBool(False)
    handlesCrashes = varBool(False)
    handlesInterruptions = varBool(False)
    implementsAPI = varBool(False)
    usesSecureFunctions = varBool(False)
    environment = varString("")
    disablesiFrames = varBool(False)
    implementsPOLP = varBool(
        False,
        doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""",
    )
    usesParameterizedInput = varBool(False)
    allowsClientSideScripting = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    encryptsCookies = varBool(False)
    usesMFA = varBool(
        False,
        doc="""Multi-factor authentication is an authentication method
in which a computer user is granted access only after successfully presenting two
or more pieces of evidence (or factors) to an authentication mechanism: knowledge
(something the user and only the user knows), possession (something the user
and only the user has), and inherence (something the user and only the user is).""",
    )
    encryptsSessionData = varBool(False)
    verifySessionIdentifiers = varBool(False)

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "circle"
