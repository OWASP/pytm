class Server(Asset):
    """An entity processing data"""

    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    validatesHeaders = varBool(False)
    encodesHeaders = varBool(False)
    implementsCSRFToken = varBool(False)
    isResilient = varBool(False)
    usesSessionTokens = varBool(False)
    usesEncryptionAlgorithm = varString("")
    usesCache = varBool(False)
    usesVPN = varBool(False)
    usesCodeSigning = varBool(False)
    validatesContentType = varBool(False)
    invokesScriptFilters = varBool(False)
    usesStrongSessionIdentifiers = varBool(False)
    implementsServerSideValidation = varBool(False)
    usesXMLParser = varBool(False)
    disablesDTD = varBool(False)
    implementsStrictHTTPValidation = varBool(False)
    implementsPOLP = varBool(
        False,
        doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""",
    )

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _shape(self):
        return "circle"
