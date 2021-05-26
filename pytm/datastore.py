class Datastore(Asset):
    """An entity storing data"""

    onRDS = varBool(False)
    storesLogData = varBool(False)
    storesPII = varBool(
        False,
        doc="""Personally Identifiable Information
is any information relating to an identifiable person.""",
    )
    storesSensitiveData = varBool(False)
    isSQL = varBool(True)
    providesConfidentiality = varBool(False)
    providesIntegrity = varBool(False)
    isShared = varBool(False)
    hasWriteAccess = varBool(False)
    handlesResourceConsumption = varBool(False)
    isResilient = varBool(False)
    handlesInterruptions = varBool(False)
    usesEncryptionAlgorithm = varString("")
    implementsPOLP = varBool(
        False,
        doc="""The principle of least privilege (PoLP),
also known as the principle of minimal privilege or the principle of least authority,
requires that in a particular abstraction layer of a computing environment,
every module (such as a process, a user, or a program, depending on the subject)
must be able to access only the information and resources
that are necessary for its legitimate purpose.""",
    )
    isEncryptedAtRest = varBool(False, doc="Stored data is encrypted at rest")

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

    def _dfd_template(self):
        return """{uniq_name} [
    shape = {shape};
    fixedsize = shape;
    image = "{image}";
    imagescale = true;
    color = {color};
    fontcolor = {color};
    xlabel = "{label}";
    label = "";
]
"""

    def _shape(self):
        return "none"

    def dfd(self, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if levels and not levels & self.levels:
            return ""

        return self._dfd_template().format(
            uniq_name=self._uniq_name(),
            label=self._label(),
            color=self._color(),
            shape=self._shape(),
            image=os.path.join(os.path.dirname(__file__), "images", "datastore.png"),
        )
