class Dataflow(Element):
    """A data flow from a source to a sink"""

    source = varElement(None, required=True)
    sink = varElement(None, required=True)
    isResponse = varBool(False, doc="Is a response to another data flow")
    response = varElement(None, doc="Another data flow that is a response to this one")
    responseTo = varElement(None, doc="Is a response to this data flow")
    srcPort = varInt(-1, doc="Source TCP port")
    dstPort = varInt(-1, doc="Destination TCP port")
    isEncrypted = varBool(False, doc="Is the data encrypted")
    tlsVersion = varTLSVersion(
        TLSVersion.NONE,
        required=True,
        doc="TLS version used.",
    )
    protocol = varString("", doc="Protocol used in this data flow")
    data = varData([], doc="pytm.Data object(s) in incoming data flows")
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
    authenticatedWith = varBool(False)
    order = varInt(-1, doc="Number of this data flow in the threat model")
    implementsAuthenticationScheme = varBool(False)
    implementsCommunicationProtocol = varBool(False)
    note = varString("")
    usesVPN = varBool(False)
    authorizesSource = varBool(False)
    usesSessionTokens = varBool(False)

    def __init__(self, source, sink, name, **kwargs):
        self.source = source
        self.sink = sink
        super().__init__(name, **kwargs)
        TM._flows.append(self)

    def display_name(self):
        if self.order == -1:
            return self.name
        return "({}) {}".format(self.order, self.name)

    def _dfd_template(self):
        return """{source} -> {sink} [
    color = {color};
    fontcolor = {color};
    dir = {direction};
    label = "{label}";
]
"""

    def dfd(self, mergeResponses=False, **kwargs):
        self._is_drawn = True

        levels = kwargs.get("levels", None)
        if (
            levels
            and not levels & self.levels
            and not (levels & self.source.levels and levels & self.sink.levels)
        ):
            return ""

        direction = "forward"
        label = self._label()
        if mergeResponses and self.response is not None:
            direction = "both"
            label += "\n" + self.response._label()

        return self._dfd_template().format(
            source=self.source._uniq_name(),
            sink=self.sink._uniq_name(),
            direction=direction,
            label=label,
            color=self._color(),
        )

    def hasDataLeaks(self):
        return any(
            d.classification > self.source.maxClassification
            or d.classification > self.sink.maxClassification
            or d.classification > self.maxClassification
            for d in self.data
        )
