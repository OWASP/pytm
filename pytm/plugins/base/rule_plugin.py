from pytm.plugins.base.base_plugin import BasePlugin


class PluginThreat():
    """ A threat description """
    # TODO: Untangle the main code and use the Threat class from there here.

    def __init__(self, element, comment, **kwargs):

        self.data = {"SID": kwargs.get("SID"),
                     "description": kwargs.get("description", ""),
                     "condition": kwargs.get("condition", ""),
                     "target": kwargs.get("target", []),
                     "details": kwargs.get("details", ""),
                     "severity": kwargs.get("severity", ""),
                     "mitigations": kwargs.get("mitigations", ""),
                     "example": kwargs.get("example", ""),
                     "references": " ".join(kwargs.get("reference_list", []))
                    }
        self.element = element
        self.comment = comment

    def to_threatfile_format(self):
        """ Returns data in threatfile format """
        return self.data


class RuleResult():
    """ Can collect a large variety of detection results. Can be extended beyond threats. This is the reason there is a whole class here to collect that """

    def __init__(self) -> None:
        self._threats = []

    def add_threat(self, element, comment, **kwargs):
        self._threats.append(PluginThreat(element, comment, **kwargs))

    def get_threats(self):
        return self._threats



class RulePlugin(BasePlugin):
    """ A rule matching plugin base

    """

    sid = None

    def __init__(self):
        self.result = RuleResult()
        self.elements = []

    ### Entry points

    def threat_check(self, elements):
        """ Calls the plugin function to check threats after abstracting internals away """

        self.elements = elements

        self.threat_match()

    ### Generic functions

    def get_type(self, element):
        """ returns a type string for an element """

        # TODO: Move that to the classes
        if str((type(element))) == "<class 'pytm.pytm.Boundary'>":
            return "Boundary"
        if str((type(element))) == "<class 'pytm.pytm.Datastore'>":
            return "Datastore"

    def get_elements(self):
        return self.elements

    ### Threat things

    def add_threat(self, element, comment):
        """ Add a threat to the results

        @param element: the threat is tied to
        @param comment: used comment for this threat

        """
        data = {"SID": self.SID,
                "description": self.description,
                "condition": self.condition,
                "target": self.target,
                "details": self.details,
                "severity": self.severity,
                "mitigations": self.mitigations,
                "example": self.example,
                "reference_list": self.reference_list}

        self.result.add_threat(element, comment, **data)

    def get_threats(self):
        """ Read threats from the collection """
        return self.result.get_threats()

    def get_id(self):
        return self.SID

    def get_description(self):
        return self.description



