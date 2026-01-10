
class ReportUtils:
    @staticmethod
    def getParentName(element):
        from pytm import Boundary
        if (isinstance(element, Boundary)):
            parent = element.inBoundary
            if (parent is not None):
                return parent.name
            else:
                return str("")
        else:
            return "ERROR: getParentName method is not valid for " + element.__class__.__name__


    @staticmethod
    def getNamesOfParents(element):
        from pytm import Boundary
        if (isinstance(element, Boundary)):
            parents = [p.name for p in element.parents()] 
            return parents 
        else:
            return "ERROR: getNamesOfParents method is not valid for " + element.__class__.__name__
    

    @staticmethod
    def getInScopeFindings(element):
        """
        Return only findings that:
        1. Belong to an in-scope element
        2. Target an in-scope element
        """
        from pytm import Element

        if not isinstance(element, Element):
            return []

        if not element.inScope:
            return []

        in_scope_findings = []

        for finding in element.findings:
            target = getattr(finding, "target", None)
            if target is not None and getattr(target, "inScope", False):
                in_scope_findings.append(finding)

        return in_scope_findings


    @staticmethod
    def getFindingCount(element):
        from pytm import Element
        if not isinstance(element, Element):
            return "ERROR: getFindingCount method is not valid for " + element.__class__.__name__
        return str(len(ReportUtils.getInScopeFindings(element)))


    @staticmethod
    def getElementType(element):
        from pytm import Element
        if (isinstance(element, Element)):
            return str(element.__class__.__name__)
        else:
            return "ERROR: getElementType method is not valid for " + element.__class__.__name__


    @staticmethod
    def getThreatId(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.threat_id
        return ""

    @staticmethod
    def getFindingDescription(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.description
        return ""

    @staticmethod
    def getFindingTarget(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.target
        return ""

    @staticmethod
    def getFindingSeverity(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.severity
        return ""

    @staticmethod
    def getFindingMitigations(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.mitigations
        return ""

    @staticmethod
    def getFindingReferences(obj):
        from pytm import Finding
        if isinstance(obj, Finding):
            return obj.references
        return ""
        
