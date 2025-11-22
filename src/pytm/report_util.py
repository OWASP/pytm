
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
    def getFindingCount(element):
        from pytm import Element
        if (isinstance(element, Element)):
            return str(len(list(element.findings)))
        else:
            return "ERROR: getFindingCount method is not valid for " + element.__class__.__name__

    @staticmethod
    def getElementType(element):
        from pytm import Element
        if (isinstance(element, Element)):
            return str(element.__class__.__name__)
        else:
            return "ERROR: getElementType method is not valid for " + element.__class__.__name__
