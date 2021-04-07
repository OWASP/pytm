
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
    def printParents(element):
        from pytm import Boundary
        if (isinstance(element, Boundary)):
            parents = map(lambda b: b.name, element.parents())
            return list(parents) 
        else:
            return "ERROR: printParents method is not valid for " + element.__class__.__name__

    @staticmethod
    def countFindings(element):
        from pytm import Element
        if (isinstance(element, Element)):
            return str(len(list(element.findings)))
        else:
            return "ERROR: countFindings method is not valid for " + element.___class___.___name___

            