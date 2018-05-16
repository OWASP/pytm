from pytm import Dataflow

class Threat():
    BagOfThreats = []

    ''' Represents a possible threat '''
    def __init__(self, description, cvss, target, condition):
        self.description = description
        self.cvss = cvss
        self.condition = condition
        self.target = target

    def apply(self, target):
        if typeof(target) != self.target:
            return None
        return eval(self.condition)


def t1_verify(df):
    if df.authenticatedWith is None:
        return True
    else:
        return False


Threat.BagOfThreats.append(Threat("Dataflow not authenticated", 8.6, Dataflow, "target.authenticatedWith is None"))
