
class Threat():
    BagOfThreats = []

    ''' Represents a possible threat '''
    def __init__(self, description, cvss, condition):
        self.description = description
        self.cvss = cvss
        self.condition = condition

    def apply(self, target):
        return self.condition(target)


def t1_verify(df):
    if df.authenticatedWith is None:
        return True
    else:
        return False


Threat.BagOfThreats.append(Threat("Dataflow not authenticated", 8.6, def verify(): pass))
