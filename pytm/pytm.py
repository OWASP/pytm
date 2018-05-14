class TM():
    ''' Describes the threat model and contains the bag of flows 
    and of elements '''

    BagOfFlows = ()
    BagOfElements = ()

    def __init__(self, name, descr):
        self.name = name
        self.descr = descr

    def verify(self):
        pass


class TMElement():
    counter = 0

    def __init__(self, name):
        counter += 1
        self.name = name
        
    def verify(self):
        ''' makes sure it is good to go '''
        # all minimum annotations are in place
        # then add itself to BagOfElements
        

class TMDataflow():
    counter = 0

    def __init__(self, source, sink, name):
        counter += 1
        self.source = source
        self.sink = sink
        self.name = name

    def verify(self):
        ''' makes sure it is good to go '''
        
        # all minimum annotations are in place
        # then add itself to BagOfFlows
            
    @classmethod
    def count(cls):
        print("{} dataflows are defined.".format(cls.counter))



