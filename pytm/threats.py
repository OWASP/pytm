from pytm.pytm import Dataflow, Element, Server, Actor, Datastore, Process, SetOfProcesses, Lambda
from os import path

''' Add threats here '''
Threats = {}
dictpath = path.dirname(__file__)+"/dictionaries/"
Threats.update(eval(open(dictpath+'default.dict', 'r').read()))
Threats.update(eval(open(dictpath+'gdpr.dict', 'r').read()))