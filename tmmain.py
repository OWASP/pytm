import json
from os.path import dirname
from pytm import TM, Actor, Boundary, Dataflow, Datastore, Lambda, Server, ExternalEntity, Process, SetOfProcesses
from pytm import get_args, check_ref

def ElementType(i):

    if i['Element'] == 'TM':
        global tm 
        tm = TM(**i)

    if i['Element']=='Server':  
        name = i['name'] 
        i.pop('name')  
        Server(name, **i)

    elif i['Element']=='Boundary':
        name = i['name']
        i.pop('name')
        Boundary(name, **i)

    elif i['Element']=='Lambda':
        name = i['name']
        i.pop('name')
        Lambda(name, **i)

    elif i['Element']=='ExternalEntity':
        name = i['name']
        ExternalEntity(name, **i)

    elif i['Element']=='Datastore':
        name = i['name']
        i.pop('name')
        Datastore(name, **i)
                    
    elif i['Element']=='Actor':
        name = i['name']
        i.pop('name')
        Actor(name, **i)

    elif i['Element']=='Process':
        name = i['name']
        i.pop('name')
        Process(name, **i)

    elif i['Element']=='setofprocesses':
        name = i['name']
        i.pop('name')
        SetOfProcesses(name, **i)

    elif i['Element']=='Dataflow':
        i = check_ref(i)
        name = i['name']
        source = i['source']
        sink = i['sink']
        i.pop('name')
        i.pop('source')
        i.pop('sink')
        Dataflow(source, sink, name, **i)


def jsonway():
    with open(dirname(__file__) + "inputfiles/tm.json", "r", encoding="utf8") as elements_file:
        elements_json = json.load(elements_file)

    for i in elements_json:
        ElementType(i)

def pythonway():
    from inputfiles import tm


if __name__ == "__main__":
    result = get_args()
    if result.input == 'JSON':
        jsonway()
        tm.process()

    if result.input == 'Python':
        pythonway()

        
