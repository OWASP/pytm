from pytm.pytm import Dataflow, Element, Server, Datastore, Process, SetOfProcesses, Actor

''' Add threats here '''
Threats = {
    "DF1": {
        "description": "Dataflow not authenticated",
        "target": Dataflow,
        "condition": "target.authenticatedWith is False",
        "comments": "instead of looking at both sides of a flow, consider the flow authenticated only if both sides authenticate",
    },
    "SR1": {
        "description": "Server not hardened",
        "target": (Server,),
        "condition": "target.isHardened is False",
    },
    "DS1": {
        "description": "Logs created: verify if sensitive data is stored",
        "target": (Datastore,),
        "condition": "target.storesLogData is True",
    },
    "DS2": {
        "description": "Potential weak protections for audit data",
        "target": (Datastore,),
        "condition": "target.storesLogData is True and target._isEncrypted is False",
    },
    "PR1": {
        "description": "{source} Process Memory Tampered",
        "source": "Generic Process",
        "target": (Process,),
        "condition": "target.codeType == 'unmanaged'",
    },
    "DF2": {
        "description": "Replay Attacks",
        "source": "Generic Process",
        "target": (Dataflow,),
        "condition": "target.implementsCommunicationProtocol is True and target.implementsNonce is False",
    },
    "DF3": {
        "description": "Collision Attacks",
        "source": "Generic Process",
        "target": (Process,),
        "condition": "target.implementsCommunicationProtocol is True",
    },
    "DS3": {
        "description": "Risks from logging",
        "source": "Generic Process",
        "target": (Datastore,),
        "condition": "target.storesLogData is True",
    },
    "AUTH1": {
        "description": "Authenticated Data Flow Compromised",
        "source": "Generic Process OR Data Store OR External Interactor",
        "target": (Process, Datastore),
        "condition": "target.providesConfidentiality is False and target.providesIntegrity is False and target.authenticatesSource is True or target.authenticatesDestination is True",
    },
    "SQL1": {
      "description": "Potential SQL Injection Vulnerability for {target}",
      "source": "Generic Process",
      "target": (Datastore,),
      "condition": "target._isSQL is True",
    },
}
