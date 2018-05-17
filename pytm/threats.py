from pytm import Dataflow, Server

''' Add threats here '''
Threats = {
    { "DF1": {
        "description": "Dataflow not authenticated",
        "cvss": 8.6,
        "target": Dataflow,
        "condition": "target.authenticatedWith is None"
    }},
    { "SR1": {
        "description": "Server not hardened",
        "cvss": 9.0,
        "target": Server,
        "condition": "target.isHardened is None"
    }}
}