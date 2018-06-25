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
        "target": Server,
        "condition": "target.isHardened is False",
    },
    "DS1": {
        "description": "Logs created: verify if sensitive data is stored",
        "target": Datastore,
        "condition": "target.storesLogData is True",
    },
    "DS2": {
        "description": "Potential weak protections for audit data",
        "target": Datastore,
        "condition": "target.storesLogData is True and target._isEncrypted is False",
    },
    "PR1": {
        "description": "Process Memory Tampered",
        "source": "Generic Process",
        "target": Process,
        "condition": "target.codeType == 'unmanaged'",
    },
    "DF2": {
        "description": "Replay Attacks",
        "source": "Generic Process",
        "target": Dataflow,
        "condition": "target.implementsCommunicationProtocol is True and target.implementsNonce is False",
    },
    "DF3": {
        "description": "Collision Attacks",
        "source": "Generic Process",
        "target": Process,
        "condition": "target.implementsCommunicationProtocol is True",
    },
    "DS3": {
        "description": "Risks from logging",
        "source": "Generic Process",
        "target": Datastore,
        "condition": "target.storesLogData is True",
    },
    "AUTH1": {
        "description": "Authenticated Data Flow Compromised",
        "source": "Generic Process OR Data Store OR External Interactor",
        "target": (Process, Datastore),
        "condition": "target.providesConfidentiality is False and target.providesIntegrity is False and target.authenticatesSource is True or target.authenticatesDestination is True",
    },
    "SQL1": {
      "description": "Potential SQL Injection Vulnerability",
      "source": "Generic Process",
      "target": Datastore,
      "condition": "target._isSQL is True",
    },
}

'''
    {
      "description": "Potential SQL Injection Vulnerability for {target}",
      "source": "External Interactor",
      "target": "Data store",
      "condition": "2.SQL Database is True",
      },
    {
      "description": "XML DTD and XSLT Processing",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "General Process",
      "condition": "3.TransmitsXML is True",
      },
    {
      "description": "JavaScript Object Notation Processing",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "Generic Process",
      "condition": "(3.HTTP is True or 3.HTTPS is True) and 3.Contains JSON Payload is True",
      },
    {
      "description": "Cross Site Scripting",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "Generic Process",
      "condition": "(1.Web Server is True OR 1.Web App is True) AND (1.Sanitizes Output is False) AND (1.Sanitizes Input is False)",
      },
    {
      "description": "Persistent Cross Site Scripting",
      "source": "Data Store",
      "target": "Generic Process",
      "condition": "(1.Web Server is True OR 1.Web App is True) AND (1.Sanitizes Input is False) AND (1.Sanitizes Input is False)",
      },
    {
      "description": "The {target} Data Store Could Be Corrupted",
      "source": "Generic Process OR External Interactor",
      "target": "Data store",
      "condition": "",
      },
    {
      "description": "Weakness in SSO Authorization",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "External Interactor",
      "condition": "(4.External Authorization Provider is False AND 4.Microsoft is False) AND (4.External Authorization Provider is True)",
      },
    {
      "description": "Elevation Using Impersonation",
      "source": "Generic Process OR External Interactor",
      "target": "Generic Process",
      "condition": "",
      },
    {
      "description": "{Target} May be Subject to Elevation of Privilege Using Remote Code Execution",
      "source": "Generic Process OR External Interactor OR Data Store",
      "target": "Generic Process",
      "condition": "",
      },
    {
      "description": "Elevation by Changing the Execution Flow in {target.Name}",
      "source": "Generic Process OR External Interactor OR Data Store",
      "target": "Generic Process",
      "condition": "",
      },
    {
      "description": "Cross Site Request Forgery",
      "source": "Generic Process OR External Interactor",
      "target": "Generic Process",
      "condition": "((1.Thread Process is False OR 1.Kernel Thread is False OR 1..Net Web App is False OR 1.Web Server is False OR 1.Virtual Machine is False OR 4.External Authorization Provider is False OR 4.WebApp is False OR 1.Browser Client is False) OR (5.Machine Trust Boundary is False OR 5.Kernel mode Boundary is False OR 5.Corporate Network is False OR 5.Sandbox Trust Boundary is False)) AND (4.Authenticates Source is True)",
      },
    {
      "description": "Potential Excessive Resource Consumption for {source} or {target}",
      "source": "Generic Process",
      "target": "Data Store",
      "condition": "",
      },
    {
      "description": "Potential Process Crash or Stop for {target}",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "Generic Process",
        "remediation": ""
    },
    { "description": "Data Flow {flow} Is Potentially Interrupted",
      "source": "Generic Process OR Data Store OR External Interactor",
      "target": "Generic Process OR Data Store OR External Interactor",
        "remediation": ""
    },
    { "description": "Data Store Inaccessible",
      "source": "Data Store",
      "target": "Data Store",
        "remediation": ""
    },
    { "description": "Authorization Bypass",
      "source": "Generic Process",
      "target": "Data Store",
        "remediation": ""
    },
    { "description": "Data Flow Sniffing",
      "source": "Generic Process OR External Interactor",
      "target": "Generic Process",
        "remediation": ""
    },
    { "description": "Data Flow Sniffing",
      "source": "Generic Process",
      "target": "Data Store",
        "remediation": ""
    },
    { "description": "Weak Access Control for a Resource",
      "source": "Data Store",
      "target": "Generic Process OR External Interactor",
        "remediation": ""
    },
    { "description": "Weak Credential Storage",
      "source": "Generic Process",
      "target": "Data Store",
        "remediation": ""
    },
    { "description": "Weak Credential Transit",
      "source": "Generic Process",
      "target": "Generic Process OR Data Store",
        "remediation": ""
    },
    { "description": "Weak Authentication Scheme",
      "source": "Generic Process",
      "target": "Generic Process",
      "condition": "1.Implements Authentication Scheme is True",
      "remediation": ""
    }
}
'''