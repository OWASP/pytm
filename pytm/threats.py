from pytm.pytm import Dataflow, Element, Server, Actor, Datastore, Process, SetOfProcesses

''' Add threats here '''
Threats = {

  "AA01": {
    "description": "Dataflow not authenticated",
    "target": Dataflow,
    "condition": "target.authenticatedWith is False",
    "comments": "instead of looking at both sides of a flow, consider the flow authenticated only if both sides authenticate",
  },
  "HA01": {
    "description": "Server not hardened",
    "target": Server,
    "condition": "target.isHardened is False",
  },
  "AU01": {
    "description": "Logs created: verify if sensitive data is stored",
    "target": Datastore,
    "condition": "target.storesLogData is True",
  },
  "AU02": {
    "description": "Potential weak protections for audit data",
    "target": Datastore,
    "condition": "target.storesLogData is True and target.isEncrypted is False",
  },
  "AC01": {
    "description": "Process Memory Tampered",
    "source": Process,
    "target": Process,
    "condition": "target.codeType == 'unmanaged'",
  },
  "AC02": {
    "description": "Replay Attacks",
    "source": Process,
    "target": Dataflow,
    "condition": "target.implementsCommunicationProtocol is True and target.implementsNonce is False",
  },
  "CR01": {
    "description": "Collision Attacks",
    "source": Process,
    "target": Process,
    "condition": "target.implementsCommunicationProtocol is True",
  },
  "AU03": {
    "description": "Risks from logging",
    "source": Process,
    "target": Datastore,
    "condition": "target.storesLogData is True",
  },
  "AA02": {
    "description": "Authenticated Data Flow Compromised",
    "source": (Process, Datastore, Element, Actor),
    "target": (Process, Datastore, Server),
    "condition": "target.providesConfidentiality is False and target.providesIntegrity is False and target.authenticatesSource is True or target.authenticatesDestination is True",
  },
  "IN01": {
    "description": "Potential SQL Injection Vulnerability",
    "source": Process,
    "target": Datastore,
    "condition": "target.isSQL is True",
  },
  "IN02": {
    "description": "XML DTD and XSLT Processing",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.dataType == 'XML'",
  },
  "IN03": {
    "description": "JavaScript Object Notation Processing/XSS",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.dataType == 'JSON'",
  },
  "IN04": {
    "description": "Cross Site Scripting",
    "source": (Process, Datastore, Element),
    "target": Server,
    "condition": "target.sanitizesInput is False and target.encodesOutput is False",
  },
  "AC03": {
    "description": "The Data Store Could Be Corrupted",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "target.isShared is True or target.hasWriteAccess is True",
  },
  "AA03": {
    "description": "Weakness in SSO Authorization",
    "source": (Process, Element),
    "target": (Process, Server),
    "condition": "target.implementsAuthenticationScheme is False",
  },
  "AC04": {
    "description": "Elevation Using Impersonation",
    "source": (Process, Element),
    "target": (Process, Server),
    "condition": "target.hasAccessControl is False",
  },
  "AC05": {
    "description": "Elevation by Changing the Execution Flow in a process",
    "source": (Process, Element, Datastore),
    "target": Process,
    "condition": "target.tracksExecutionFlow is False or target.hasAccessControl is False",
  },
  "OT01": {
    "description": "Cross Site Request Forgery",
    "source": Element,
    "target": (Process, Server),
    "condition": "target.implementsCSRFToken is False",
  },
  "DO01": {
    "description": "Potential Excessive Resource Consumption",
    "source": Element,
    "target": (Process, Server),
    "condition": "target.handlesResourceConsumption is False",
  },
  "DO02": {
    "description": "Potential Process Crash or Stop",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.handlesCrashes is False",
  },
  "DO03": {
    "description": "Data Flow Is Potentially Interrupted",
    "source": (Process, Datastore, Element),
    "target": (Process, Datastore),
    "condition": "target.handlesInterruptions is False",
  },
  "DO04": {
    "description": "Data Store Inaccessible",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "target.isResilient is False",
  },
  "AA04": {
    "description": "Authorization Bypass",
    "source": Element,
    "target": (Process, Datastore),
    "condition": "target.authorizesSource is False",
  },
  "DE01": {
    "description": "Data Flow Sniffing",
    "source": (Process, Element, Datastore),
    "target": Dataflow,
    "condition": "target.protocol == 'HTTP' and target.isEncrypted is False",
  },
  "AC06": {
    "description": "Weak Access Control for a Resource",
    "source": (Process, Datastore, Element),
    "target": (Process, Datastore),
    "condition": "target.hasAccessControl is False",
  },
  "DS01": {
    "description": "Weak Credential Storage",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "(target.storesPII is True or target.storesSensitiveData is True) and (target.isEncrypted is False or target.providesConfidentiality is False or target.providesIntegrity is False)",
  },
  "DE02": {
    "description": "Weak Credential Transit",
    "source": (Process, Datastore, Element),
    "target": Dataflow,
    "condition": "target.authenticatedWith is False and target.protocol == 'HTTP'",
},
  "AA05": {
    "description": "Weak Authentication Scheme",
    "source": (Process, Element),
    "target": (Process, Datastore, Server),
    "condition": "target.authenticationScheme in ('Basic', 'BASIC')",
},
}
