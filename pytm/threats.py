from pytm.pytm import Dataflow, Element, Server, Actor, Datastore, Process, SetOfProcesses, Lambda

''' Add threats here '''
Threats = {

  "AA01": {
    "description": "Dataflow not or insufficiently authenticated [vulnerability](https://cwe.mitre.org/data/definitions/287.html)",
    "target": Dataflow,
    "condition": "target.authenticatedWith is False",
    "comments": "instead of looking at both sides of a flow, consider the flow authenticated only if both sides authenticate",
  },
  "HA01": {
    "description": "Server not hardened",
    "target": (Datastore, Server),
    "condition": "target.isHardened is False",
  },
  "AU01": {
    "description": "Logs created: verify if sensitive data is stored. [vulnerability](https://cwe.mitre.org/data/definitions/532.html)",
    "target": Datastore,
    "condition": "target.storesLogData is True",
  },
  "AU02": {
    "description": "Potential weak protections for audit data [vulnerability](https://cwe.mitre.org/data/definitions/311.html) ",
    "target": Datastore,
    "condition": "target.storesLogData is True and target.isEncrypted is False",
  },
  "AC01": {
    "description": "Process Memory Tampered. [Vulnerability](https://cwe.mitre.org/data/definitions/119.html)",
    "source": Process,
    "target": Process,
    "condition": "target.codeType == 'unmanaged'",
  },
  "AC02": {
    "description": "Replay [Attacks](https://capec.mitre.org/data/definitions/60.html)",
    "source": Process,
    "target": Dataflow,
    "condition": "target.implementsCommunicationProtocol is True and target.implementsNonce is False",
  },
  "CR01": {
    "description": "Collision [Attacks](https://capec.mitre.org/data/definitions/194.html)",
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
    "description": "Authenticated Data Flow Compromised. [Vulnerability1](https://cwe.mitre.org/data/definitions/319.html), [Vulnerability2](https://cwe.mitre.org/data/definitions/924.html)",
    "source": (Process, Datastore, Element, Actor),
    "target": (Process, Datastore, Server),
    "condition": "target.providesConfidentiality is False and target.providesIntegrity is False and target.authenticatesSource is True",
  },
  "IN01": {
    "description": "Potential SQL injection [Vulnerability](https://cwe.mitre.org/data/definitions/89.html)",
    "source": Process,
    "target": Datastore,
    "condition": "target.isSQL is True",
  },
  "IN02": {
    "description": "XML DTD and XSLT Processing. [Vulnerability1](https://cwe.mitre.org/data/definitions/611.html), [Vulnerability2](https://cwe.mitre.org/data/definitions/91.html), [Attack](https://capec.mitre.org/data/definitions/250.html), [Attack2](https://capec.mitre.org/data/definitions/230.html), [Attack3](https://capec.mitre.org/data/definitions/231.html)",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.dataType == 'XML'",
  },
  "IN03": {
    "description": "JavaScript Object Notation Processing/XSS, [Vulnerability](https://cwe.mitre.org/data/definitions/20.html), [attack](https://capec.mitre.org/data/definitions/63.html)",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.dataType == 'JSON'",
  },
  "IN04": {
    "description": "Cross Site Scripting [Vulnerability](https://cwe.mitre.org/data/definitions/79.html)",
    "source": (Process, Datastore, Element),
    "target": Server,
    "condition": "target.sanitizesInput is False and target.encodesOutput is False",
  },
  "AC03": {
    "description": "The Data Store Could Be Corrupted [Vulnerability](https://cwe.mitre.org/data/definitions/707.html),",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "target.isShared is True or target.hasWriteAccess is True",
  },
  "AA03": {
    "description": "Weakness in SSO Authorization [Attack](https://capec.mitre.org/data/definitions/473.html), [Vulnerability](https://cwe.mitre.org/data/definitions/287.html), [Vulnerability2](https://capec.mitre.org/data/definitions/345.html), [Vulnerability3](https://capec.mitre.org/data/definitions/347.html)",
    "source": (Process, Element),
    "target": (Process, Server),
    "condition": "target.implementsAuthenticationScheme is False",
  },
  "AC04": {
    "description": "Elevation Using Impersonation [Attack](https://capec.mitre.org/data/definitions/633.html), [Vulnerability](https://cwe.mitre.org/data/definitions/287.html)",
    "source": (Process, Element),
    "target": (Process, Server),
    "condition": "target.hasAccessControl is False",
  },
  "AC05": {
    "description": "Elevation by Changing the Execution Flow in a process [vulnerability](https://cwe.mitre.org/data/definitions/288.html)",
    "source": (Process, Element, Datastore),
    "target": Process,
    "condition": "target.tracksExecutionFlow is False or target.hasAccessControl is False",
  },
  "OT01": {
    "description": "Cross Site Request Forgery [Vulnerability](https://cwe.mitre.org/data/definitions/352.html)",
    "source": Element,
    "target": (Process, Server),
    "condition": "target.implementsCSRFToken is False",
  },
  "DO01": {
    "description": "Potential Excessive Resource Consumption [vulnerability](https://cwe.mitre.org/data/definitions/400.html)",
    "source": Element,
    "target": (Process, Server),
    "condition": "target.handlesResourceConsumption is False",
  },
  "DO02": {
    "description": "Potential Process Crash or Stop [vulnerability](https://cwe.mitre.org/data/definitions/703.html)",
    "source": (Process, Datastore, Element),
    "target": Process,
    "condition": "target.handlesCrashes is False",
  },
  "DO03": {
    "description": "Data Flow Is Potentially Interrupted [vulnerability](https://cwe.mitre.org/data/definitions/364.html), [vulnerability 2](https://cwe.mitre.org/data/definitions/400.html)",
    "source": (Process, Datastore, Element),
    "target": (Process, Datastore),
    "condition": "target.handlesInterruptions is False",
  },
  "DO04": {
    "description": "Data Store Inaccessible, [vulnerability](https://cwe.mitre.org/data/definitions/400.html), [attack](https://capec.mitre.org/data/definitions/262.html)",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "target.isResilient is False",
  },
  "AA04": {
    "description": "Authorization Bypass [vulnerability](https://cwe.mitre.org/data/definitions/285.html)",
    "source": Element,
    "target": (Process, Datastore),
    "condition": "target.authorizesSource is False",
  },
  "DE01": {
    "description": "Data Flow Sniffing [attack](https://capec.mitre.org/data/definitions/157.html)",
    "source": (Process, Element, Datastore),
    "target": Dataflow,
    "condition": "target.protocol == 'HTTP' and target.isEncrypted is False",
  },
  "AC06": {
    "description": "Weak Access Control for a Resource [vulnerability](https://cwe.mitre.org/data/definitions/284.html)",
    "source": (Process, Datastore, Element),
    "target": (Process, Datastore),
    "condition": "target.hasAccessControl is False",
  },
  "DS01": {
    "description": "Weak Credential Storage [vulnerability](https://cwe.mitre.org/data/definitions/256.html)",
    "source": (Process, Element),
    "target": Datastore,
    "condition": "(target.storesPII is True or target.storesSensitiveData is True) and (target.isEncrypted is False or target.providesConfidentiality is False or target.providesIntegrity is False)",
  },
  "DE02": {
    "description": "Weak Credential Transit [vulnerability](https://cwe.mitre.org/data/definitions/319.html)",
    "source": (Process, Datastore, Element),
    "target": Dataflow,
    "condition": "target.authenticatedWith is False and target.protocol == 'HTTP'",
},
  "AA05": {
    "description": "Weak Authentication Scheme [vulnerability](https://cwe.mitre.org/data/definitions/308.html)",
    "source": (Process, Element),
    "target": (Process, Datastore, Server),
    "condition": "target.authenticationScheme in ('Basic', 'BASIC')",
},
  "LB01": {
    "description": "Lambda does not authenticate source of request [vulnerability](https://cwe.mitre.org/data/definitions/345.html)",
    "source": (Process, Element),
    "target": Lambda,
    "condition": "target.authenticatesSource is False",
},
  "LB02": {
    "description": "Lambda has no access control [vulnerability](https://cwe.mitre.org/data/definitions/284.html)",
    "source": (Process, Element),
    "target": Lambda,
    "condition": "target.hasAccessControl is False",
},
  "LB03": {
    "description": "Lambda does not handle resource consumption [vulnerability](https://cwe.mitre.org/data/definitions/400.html)",
    "source": (Process, Element),
    "target": Lambda,
    "condition": "target.handlesResourceConsumption is False",
}
}
