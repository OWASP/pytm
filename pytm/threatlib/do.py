"""Denial of service threat definitions."""

from __future__ import annotations

import pytm

from pytm.enums import Likelihood, Severity
from pytm.threat import Threat

class DO01(Threat):
    """Flooding."""

    id: str = 'DO01'
    target: tuple = (pytm.Process, pytm.Server)
    description: str = 'Flooding'
    details: str = "An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target's operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target."
    likelihood: Likelihood = Likelihood.HIGH
    severity: Severity = Severity.MEDIUM
    prerequisites: str = 'Any target that services requests is vulnerable to this attack on some level of scale.'
    mitigations: str = 'Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.'
    example: str = 'Adversary tries to bring a network or service down by flooding it with large amounts of traffic.'
    references: str = 'https://capec.mitre.org/data/definitions/125.html, http://cwe.mitre.org/data/definitions/404.html, http://cwe.mitre.org/data/definitions/770.html'

    def condition_applies(self, target) -> bool:
        return target.controls.handlesResourceConsumption is False or target.controls.isResilient is False

class DO02(Threat):
    """Excessive Allocation."""

    id: str = 'DO02'
    target: tuple = (pytm.Process, pytm.Server, pytm.Datastore, pytm.Lambda)
    description: str = 'Excessive Allocation'
    details: str = "An adversary causes the target to allocate excessive resources to servicing the attackers' request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request."
    likelihood: Likelihood = Likelihood.MEDIUM
    severity: Severity = Severity.MEDIUM
    prerequisites: str = 'The target must accept service requests from the attacker and the adversary must be able to control the resource allocation associated with this request to be in excess of the normal allocation. The latter is usually accomplished through the presence of a bug on the target that allows the adversary to manipulate variables used in the allocation.'
    mitigations: str = 'Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.'
    example: str = 'In an Integer Attack, the adversary could cause a variable that controls allocation for a request to hold an excessively large value. Excessive allocation of resources can render a service degraded or unavailable to legitimate users and can even lead to crashing of the target.'
    references: str = 'https://capec.mitre.org/data/definitions/130.html, http://cwe.mitre.org/data/definitions/770.html, http://cwe.mitre.org/data/definitions/404.html'

    def condition_applies(self, target) -> bool:
        return target.controls.handlesResourceConsumption is False

class DO03(Threat):
    """XML Ping of the Death."""

    id: str = 'DO03'
    target: tuple = (pytm.Dataflow,)
    description: str = 'XML Ping of the Death'
    details: str = 'An attacker initiates a resource depletion attack where a large number of small XML messages are delivered at a sufficiently rapid rate to cause a denial of service or crash of the target. Transactions such as repetitive SOAP transactions can deplete resources faster than a simple flooding attack because of the additional resources used by the SOAP protocol and the resources necessary to process SOAP messages. The transactions used are immaterial as long as they cause resource utilization on the target. In other words, this is a normal flooding attack augmented by using messages that will require extra processing on the target.'
    likelihood: Likelihood = Likelihood.LOW
    severity: Severity = Severity.MEDIUM
    prerequisites: str = 'The target must receive and process XML transactions.'
    mitigations: str = 'Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval. Implementation: Provide for network flow control and traffic shaping to control access to the resources.'
    example: str = 'Consider the case of attack performed against the createCustomerBillingAccount Web Service for an online store. In this case, the createCustomerBillingAccount Web Service receives a huge number of simultaneous requests, containing nonsense billing account creation information (the small XML messages). The createCustomerBillingAccount Web Services may forward the messages to other Web Services for processing. The application suffers from a high load of requests, potentially leading to a complete loss of availability the involved Web Service.'
    references: str = 'https://capec.mitre.org/data/definitions/147.html, http://cwe.mitre.org/data/definitions/400.html, http://cwe.mitre.org/data/definitions/770.html'

    def condition_applies(self, target) -> bool:
        return any(d.format == 'XML' for d in target.data)

class DO04(Threat):
    """XML Entity Expansion."""

    id: str = 'DO04'
    target: tuple = (pytm.Dataflow,)
    description: str = 'XML Entity Expansion'
    details: str = "An attacker submits an XML document to a target application where the XML document uses nested entity expansion to produce an excessively large output XML. XML allows the definition of macro-like structures that can be used to simplify the creation of complex structures. However, this capability can be abused to create excessive demands on a processor's CPU and memory. A small number of nested expansions can result in an exponential growth in demands on memory."
    likelihood: Likelihood = Likelihood.HIGH
    severity: Severity = Severity.MEDIUM
    prerequisites: str = 'This type of attack requires that the target must receive XML input but either fail to provide an upper limit for entity expansion or provide a limit that is so large that it does not preclude significant resource consumption.'
    mitigations: str = 'Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.Implementation: Disable altogether the use of inline DTD schemas in your XML parsing objects. If must use DTD, normalize, filter and white list and parse with methods and routines that will detect entity expansion from untrusted sources.'
    example: str = "The most common example of this type of attack is the many laughs attack (sometimes called the 'billion laughs' attack). For example: <?xml version=1.0?><!DOCTYPE lolz [<!ENTITY lol lol><!ENTITY lol2 &lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;><!ENTITY lol3 &lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;><!ENTITY lol4 &lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;><!ENTITY lol5 &lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;><!ENTITY lol6 &lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;><!ENTITY lol7 &lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6><!ENTITY lol8 &lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;><!ENTITY lol9 &lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;> ]><lolz>&lol9;</lolz> This is well formed and valid XML according to the DTD. Each entity increases the number entities by a factor of 10. The line of XML containing lol9; expands out exponentially to a message with 10^9 entities. A small message of a few KBs in size can easily be expanded into a few GB of memory in the parser. By including 3 more entities similar to the lol9 entity in the above code to the DTD, the program could expand out over a TB as there will now be 10^12 entities. Depending on the robustness of the target machine, this can lead to resource depletion, application crash, or even the execution of arbitrary code through a buffer overflow."
    references: str = 'https://capec.mitre.org/data/definitions/197.html, http://cwe.mitre.org/data/definitions/400.html, http://cwe.mitre.org/data/definitions/770.html'

    def condition_applies(self, target) -> bool:
        return any(d.format == 'XML' for d in target.data)

class DO05(Threat):
    """XML Nested Payloads."""

    id: str = 'DO05'
    target: tuple = (pytm.Server,)
    description: str = 'XML Nested Payloads'
    details: str = "Applications often need to transform data in and out of the XML format by using an XML parser. It may be possible for an attacker to inject data that may have an adverse effect on the XML parser when it is being processed. By nesting XML data and causing this data to be continuously self-referential, an attacker can cause the XML parser to consume more resources while processing, causing excessive memory consumption and CPU utilization. An attacker's goal is to leverage parser failure to his or her advantage. In most cases this type of an attack will result in a denial of service due to an application becoming unstable, freezing, or crash. However it may be possible to cause a crash resulting in arbitrary code execution, leading to a jump from the data plane to the control plane [R.230.1]."
    likelihood: Likelihood = Likelihood.MEDIUM
    severity: Severity = Severity.HIGH
    prerequisites: str = 'An application uses an XML parser to perform transformation on user-controllable data.An application does not perform sufficient validation to ensure that user-controllable data is safe for an XML parser.'
    mitigations: str = 'Carefully validate and sanitize all user-controllable data prior to passing it to the XML parser routine. Ensure that the resultant data is safe to pass to the XML parser.Perform validation on canonical data.Pick a robust implementation of an XML parser.Validate XML against a valid schema or DTD prior to parsing.'
    example: str = "An adversary crafts input data that may have an adverse effect on the operation of the XML parser when the data is parsed on the victim's system."
    references: str = 'https://capec.mitre.org/data/definitions/230.html, http://cwe.mitre.org/data/definitions/112.html, http://cwe.mitre.org/data/definitions/770.html'

    def condition_applies(self, target) -> bool:
        return target.usesXMLParser is True and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)
