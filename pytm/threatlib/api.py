"""API security threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class API01(Threat):
    """Exploit Test APIs."""

    id: str = 'API01'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Exploit Test APIs'
    details: str = 'An attacker exploits a sample, demonstration, or test API that is insecure by default and should not be resident on production systems. Some applications include APIs that are intended to allow an administrator to test and refine their domain. These APIs should usually be disabled once a system enters a production environment. Testing APIs may expose a great deal of diagnostic information intended to aid an administrator, but which can also be used by an attacker to further refine their attack. Moreover, testing APIs may not have adequate security controls or may not have undergone rigorous testing since they were not intended for use in production environments. As such, they may have many flaws and vulnerabilities that would allow an attacker to severely disrupt a target.'
    likelihood: str = "Low"
    severity: str = "High"
    prerequisites: str = 'The target must have installed test APIs and failed to secure or remove them when brought into a production environment.'
    mitigations: str = 'Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.'
    example: str = 'Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.'
    references: str = 'https://capec.mitre.org/data/definitions/121.html, http://cwe.mitre.org/data/definitions/489.html'

    def _check_condition(self, target) -> bool:
        return target.implementsAPI is True

class API02(Threat):
    """Exploit Script-Based APIs."""

    id: str = 'API02'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Exploit Script-Based APIs'
    details: str = 'Some APIs support scripting instructions as arguments. Methods that take scripted instructions (or references to scripted instructions) can be very flexible and powerful. However, if an attacker can specify the script that serves as input to these methods they can gain access to a great deal of functionality. For example, HTML pages support <script> tags that allow scripting languages to be embedded in the page and then interpreted by the receiving web browser. If the content provider is malicious, these scripts can compromise the client application. Some applications may even execute the scripts under their own identity (rather than the identity of the user providing the script) which can allow attackers to perform activities that would otherwise be denied to them.'
    severity: str = "Medium"
    prerequisites: str = 'The target application must include the use of APIs that execute scripts.The target application must allow the attacker to provide some or all of the arguments to one of these script interpretation methods and must fail to adequately filter these arguments for dangerous or unwanted script commands.'
    mitigations: str = 'Always use HTTPS and SSL Certificates. Firewall optimizations to prevent unauthorized access to or from a private network. Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API. Use IP whitelisting and rate limiting.'
    example: str = 'Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.'
    references: str = 'https://capec.mitre.org/data/definitions/160.html, http://cwe.mitre.org/data/definitions/346.html'

    def _check_condition(self, target) -> bool:
        return target.implementsAPI is True and target.controls.validatesInput is False
