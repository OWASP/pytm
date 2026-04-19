"""Load balancing and API threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class LB01(Threat):
    """API Manipulation."""

    id: str = 'LB01'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'API Manipulation'
    details: str = 'An adversary manipulates the use or processing of an Application Programming Interface (API) resulting in an adverse impact upon the security of the system implementing the API. This can allow the adversary to execute functionality not intended by the API implementation, possibly compromising the system which integrates the API. API manipulation can take on a number of forms including forcing the unexpected use of an API, or the use of an API in an unintended way. For example, an adversary may make a request to an application that leverages a non-standard API that is known to incorrectly validate its data and thus it may be manipulated by supplying metacharacters or alternate encodings as input, resulting in any number of injection flaws, including SQL injection, cross-site scripting, or command execution. Another example could be API methods that should be disabled in a production application but were not, thus exposing dangerous functionality within a production environment.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target system must expose API functionality in a manner that can be discovered and manipulated by an adversary. This may require reverse engineering the API syntax or decrypting/de-obfuscating client-server exchanges.'
    mitigations: str = 'Always use HTTPS and SSL Certificates. Firewall optimizations to prevent unauthorized access to or from a private network. Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API. Use IP whitelisting and rate limiting.'
    example: str = 'Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.'
    references: str = 'https://capec.mitre.org/data/definitions/113.html, http://cwe.mitre.org/data/definitions/227.html'

    def _check_condition(self, target) -> bool:
        return target.implementsAPI is True and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)
