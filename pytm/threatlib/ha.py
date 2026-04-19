"""Hardware and path threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class HA01(Threat):
    """Path Traversal."""

    id: str = 'HA01'
    target: tuple = (pytm.Server,)
    description: str = 'Path Traversal'
    details: str = 'An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory structure and into the root file system. By replacing or modifying the expected path information the access function or API retrieves the file desired by the attacker. These attacks either involve the attacker providing a complete path to a targeted file or using control characters (e.g. path separators (/ or ) and/or dots (.)) to reach desired directories or files.'
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'The attacker must be able to control the path that is requested of the target.The target must fail to adequately sanitize incoming paths'
    mitigations: str = 'Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.'
    example: str = 'An example of using path traversal to attack some set of resources on a web server is to use a standard HTTP request http://example/../../../../../etc/passwd From an attacker point of view, this may be sufficient to gain access to the password file on a poorly protected system. If the attacker can list directories of critical resources then read only access is not sufficient to protect the system.'
    references: str = 'https://capec.mitre.org/data/definitions/126.html, http://cwe.mitre.org/data/definitions/22.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False and target.controls.sanitizesInput is False

class HA02(Threat):
    """White Box Reverse Engineering."""

    id: str = 'HA02'
    target: tuple = (pytm.ExternalEntity,)
    description: str = 'White Box Reverse Engineering'
    details: str = 'An attacker discovers the structure, function, and composition of a type of computer software through white box analysis techniques. White box techniques involve methods which can be applied to a piece of software when an executable or some other compiled object can be directly subjected to analysis, revealing at least a portion of its machine instructions that can be observed upon execution.'
    severity: str = "Medium"
    prerequisites: str = 'Direct access to the object or software.'
    mitigations: str = 'Employ code obfuscation techniques to prevent the adversary from reverse engineering the targeted entity.'
    example: str = 'Attacker identifies client components to extract information from. These may be binary executables, class files, shared libraries (e.g., DLLs), configuration files, or other system files.'
    references: str = 'https://capec.mitre.org/data/definitions/167.html'

    def _check_condition(self, target) -> bool:
        return target.hasPhysicalAccess is True

class HA03(Threat):
    """Web Application Fingerprinting."""

    id: str = 'HA03'
    target: tuple = (pytm.Server,)
    description: str = 'Web Application Fingerprinting'
    details: str = 'An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This information can then be used by an attacker to formulate a targeted attack plan. While web application fingerprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.'
    likelihood: str = "High"
    severity: str = "Low"
    prerequisites: str = 'Any web application can be fingerprinted. However, some configuration choices can limit the useful information an attacker may collect during a fingerprinting attack.'
    mitigations: str = "Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message."
    example: str = 'An attacker sends malformed requests or requests of nonexistent pages to the server. Consider the following HTTP responses. Response from Apache 1.3.23$ nc apache.server.com80 GET / HTTP/3.0 HTTP/1.1 400 Bad RequestDate: Sun, 15 Jun 2003 17:12: 37 GMTServer: Apache/1.3.23Connection: closeTransfer: chunkedContent-Type: text/HTML; charset=iso-8859-1 Response from IIS 5.0$ nc iis.server.com 80GET / HTTP/3.0 HTTP/1.1 200 OKServer: Microsoft-IIS/5.0Content-Location: http://iis.example.com/Default.htmDate: Fri, 01 Jan 1999 20:14: 02 GMTContent-Type: text/HTMLAccept-Ranges: bytes Last-Modified: Fri, 01 Jan 1999 20:14: 02 GMTETag: W/e0d362a4c335be1: ae1Content-Length: 133 [R.170.2]'
    references: str = 'https://capec.mitre.org/data/definitions/170.html, http://cwe.mitre.org/data/definitions/497.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesHeaders is False or target.controls.encodesOutput is False or target.controls.isHardened is False

class HA04(Threat):
    """Reverse Engineering."""

    id: str = 'HA04'
    target: tuple = (pytm.ExternalEntity,)
    description: str = 'Reverse Engineering'
    details: str = 'An adversary discovers the structure, function, and composition of an object, resource, or system by using a variety of analysis techniques to effectively determine how the analyzed entity was constructed or operates. The goal of reverse engineering is often to duplicate the function, or a part of the function, of an object in order to duplicate or back engineer some aspect of its functioning. Reverse engineering techniques can be applied to mechanical objects, electronic devices, or software, although the methodology and techniques involved in each type of analysis differ widely.'
    likelihood: str = "Low"
    severity: str = "Low"
    prerequisites: str = 'Access to targeted system, resources, and information.'
    mitigations: str = 'Employ code obfuscation techniques to prevent the adversary from reverse engineering the targeted entity.'
    example: str = "When adversaries are reverse engineering software, methodologies fall into two broad categories, 'white box' and 'black box.' White box techniques involve methods which can be applied to a piece of software when an executable or some other compiled object can be directly subjected to analysis, revealing at least a portion of its machine instructions that can be observed upon execution. 'Black Box' methods involve interacting with the software indirectly, in the absence of the ability to measure, instrument, or analyze an executable object directly. Such analysis typically involves interacting with the software at the boundaries of where the software interfaces with a larger execution environment, such as input-output vectors, libraries, or APIs."
    references: str = 'https://capec.mitre.org/data/definitions/188.html'

    def _check_condition(self, target) -> bool:
        return target.hasPhysicalAccess is True
