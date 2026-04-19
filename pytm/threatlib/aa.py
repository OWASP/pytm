"""Authentication and authorization threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class AA01(Threat):
    """Authentication Abuse/ByPass."""

    id: str = 'AA01'
    target: tuple = (pytm.Server, pytm.Process)
    description: str = 'Authentication Abuse/ByPass'
    details: str = "An attacker obtains unauthorized access to an application, service or device either through knowledge of the inherent weaknesses of an authentication mechanism, or by exploiting a flaw in the authentication scheme's implementation. In such an attack an authentication mechanism is functioning but a carefully controlled sequence of events causes the mechanism to grant access to the attacker. This attack may exploit assumptions made by the target's authentication procedures, such as assumptions regarding trust relationships or assumptions regarding the generation of secret values. This attack differs from Authentication Bypass attacks in that Authentication Abuse allows the attacker to be certified as a valid user through illegitimate means, while Authentication Bypass allows the user to access protected material without ever being certified as an authenticated user. This attack does not rely on prior sessions established by successfully authenticating users, as relied upon for the Exploitation of Session Variables, Resource IDs and other Trusted Credentials attack patterns."
    severity: str = "Medium"
    prerequisites: str = 'An authentication mechanism or subsystem implementing some form of authentication such as passwords, digest authentication, security certificates, etc. which is flawed in some way.'
    mitigations: str = 'Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.'
    example: str = 'An adversary that has previously obtained unauthorized access to certain device resources, uses that access to obtain information such as location and network information.'
    references: str = 'https://capec.mitre.org/data/definitions/114.html, http://cwe.mitre.org/data/definitions/287.html'

    def _check_condition(self, target) -> bool:
        return target.controls.authenticatesSource is False

class AA02(Threat):
    """Principal Spoof."""

    id: str = 'AA02'
    target: tuple = (pytm.Server, pytm.Process)
    description: str = 'Principal Spoof'
    details: str = "A Principal Spoof is a form of Identity Spoofing where an adversary pretends to be some other person in an interaction. This is often accomplished by crafting a message (either written, verbal, or visual) that appears to come from a person other than the adversary. Phishing and Pharming attacks often attempt to do this so that their attempts to gather sensitive information appear to come from a legitimate source. A Principal Spoof does not use stolen or spoofed authentication credentials, instead relying on the appearance and content of the message to reflect identity. The possible outcomes of a Principal Spoof mirror those of Identity Spoofing. (e.g., escalation of privilege and false attribution of data or activities) Likewise, most techniques for Identity Spoofing (crafting messages or intercepting and replaying or modifying messages) can be used for a Principal Spoof attack. However, because a Principal Spoof is used to impersonate a person, social engineering can be both an attack technique (using social techniques to generate evidence in support of a false identity) as well as a possible outcome (manipulating people's perceptions by making statements or performing actions under a target's name)."
    severity: str = "Medium"
    prerequisites: str = "The target must associate data or activities with a person's identity and the adversary must be able to modify this identity without detection."
    mitigations: str = 'Employ robust authentication processes (e.g., multi-factor authentication).'
    example: str = 'An adversary may craft messages that appear to come from a different principle or use stolen / spoofed authentication credentials.'
    references: str = 'https://capec.mitre.org/data/definitions/195.html'

    def _check_condition(self, target) -> bool:
        return target.controls.authenticatesSource is False

class AA03(Threat):
    """Exploitation of Trusted Credentials."""

    id: str = 'AA03'
    target: tuple = (pytm.Server,)
    description: str = 'Exploitation of Trusted Credentials'
    details: str = "Attacks on session IDs and resource IDs take advantage of the fact that some software accepts user input without verifying its authenticity. For example, a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or indeed the process that wrote the message to the queue are authentic and authorized to do so. Many server side processes are vulnerable to these attacks because the server to server communications have not been analyzed from a security perspective or the processes trust other systems because they are behind a firewall. In a similar way servers that use easy to guess or spoofable schemes for representing digital identity can also be vulnerable. Such systems frequently use schemes without cryptography and digital signatures (or with broken cryptography). Session IDs may be guessed due to insufficient randomness, poor protection (passed in the clear), lack of integrity (unsigned), or improperly correlation with access control policy enforcement points. Exposed configuration and properties files that contain system passwords, database connection strings, and such may also give an attacker an edge to identify these identifiers. The net result is that spoofing and impersonation is possible leading to an attacker's ability to break authentication, authorization, and audit controls on the system."
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Server software must rely on weak session IDs proof and/or verification schemes'
    mitigations: str = 'Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.'
    example: str = "Thin client applications like web applications are particularly vulnerable to session ID attacks. Since the server has very little control over the client, but still must track sessions, data, and objects on the server side, cookies and other mechanisms have been used to pass the key to the session data between the client and server. When these session keys are compromised it is trivial for an attacker to impersonate a user's session in effect, have the same capabilities as the authorized user. There are two main ways for an attacker to exploit session IDs. A brute force attack involves an attacker repeatedly attempting to query the system with a spoofed session header in the HTTP request. A web server that uses a short session ID can be easily spoofed by trying many possible combinations so the parameters session-ID= 1234 has few possible combinations, and an attacker can retry several hundred or thousand request with little to no issue on their side. The second method is interception, where a tool such as wireshark is used to sniff the wire and pull off any unprotected session identifiers. The attacker can then use these variables and access the application."
    references: str = 'https://capec.mitre.org/data/definitions/21.html, http://cwe.mitre.org/data/definitions/290.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/664.html'

    def _check_condition(self, target) -> bool:
        return target.controls.providesIntegrity is False or target.controls.authenticatesSource is False or target.controls.usesStrongSessionIdentifiers is False

class AA04(Threat):
    """Exploiting Trust in Client."""

    id: str = 'AA04'
    target: tuple = (pytm.Server,)
    description: str = 'Exploiting Trust in Client'
    details: str = 'An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by placing themselves in the communication channel between client and server such that communication directly to the server is possible where the server believes it is communicating only with a valid client. There are numerous variations of this type of attack.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Server software must rely on client side formatted and validated values, and not reinforce these checks on the server side.'
    mitigations: str = 'Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.'
    example: str = "Web applications may use JavaScript to perform client side validation, request encoding/formatting, and other security functions, which provides some usability benefits and eliminates some client-server round-tripping. However, the web server cannot assume that the requests it receives have been subject to those validations, because an attacker can use an alternate method for crafting the HTTP Request and submit data that contains poisoned values designed to spoof a user and/or get the web server to disclose information.Web 2.0 style applications may be particularly vulnerable because they in large part rely on existing infrastructure which provides scalability without the ability to govern the clients. Attackers identify vulnerabilities that either assume the client side is responsible for some security services (without the requisite ability to ensure enforcement of these checks) and/or the lack of a hardened, default deny server configuration that allows for an attacker probing for weaknesses in unexpected ways. Client side validation, request formatting and other services may be performed, but these are strictly usability enhancements not security enhancements.Many web applications use client side scripting like JavaScript to enforce authentication, authorization, session state and other variables, but at the end of day they all make requests to the server. These client side checks may provide usability and performance gains, but they lack integrity in terms of the http request. It is possible for an attacker to post variables directly to the server without using any of the client script security checks and customize the patterns to impersonate other users or probe for more information.Many message oriented middleware systems like MQ Series are rely on information that is passed along with the message request for making authorization decisions, for example what group or role the request should be passed. However, if the message server does not or cannot authenticate the authorization information in the request then the server's policy decisions about authorization are trivial to subvert because the client process can simply elevate privilege by passing in elevated group or role information which the message server accepts and acts on."
    references: str = 'https://capec.mitre.org/data/definitions/22.html, http://cwe.mitre.org/data/definitions/287.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsServerSideValidation is False and (target.controls.providesIntegrity is False or target.controls.authorizesSource is False)
