"""Cryptography and session threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class CR01(Threat):
    """Session Sidejacking."""

    id: str = "CR01"
    target: tuple = (pytm.Dataflow, pytm.Server)
    description: str = "Session Sidejacking"
    details: str = (
        "Session sidejacking takes advantage of an unencrypted communication channel "
        "between a victim and target system. The attacker sniffs traffic on a network "
        "looking for session tokens in unencrypted traffic. Once a session token is "
        "captured, the attacker performs malicious actions by using the stolen token "
        "with the targeted application to impersonate the victim."
    )
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = (
        "An attacker and the victim are both using the same WiFi network. "
        "The victim has an active session with a target system. "
        "The victim is not using a secure channel to communicate with the target system "
        "(e.g. SSL, VPN, etc.)."
    )
    mitigations: str = (
        "Make sure that HTTPS is used to communicate with the target system. "
        "Alternatively, use VPN if possible. "
        "It is important to ensure that all communication between the client and the "
        "server happens via an encrypted secure channel. "
        "Modify the session token with each transmission and protect it with cryptography. "
        "Add the idea of request sequencing that gives the server an ability to detect "
        "replay attacks."
    )
    example: str = (
        "The attacker and the victim are using the same WiFi public hotspot. "
        "When the victim connects to the hotspot, he has a hosted e-mail account open. "
        "This e-mail account uses AJAX on the client side which periodically asynchronously "
        "connects to the server side and transfers the user's session token to the server. "
        "The victim's session token is now flowing unencrypted and the attacker leverages "
        "this opportunity to capture it."
    )
    references: str = (
        "https://capec.mitre.org/data/definitions/102.html, "
        "http://cwe.mitre.org/data/definitions/294.html, "
        "http://cwe.mitre.org/data/definitions/614.html, "
        "http://cwe.mitre.org/data/definitions/319.html, "
        "http://cwe.mitre.org/data/definitions/523.html, "
        "http://cwe.mitre.org/data/definitions/522.html"
    )

    def _check_condition(self, target) -> bool:
        return (
            target.protocol == "HTTP" or target.usesVPN is False
        ) and target.usesSessionTokens is True

class CR02(Threat):
    """Cross Site Tracing."""

    id: str = 'CR02'
    target: tuple = (pytm.Dataflow, pytm.Server)
    description: str = 'Cross Site Tracing'
    details: str = "Cross Site Tracing (XST) enables an adversary to steal the victim's session cookie and possibly other authentication credentials transmitted in the header of the HTTP request when the victim's browser communicates to destination system's web server. The adversary first gets a malicious script to run in the victim's browser that induces the browser to initiate an HTTP TRACE request to the web server. If the destination web server allows HTTP TRACE requests, it will proceed to return a response to the victim's web browser that contains the original HTTP request in its body. The function of HTTP TRACE, as defined by the HTTP specification, is to echo the request that the web server receives from the client back to the client. Since the HTTP header of the original request had the victim's session cookie in it, that session cookie can now be picked off the HTTP TRACE response and sent to the adversary's malicious site. XST becomes relevant when direct access to the session cookie via the document.cookie object is disabled with the use of httpOnly attribute which ensures that the cookie can be transmitted in HTTP requests but cannot be accessed in other ways. Using SSL does not protect against XST. If the system with which the victim is interacting is susceptible to XSS, an adversary can exploit that weakness directly to get his or her malicious script to issue an HTTP TRACE request to the destination system's web server. In the absence of an XSS weakness on the site with which the victim is interacting, an adversary can get the script to come from the site that he controls and get it to execute in the victim's browser (if he can trick the victim's into visiting his malicious website or clicking on the link that he supplies). However, in that case, due to the same origin policy protection mechanism in the browser, the adversary's malicious script cannot directly issue an HTTP TRACE request to the destination system's web server because the malicious script did not originate at that domain. An adversary will then need to find a way to exploit another weakness that would enable him or her to get around the same origin policy protection."
    likelihood: str = "Medium"
    severity: str = "Very high"
    prerequisites: str = "HTTP TRACE is enabled on the web serverThe destination system is susceptible to XSS or an adversary can leverage some other weakness to bypass the same origin policyScripting is enabled in the client's browserHTTP is used as the communication protocol between the server and the client"
    mitigations: str = "Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits."
    example: str = "An adversary determines that a particular system is vulnerable to reflected cross-site scripting (XSS) and endeavors to leverage this weakness to steal the victim's authentication cookie. An adversary realizes that since httpOnly attribute is set on the user's cookie, it is not possible to steal it directly with his malicious script. Instead, the adversary has their script use XMLHTTP ActiveX control in the victim's IE browser to issue an HTTP TRACE to the target system's server which has HTTP TRACE enabled. The original HTTP TRACE request contains the session cookie and so does the echoed response. The adversary picks the session cookie from the body of HTTP TRACE response and ships it to the adversary. The adversary then uses the newly acquired victim's session cookie to impersonate the victim in the target system."
    references: str = 'https://capec.mitre.org/data/definitions/107.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/648.html'

    def _check_condition(self, target) -> bool:
        return (target.protocol == 'HTTP' and target.usesSessionTokens is True) and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class CR03(Threat):
    """Dictionary-based Password Attack."""

    id: str = 'CR03'
    target: tuple = (pytm.Process, pytm.Server)
    description: str = 'Dictionary-based Password Attack'
    details: str = "An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user's account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern."
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'The system uses one factor password based authentication.The system does not have a sound password policy that is being enforced.The system does not implement an effective password throttling mechanism.'
    mitigations: str = 'Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.'
    example: str = "A system user selects the word treacherous as their passwords believing that it would be very difficult to guess. The password-based dictionary attack is used to crack this password and gain access to the account.The Cisco LEAP challenge/response authentication mechanism uses passwords in a way that is susceptible to dictionary attacks, which makes it easier for remote attackers to gain privileges via brute force password guessing attacks. Cisco LEAP is a mutual authentication algorithm that supports dynamic derivation of session keys. With Cisco LEAP, mutual authentication relies on a shared secret, the user's logon password (which is known by the client and the network), and is used to respond to challenges between the user and the Remote Authentication Dial-In User Service (RADIUS) server. Methods exist for someone to write a tool to launch an offline dictionary attack on password-based authentications that leverage Microsoft MS-CHAP, such as Cisco LEAP. The tool leverages large password lists to efficiently launch offline dictionary attacks against LEAP user accounts, collected through passive sniffing or active techniques.See also: CVE-2003-1096"
    references: str = 'https://capec.mitre.org/data/definitions/16.html, http://cwe.mitre.org/data/definitions/521.html, http://cwe.mitre.org/data/definitions/262.html, http://cwe.mitre.org/data/definitions/263.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsAuthenticationScheme is False

class CR04(Threat):
    """Session Credential Falsification through Forging."""

    id: str = 'CR04'
    target: tuple = (pytm.Server,)
    description: str = 'Session Credential Falsification through Forging'
    details: str = "An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to bypass authentication or piggy-back off some other authenticated user's session. This attack differs from Reuse of Session IDs and Session Sidejacking attacks in that in the latter attacks an attacker uses a previous or existing credential without modification while, in a forging attack, the attacker must create their own credential, although it may be based on previously observed credentials."
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The targeted application must use session credentials to identify legitimate users. Session identifiers that remains unchanged when the privilege levels change. Predictable session identifiers.'
    mitigations: str = 'Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.'
    example: str = "This example uses client side scripting to set session ID in the victim's browser. The JavaScript code document.cookie=sessionid=0123456789 fixates a falsified session credential into victim's browser, with the help of crafted a URL link. http://www.example.com/<script>document.cookie=sessionid=0123456789;</script> A similar example uses session ID as an argument of the URL. http://www.example.com/index.php/sessionid=0123456789 Once the victim clicks the links, the attacker may be able to bypass authentication or piggy-back off some other authenticated victim's session."
    references: str = 'https://capec.mitre.org/data/definitions/196.html, http://cwe.mitre.org/data/definitions/384.html, http://cwe.mitre.org/data/definitions/664.html'

    def _check_condition(self, target) -> bool:
        return target.usesSessionTokens is True and target.controls.implementsNonce is False

class CR05(Threat):
    """Encryption Brute Forcing."""

    id: str = 'CR05'
    target: tuple = (pytm.Server, pytm.Datastore)
    description: str = 'Encryption Brute Forcing'
    details: str = 'An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.'
    likelihood: str = "Low"
    severity: str = "Low"
    prerequisites: str = 'Ciphertext is known.Encryption algorithm and key size are known.'
    mitigations: str = "Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months."
    example: str = 'In 1997 the original DES challenge used distributed net computing to brute force the encryption key and decrypt the ciphertext to obtain the original plaintext. Each machine was given its own section of the key space to cover. The ciphertext was decrypted in 96 days.'
    references: str = 'https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesEncryptionAlgorithm != 'RSA' and target.controls.usesEncryptionAlgorithm != 'AES'

class CR06(Threat):
    """Communication Channel Manipulation."""

    id: str = 'CR06'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Communication Channel Manipulation'
    details: str = 'An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'The target application must leverage an open communications channel.The channel on which the target communicates must be vulnerable to interception (e.g., man in the middle attack).'
    mitigations: str = 'Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.'
    example: str = 'Using MITM techniques, an attacker launches a blockwise chosen-boundary attack to obtain plaintext HTTP headers by taking advantage of an SSL session using an encryption protocol in CBC mode with chained initialization vectors (IV). This allows the attacker to recover session IDs, authentication cookies, and possibly other valuable data that can be used for further exploitation. Additionally this could allow for the insertion of data into the stream, allowing for additional attacks (CSRF, SQL inject, etc) to occur.'
    references: str = 'https://capec.mitre.org/data/definitions/216.html'

    def _check_condition(self, target) -> bool:
        return (target.protocol != 'HTTPS' or target.usesVPN is False) and (target.controls.implementsAuthenticationScheme is False or target.controls.authorizesSource is False)

class CR07(Threat):
    """XML Routing Detour Attacks."""

    id: str = 'CR07'
    target: tuple = (pytm.Dataflow,)
    description: str = 'XML Routing Detour Attacks'
    details: str = 'An attacker subverts an intermediate system used to process XML content and forces the intermediate to modify and/or re-route the processing of the content. XML Routing Detour Attacks are Man in the Middle type attacks. The attacker compromises or inserts an intermediate system in the processing of the XML message. For example, WS-Routing can be used to specify a series of nodes or intermediaries through which content is passed. If any of the intermediate nodes in this route are compromised by an attacker they could be used for a routing detour attack. From the compromised system the attacker is able to route the XML process to other nodes of his or her choice and modify the responses so that the normal chain of processing is unaware of the interception. This system can forward the message to an outside entity and hide the forwarding and processing from the legitimate processing systems by altering the header information.'
    likelihood: str = "High"
    severity: str = "Medium"
    prerequisites: str = 'The targeted system must have multiple stages processing of XML content.'
    mitigations: str = 'Design: Specify maximum number intermediate nodes for the request and require SSL connections with mutual authentication.Implementation: Use SSL for connections between all parties with mutual authentication.'
    example: str = "Here is an example SOAP call from a client, example1.com, to a target, example4.com, via 2 intermediaries, example2.com and example3.com. (note: The client here is not necessarily a 'end user client' but rather the starting point of the XML transaction). Example SOAP message with routing information in header: &lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example1.com/&lt;/m:action&gt; &lt;m:to&gt;http://example4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt; ... &lt;/S:Body&gt; &lt;/S:Envelope&gt; Add an additional node (example3.com/router) to the XML path in a WS-Referral message &lt;r:ref xmlns:r=http://schemas.example.com/referral&gt; &lt;r:for&gt; &lt;r:prefix&gt;http://example2.com/router&lt;/r:prefix&gt; &lt;/r:for&gt; &lt;r:if/&gt; &lt;r:go&gt; &lt;r:via&gt;http://example3.com/router&lt;/r:via&gt; &lt;/r:go&gt; &lt;/r:ref&gt; Resulting in the following SOAP Header:&lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example1.com/&lt;/m:action&gt; &lt;m:to&gt;http://example4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;m:via&gt;http://example3.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt;...&lt;/S:Body&gt; &lt;/S:Envelope&gt; In the following example, the attacker injects a bogus routing node (using a WS-Referral service) into the routing table of the XML header but not access the message directly on the initiator/intermediary node that he/she has targeted. Example of WS-Referral based WS-Routing injection of the bogus node route:&lt;r:ref xmlns:r=http://schemas.example.com/referral&gt; &lt;r:for&gt; &lt;r:prefix&gt;http://example2.com/router&lt;/r:prefix&gt; &lt;/r:for&gt; &lt;r:if/&gt; &lt;r:go&gt; &lt;r:via&gt;http://evilsite1.com/router&lt;/r:via&gt; &lt;/r:go&gt; &lt;/r:ref&gt; Resulting XML Routing Detour attack:&lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example_0.com/&lt;/m:action&gt; &lt;m:to&gt;http://example_4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;m:via&gt;http://evilesite1.com/router&lt;/m:via&gt; &lt;m:via&gt;http://example3.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt; ... &lt;/S:Body&gt; &lt;/S:Envelope&gt; Thus, the attacker can route the XML message to the attacker controlled node (and access to the message contents)."
    references: str = 'https://capec.mitre.org/data/definitions/219.html'

    def _check_condition(self, target) -> bool:
        return target.protocol == 'HTTP' and any(d.format == 'XML' for d in target.data)

class CR08(Threat):
    """Client-Server Protocol Manipulation."""

    id: str = 'CR08'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Client-Server Protocol Manipulation'
    details: str = 'An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The client and/or server must utilize a protocol that has a weakness allowing manipulation of the interaction.'
    mitigations: str = 'Use strong authentication protocols.'
    example: str = 'An adversary could exploit existing communication protocol vulnerabilities and can launch MITM attacks and gain sensitive information or spoof client/server identities.'
    references: str = 'https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html'

    def _check_condition(self, target) -> bool:
        return not target.controls.isEncrypted or target.tlsVersion < target.sink.minTLSVersion
