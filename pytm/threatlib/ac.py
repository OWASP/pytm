"""Access control threat definitions."""

from __future__ import annotations

from typing import ClassVar

import pytm
from pytm.enums import Lifetime
from pytm.threat import Threat

class AC01(Threat):
    """Privilege Abuse."""

    id: str = 'AC01'
    target: tuple = (pytm.Server, pytm.Process, pytm.Datastore)
    description: str = 'Privilege Abuse'
    details: str = 'An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources. If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts. This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.'
    severity: str = "Medium"
    prerequisites: str = 'The target must have misconfigured their access control mechanisms such that sensitive information, which should only be accessible to more trusted users, remains accessible to less trusted users.The adversary must have access to the target, albeit with an account that is less privileged than would be appropriate for the targeted resources.'
    mitigations: str = 'Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.'
    example: str = 'An adversary that has previously obtained unauthorized access to certain device resources, uses that access to obtain information such as location and network information.'
    references: str = 'https://capec.mitre.org/data/definitions/122.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/269.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False or target.controls.authorizesSource is False

class AC02(Threat):
    """Shared Data Manipulation."""

    id: str = 'AC02'
    target: tuple = (pytm.Datastore,)
    description: str = 'Shared Data Manipulation'
    details: str = 'An adversary exploits a data structure shared between multiple applications or an application pool to affect application behavior. Data may be shared between multiple applications or between multiple threads of a single application. Data sharing is usually accomplished through mutual access to a single memory location. If an adversary can manipulate this shared data (usually by co-opting one of the applications or threads) the other applications or threads using the shared data will often continue to trust the validity of the compromised shared data and use it in their calculations. This can result in invalid trust assumptions, corruption of additional data through the normal operations of the other users of the shared data, or even cause a crash or compromise of the sharing applications.'
    severity: str = "Medium"
    prerequisites: str = 'The target applications (or target application threads) must share data between themselves.The adversary must be able to manipulate some piece of the shared data either directly or indirectly and the other users of the data must accept the changed data as valid. Usually this requires that the adversary be able to compromise one of the sharing applications or threads in order to manipulate the shared data.'
    mitigations: str = 'Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.'
    example: str = 'Adversary was able to compromise one of the sharing applications or data stores in order to manipulate shared data.'
    references: str = 'https://capec.mitre.org/data/definitions/124.html'

    def _check_condition(self, target) -> bool:
        return target.isShared is True

class AC03(Threat):
    """Subverting Environment Variable Values."""

    id: str = 'AC03'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Subverting Environment Variable Values'
    details: str = "The attacker directly or indirectly modifies environment variables used by or controlling the target software. The attacker's goal is to cause the target software to deviate from its expected operation in a manner that benefits the attacker."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An environment variable is accessible to the user.An environment variable used by the application can be tainted with user supplied data.Input data used in an environment variable is not validated properly.The variables encapsulation is not done properly. For instance setting a variable as public in a class makes it visible and an attacker may attempt to manipulate that variable.'
    mitigations: str = 'Protect environment variables against unauthorized read and write access. Protect the configuration files which contain environment variables against illegitimate read and write access. Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Apply the least privilege principles. If a process has no legitimate reason to read an environment variable do not give that privilege.'
    example: str = 'Changing the LD_LIBRARY_PATH environment variable in TELNET will cause TELNET to use an alternate (possibly Trojan) version of a function library. The Trojan library must be accessible using the target file system and should include Trojan code that will allow the user to log in with a bad password. This requires that the attacker upload the Trojan library to a specific location on the target. As an alternative to uploading a Trojan file, some file systems support file paths that include remote addresses, such as 172.16.2.100shared_filestrojan_dll.dll. See also: Path Manipulation (CVE-1999-0073). The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to ignorespace. HISTCONTROL can also be set to ignore duplicate commands by setting it to ignoredups. In some Linux systems, this is set by default to ignoreboth which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands.'
    references: str = 'https://capec.mitre.org/data/definitions/13.html, http://cwe.mitre.org/data/definitions/353.html, http://cwe.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/302.html'

    def _check_condition(self, target) -> bool:
        return target.usesEnvironmentVariables is True and (target.controls.implementsAuthenticationScheme is False or target.controls.validatesInput is False or target.controls.authorizesSource is False)

class AC04(Threat):
    """XML Schema Poisoning."""

    id: str = 'AC04'
    target: tuple = (pytm.Dataflow,)
    description: str = 'XML Schema Poisoning'
    details: str = 'An adversary corrupts or modifies the content of XML schema information passed between a client and server for the purpose of undermining the security of the target. XML Schemas provide the structure and content definitions for XML documents. Schema poisoning is the ability to manipulate a schema either by replacing or modifying it to compromise the programs that process documents that use this schema. Possible attacks are denial of service attacks by modifying the schema so that it does not contain required information for subsequent processing. For example, the unaltered schema may require a @name attribute in all submitted documents. If the adversary removes this attribute from the schema then documents created using the new grammar may lack this field, which may cause the processing application to enter an unexpected state or record incomplete data. In addition, manipulation of the data types described in the schema may affect the results of calculations taken by the document reader. For example, a float field could be changed to an int field. Finally, the adversary may change the encoding defined in the schema for certain fields allowing the contents to bypass filters that scan for dangerous strings. For example, the modified schema might us a URL encoding instead of ASCII, and a filter that catches a semicolon (;) might fail to detect its URL encoding (%3B).'
    likelihood: str = "Low"
    severity: str = "High"
    prerequisites: str = 'Some level of access to modify the target schema.The schema used by the target application must be improperly secured against unauthorized modification and manipulation.'
    mitigations: str = 'Design: Protect the schema against unauthorized modification. Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the XML document. Additionally, ensure that the proper permissions are set on local files to avoid unauthorized modification. Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.'
    example: str = "XML Schema Poisoning Attacks can often occur locally due to being embedded within the XML document itself or being located on the host within an improperaly protected file. In these cases, the adversary can simply edit the XML schema without the need for additional privileges. An example of the former can be seen below: <?xml version=1.0?> <!DOCTYPE contact [ <!ELEMENT contact (name,phone,email,address)> <!ELEMENT name (#PCDATA)> <!ELEMENT phone (#PCDATA)> <!ELEMENT email (#PCDATA)> <!ELEMENT address (#PCDATA)> ]> <note> <name>John Smith</name> <phone>555-1234</phone> <email>jsmith@email.com</email> <address>1 Example Lane</address> </note></capec:Code> If the 'name' attribute is required in all submitted documents and this field is removed by the adversary, the application may enter an unexpected state or record incomplete data. Additionally, if this data is needed to perform additional functions, a Denial of Service (DOS) may occur.XML Schema Poisoning Attacks can also be executed remotely if the HTTP protocol is being used to transport data. : <?xml version=1.0?> <!DOCTYPE contact SYSTEM http://example.com/contact.dtd[ <note> <name>John Smith</name> <phone>555-1234</phone> <email>jsmith@email.com</email> <address>1 Example Lane</address> </note></capec:Code> The HTTP protocol does not encrypt the traffic it transports, so all communication occurs in plaintext. This traffic can be observed and modified by the adversary during transit to alter the XML schema before it reaches the end user. The adversary can perform a Man-in-the-Middle (MITM) Attack to alter the schema in the same way as the previous example and to acheive the same results."
    references: str = 'https://capec.mitre.org/data/definitions/146.html, http://cwe.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/472.html'

    def _check_condition(self, target) -> bool:
        return any(d.format == 'XML' for d in target.data) and target.controls.authorizesSource is False

class AC05(Threat):
    """Content Spoofing."""

    id: str = 'AC05'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Content Spoofing'
    details: str = "An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary's content instead of the owner's content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes."
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target must provide content but fail to adequately protect it against modification.The adversary must have the means to alter data to which he/she is not authorized.If the content is to be modified in transit, the adversary must be able to intercept the targeted messages.'
    mitigations: str = 'Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.'
    example: str = "An attacker finds a site which is vulnerable to HTML Injection. He sends a URL with malicious code injected in the URL to the user of the website(victim) via email or some other social networking site. User visits the page because the page is located within trusted domain. When the victim accesses the page, the injected HTML code is rendered and presented to the user asking for username and password. The username and password are both sent to the attacker's server."
    references: str = 'https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html'

    def _check_condition(self, target) -> bool:
        return ((not target.source.controls.providesIntegrity or not target.sink.controls.providesIntegrity) and not target.controls.isEncrypted) or (target.source.inScope and not target.isResponse and (not target.controls.authenticatesDestination or not target.controls.checksDestinationRevocation))

class AC06(Threat):
    """Using Malicious Files."""

    id: str = 'AC06'
    target: tuple = (pytm.Server,)
    description: str = 'Using Malicious Files'
    details: str = "An attack of this type exploits a system's configuration that allows an attacker to either directly access an executable file, for example through shell access; or in a possible worst case allows an attacker to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the programmers and the administrators must be in synch regarding the interfaces and the correct privileges for each interface."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = "System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications between the subject and the object is set incorrectly or assumes a benign environment."
    mitigations: str = 'Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.'
    example: str = "Consider a directory on a web server with the following permissions drwxrwxrwx 5 admin public 170 Nov 17 01:08 webroot This could allow an attacker to both execute and upload and execute programs' on the web server. This one vulnerability can be exploited by a threat to probe the system and identify additional vulnerabilities to exploit."
    references: str = 'https://capec.mitre.org/data/definitions/17.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/272.html, http://cwe.mitre.org/data/definitions/270.html'

    def _check_condition(self, target) -> bool:
        return target.controls.isHardened is False or target.controls.hasAccessControl is False

class AC07(Threat):
    """Exploiting Incorrectly Configured Access Control Security Levels."""

    id: str = 'AC07'
    target: tuple = (pytm.Server,)
    description: str = 'Exploiting Incorrectly Configured Access Control Security Levels'
    details: str = 'An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many opportunities for mistakes. If an attacker can learn of incorrectly configured access security settings, they may be able to exploit this in an attack. Most commonly, attackers would take advantage of controls that provided too little protection for sensitive activities in order to perform actions that should be denied to them. In some circumstances, an attacker may be able to take advantage of overly restrictive access control policies, initiating denial of services (if an application locks because it unexpectedly failed to be granted access) or causing other legitimate actions to fail due to security. The latter class of attacks, however, is usually less severe and easier to detect than attacks based on inadequate security restrictions. This attack pattern differs from CAPEC 1, Accessing Functionality Not Properly Constrained by ACLs in that the latter describes attacks where sensitive functionality lacks access controls, where, in this pattern, the access control is present, but incorrectly configured.'
    likelihood: str = "High"
    severity: str = "Medium"
    prerequisites: str = "The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little security to some functionality, then the attacker may be able to exploit it if the access control would be the only thing preventing an attacker's access and it no longer does so. If the incorrect configuration applies too much security, it must prevent legitimate activity and the attacker must be able to force others to require this activity."
    mitigations: str = 'Design: Configure the access control correctly.'
    example: str = 'For example, an incorrectly configured Web server, may allow unauthorized access to it, thus threaten the security of the Web application.'
    references: str = 'https://capec.mitre.org/data/definitions/180.html, http://cwe.mitre.org/data/definitions/732.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False

class AC08(Threat):
    """Manipulate Registry Information."""

    id: str = 'AC08'
    target: tuple = (pytm.Server,)
    description: str = 'Manipulate Registry Information'
    details: str = 'An adversary exploits a weakness in authorization in order to modify content within a registry (e.g., Windows Registry, Mac plist, application registry). Editing registry information can permit the adversary to hide configuration information or remove indicators of compromise to cover up activity. Many applications utilize registries to store configuration and service information. As such, modification of registry information can affect individual services (affecting billing, authorization, or even allowing for identity spoofing) or the overall configuration of a targeted application. For example, both Java RMI and SOAP use registries to track available services. Changing registry values is sometimes a preliminary step towards completing another attack pattern, but given the long term usage of many registry values, manipulation of registry information could be its own end.'
    severity: str = "Medium"
    prerequisites: str = 'The targeted application must rely on values stored in a registry.The adversary must have a means of elevating permissions in order to access and modify registry content through either administrator privileges (e.g., credentialed access), or a remote access tool capable of editing a registry through an API.'
    mitigations: str = 'Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.'
    example: str = "Manipulating registration information can be undertaken in advance of a path traversal attack (inserting relative path modifiers) or buffer overflow attack (enlarging a registry value beyond an application's ability to store it)."
    references: str = 'https://capec.mitre.org/data/definitions/203.html, http://cwe.mitre.org/data/definitions/15.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False

class AC09(Threat):
    """Functionality Misuse."""

    id: str = 'AC09'
    target: tuple = (pytm.Server,)
    description: str = 'Functionality Misuse'
    details: str = 'An adversary leverages a legitimate capability of an application in such a way as to achieve a negative technical impact. The system functionality is not altered or modified but used in a way that was not intended. This is often accomplished through the overuse of a specific functionality or by leveraging functionality with design flaws that enables the adversary to gain access to unauthorized, sensitive data.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The adversary has the capability to interact with the application directly.The target system does not adequately implement safeguards to prevent misuse of authorized actions/processes.'
    mitigations: str = 'Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.'
    example: str = "An attacker clicks on the 'forgot password' and is presented with a single security question. The question is regarding the name of the first dog of the user. The system does not limit the number of attempts to provide the dog's name. An attacker goes through a list of 100 most popular dog names and finds the right name, thus getting the ability to reset the password and access the system."
    references: str = 'https://capec.mitre.org/data/definitions/212.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False or target.controls.authorizesSource is False

class AC10(Threat):
    """Exploiting Incorrectly Configured SSL."""

    id: str = 'AC10'
    target: tuple = (pytm.Server,)
    description: str = 'Exploiting Incorrectly Configured SSL'
    details: str = 'An adversary takes advantage of incorrectly configured SSL communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.'
    likelihood: str = "Low"
    severity: str = "High"
    prerequisites: str = 'Access to the client/server stream.'
    mitigations: str = 'Usage of configuration settings, such as stream ciphers vs. block ciphers and setting timeouts on SSL sessions to extremely low values lessens the potential impact. Use of later versions of TLS (e.g. TLS 1.1+) can also be effective, but not all clients or servers support the later versions.'
    example: str = 'Using MITM techniques, an attacker launches a blockwise chosen-boundary attack to obtain plaintext HTTP headers by taking advantage of an SSL session using an encryption protocol in CBC mode with chained initialization vectors (IV). This allows the attacker to recover session IDs, authentication cookies, and possibly other valuable data that can be used for further exploitation. Additionally this could allow for the insertion of data into the stream, allowing for additional attacks (CSRF, SQL inject, etc) to occur.'
    references: str = 'https://capec.mitre.org/data/definitions/217.html, http://cwe.mitre.org/data/definitions/201.html'

    def _check_condition(self, target) -> bool:
        return target.checkTLSVersion(target.inputs) and (not target.controls.implementsAuthenticationScheme or not target.controls.authorizesSource)

class AC11(Threat):
    """Session Credential Falsification through Manipulation."""

    id: str = 'AC11'
    target: tuple = (pytm.Server,)
    description: str = 'Session Credential Falsification through Manipulation'
    details: str = 'An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server. For example, a credential in the form of a web cookie might have a field that indicates the access rights of a user. By manually tweaking this cookie, a user might be able to increase their access rights to the server. Alternately an attacker may be able to manipulate an existing credential to appear as a different user. This attack differs from falsification through prediction in that the user bases their modified credentials off existing credentials instead of using patterns detected in prior credentials to create a new credential that is accepted because it fits the pattern. As a result, an attacker may be able to impersonate other users or elevate their permissions to a targeted service.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The targeted application must use session credentials to identify legitimate users.'
    mitigations: str = 'Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.'
    example: str = "An adversary uses client side scripting(JavaScript) to set session ID in the victim's browser using document.cookie. This fixates a falsified session credential into victim's browser with the help of a crafted URL link. Once the victim clicks on the link, the attacker is able to bypass authentication or piggyback off some other authenticated victim's session."
    references: str = 'https://capec.mitre.org/data/definitions/226.html, http://cwe.mitre.org/data/definitions/565.html, http://cwe.mitre.org/data/definitions/472.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesStrongSessionIdentifiers is False

class AC12(Threat):
    """Privilege Escalation."""

    id: str = 'AC12'
    target: tuple = (pytm.Process,)
    description: str = 'Privilege Escalation'
    details: str = 'An adversary exploits a weakness enabling them to elevate their privilege and perform an action that they are not supposed to be authorized to perform.'
    likelihood: str = "Medium"
    severity: str = "High"
    mitigations: str = 'Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.'
    example: str = 'The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor. As a result, the program is indefinitely operating in a raised privilege state, possibly allowing further exploitation to occur.'
    references: str = 'https://capec.mitre.org/data/definitions/233.html, http://cwe.mitre.org/data/definitions/269.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False or target.controls.implementsPOLP is False

class AC13(Threat):
    """Hijacking a privileged process."""

    id: str = 'AC13'
    target: tuple = (pytm.Process,)
    description: str = 'Hijacking a privileged process'
    details: str = 'An attacker gains control of a process that is assigned elevated privileges in order to execute arbitrary code with those privileges. Some processes are assigned elevated privileges on an operating system, usually through association with a particular user, group, or role. If an attacker can hijack this process, they will be able to assume its level of privilege in order to execute their own code. Processes can be hijacked through improper handling of user input (for example, a buffer overflow or certain types of injection attacks) or by utilizing system utilities that support process control that have been inadequately secured.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The targeted process or operating system must contain a bug that allows attackers to hijack the targeted process.'
    mitigations: str = 'Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.'
    example: str = 'The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor. As a result, the program is indefinitely operating in a raised privilege state, possibly allowing further exploitation to occur.'
    references: str = 'https://capec.mitre.org/data/definitions/234.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/648.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False or target.controls.implementsPOLP is False

class AC14(Threat):
    """Catching exception throw/signal from privileged block."""

    id: str = 'AC14'
    target: tuple = (pytm.Process,)
    description: str = 'Catching exception throw/signal from privileged block'
    details: str = "Attackers can sometimes hijack a privileged thread from the underlying system through synchronous (calling a privileged function that returns incorrectly) or asynchronous (callbacks, signal handlers, and similar) means. Having done so, the Attacker may not only likely access functionality the system's designer didn't intend for them, but they may also go undetected or deny other users essential service in a catastrophic (or insidiously subtle) way."
    likelihood: str = "Low"
    severity: str = "Very high"
    prerequisites: str = 'The application in question employs a threaded model of execution with the threads operating at, or having the ability to switch to, a higher privilege level than normal usersIn order to feasibly execute this class of attacks, the attacker must have the ability to hijack a privileged thread.This ability includes, but is not limited to, modifying environment variables that affect the process the thread belongs to, or providing malformed user-controllable input that causes the executing thread to fault and return to a higher privilege level or such.This does not preclude network-based attacks, but makes them conceptually more difficult to identify and execute.'
    mitigations: str = 'Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.'
    example: str = "Attacker targets an application written using Java's AWT, with the 1.2.2 era event model. In this circumstance, any AWTEvent originating in the underlying OS (such as a mouse click) would return a privileged thread. The Attacker could choose to not return the AWT-generated thread upon consuming the event, but instead leveraging its privilege to conduct privileged operations."
    references: str = 'https://capec.mitre.org/data/definitions/236.html, http://cwe.mitre.org/data/definitions/270.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsPOLP is False and (target.usesEnvironmentVariables is True or target.controls.validatesInput is False)

class AC15(Threat):
    """Schema Poisoning."""

    id: str = 'AC15'
    target: tuple = (pytm.Process,)
    description: str = 'Schema Poisoning'
    details: str = 'An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected state, or recording incomplete data.'
    likelihood: str = "Low"
    severity: str = "High"
    prerequisites: str = 'Some level of access to modify the target schema.The schema used by the target application must be improperly secured against unauthorized modification and manipulation.'
    mitigations: str = 'Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.'
    example: str = "In a JSON Schema Poisoning Attack, an adervary modifies the JSON schema to cause a Denial of Service (DOS) or to submit malicious input: { title: Contact, type: object, properties: { Name: { type: string }, Phone: { type: string }, Email: { type: string }, Address: { type: string } }, required: [Name, Phone, Email, Address] } If the 'name' attribute is required in all submitted documents and this field is removed by the adversary, the application may enter an unexpected state or record incomplete data. Additionally, if this data is needed to perform additional functions, a Denial of Service (DOS) may occur.In a Database Schema Poisoning Attack, an adversary alters the database schema being used to modify the database in some way. This can result in loss of data, DOS, or malicious input being submitted. Assuming there is a column named name, an adversary could make the following schema change: ALTER TABLE Contacts MODIFY Name VARCHAR(65353); The Name field of the Conteacts table now allows the storing of names up to 65353 characters in length. This could allow the adversary to store excess data within the database to consume system resource or to execute a DOS."
    references: str = 'https://capec.mitre.org/data/definitions/271.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsPOLP is False

class AC16(Threat):
    """Session Credential Falsification through Prediction."""

    id: str = 'AC16'
    target: tuple = (pytm.Server,)
    description: str = 'Session Credential Falsification through Prediction'
    details: str = 'This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are predictable. For example, the session IDs are generated using predictable information (e.g., time).'
    mitigations: str = 'Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.'
    example: str = "Jetty before 4.2.27, 5.1 before 5.1.12, 6.0 before 6.0.2, and 6.1 before 6.1.0pre3 generates predictable session identifiers using java.util.random, which makes it easier for remote attackers to guess a session identifier through brute force attacks, bypass authentication requirements, and possibly conduct cross-site request forgery attacks. See also: CVE-2006-6969mod_usertrack in Apache 1.3.11 through 1.3.20 generates session ID's using predictable information including host IP address, system time and server process ID, which allows local users to obtain session ID's and bypass authentication when these session ID's are used for authentication. See also: CVE-2001-1534"
    references: str = 'https://capec.mitre.org/data/definitions/59.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesStrongSessionIdentifiers is False

class AC17(Threat):
    """Session Hijacking - ServerSide."""

    id: str = 'AC17'
    target: tuple = (pytm.Server,)
    description: str = 'Session Hijacking - ServerSide'
    details: str = "This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An application that leverages sessions to perform authentication.'
    mitigations: str = 'Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.'
    example: str = 'Cross Site Injection Attack is a great example of Session Hijacking. Attacker can capture victim’s Session ID using XSS attack by using javascript. If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the link, the JavaScript will run and complete the instructions made by the attacker.'
    references: str = 'https://capec.mitre.org/data/definitions/593.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesStrongSessionIdentifiers is False

class AC18(Threat):
    """Session Hijacking - ClientSide."""

    id: str = 'AC18'
    target: tuple = (pytm.Process,)
    description: str = 'Session Hijacking - ClientSide'
    details: str = "This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An application that leverages sessions to perform authentication.'
    mitigations: str = 'Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.'
    example: str = 'Cross Site Injection Attack is a great example of Session Hijacking. Attacker can capture victim’s Session ID using XSS attack by using javascript. If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the link, the JavaScript will run and complete the instructions made by the attacker.'
    references: str = 'https://capec.mitre.org/data/definitions/593.html'

    def _check_condition(self, target) -> bool:
        return (target.controls.usesStrongSessionIdentifiers is False or target.controls.encryptsCookies is False) and target.controls.definesConnectionTimeout is False

class AC19(Threat):
    """Reusing Session IDs (aka Session Replay) - ServerSide."""

    id: str = 'AC19'
    target: tuple = (pytm.Server,)
    description: str = 'Reusing Session IDs (aka Session Replay) - ServerSide'
    details: str = 'This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are not well protected from session theft.'
    mitigations: str = 'Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.'
    example: str = "OpenSSL and SSLeay allow remote attackers to reuse SSL sessions and bypass access controls. See also: CVE-1999-0428Merak Mail IceWarp Web Mail uses a static identifier as a user session ID that does not change across sessions, which could allow remote attackers with access to the ID to gain privileges as that user, e.g. by extracting the ID from the user's answer or forward URLs. See also: CVE-2002-0258"
    references: str = 'https://capec.mitre.org/data/definitions/60.html'

    def _check_condition(self, target) -> bool:
        return target.usesSessionTokens is True and target.controls.implementsNonce is False

class AC20(Threat):
    """Reusing Session IDs (aka Session Replay) - ClientSide."""

    id: str = 'AC20'
    target: tuple = (pytm.Process,)
    description: str = 'Reusing Session IDs (aka Session Replay) - ClientSide'
    details: str = 'This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are not well protected from session theft.'
    mitigations: str = 'Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.'
    example: str = "OpenSSL and SSLeay allow remote attackers to reuse SSL sessions and bypass access controls. See also: CVE-1999-0428Merak Mail IceWarp Web Mail uses a static identifier as a user session ID that does not change across sessions, which could allow remote attackers with access to the ID to gain privileges as that user, e.g. by extracting the ID from the user's answer or forward URLs. See also: CVE-2002-0258"
    references: str = 'https://capec.mitre.org/data/definitions/60.html'

    def _check_condition(self, target) -> bool:
        return target.controls.definesConnectionTimeout is False and (target.controls.usesMFA is False or target.controls.encryptsSessionData is False)

class AC21(Threat):
    """Cross Site Request Forgery."""

    id: str = 'AC21'
    target: tuple = (pytm.Process,)
    description: str = 'Cross Site Request Forgery'
    details: str = "An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply riding the existing session cookie."
    likelihood: str = "High"
    severity: str = "Very high"
    mitigations: str = 'Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.'
    example: str = "While a user is logged into his bank account, an attacker can send an email with some potentially interesting content and require the user to click on a link in the email. The link points to or contains an attacker setup script, probably even within an iFrame, that mimics an actual user form submission to perform a malicious activity, such as transferring funds from the victim's account. The attacker can have the script embedded in, or targeted by, the link perform any arbitrary action as the authenticated user. When this script is executed, the targeted application authenticates and accepts the actions based on the victims existing session cookie.See also: Cross-site request forgery (CSRF) vulnerability in util.pl in @Mail WebMail 4.51 allows remote attackers to modify arbitrary settings and perform unauthorized actions as an arbitrary user, as demonstrated using a settings action in the SRC attribute of an IMG element in an HTML e-mail."
    references: str = 'https://capec.mitre.org/data/definitions/62.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsCSRFToken is False or target.controls.verifySessionIdentifiers is False

class AC22(Threat):
    """Credentials Aging."""

    DEPRECATED: ClassVar[str] = 'AC22 was replaced by AC23 and AC24. Forcing short lived credentials by rotating the credentials regularly is no longer recommended. It better to go for long living strong credentials, which can be easily replaced, when a disclosure has happend.'

    id: str = 'AC22'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Credentials Aging'
    details: str = 'If no mechanism is in place for managing credentials (passwords and certificates) aging, users will have no incentive to update passwords or rotate certificates in a timely manner. Allowing password aging to occur unchecked or long certificate expiration dates can result in the possibility of diminished password integrity.'
    likelihood: str = "Medium"
    severity: str = "High"
    mitigations: str = 'All passwords and other credentials should have a relatively short expiration date with a possibility to be revoked immediately under special circumstances.'
    references: str = 'https://cwe.mitre.org/data/definitions/262.html, https://cwe.mitre.org/data/definitions/263.html, https://cwe.mitre.org/data/definitions/798.html'

    def _check_condition(self, target) -> bool:
        return any(d.isCredentials for d in target.data) and target.sink.inScope and any(d.credentialsLife in (Lifetime.UNKNOWN, Lifetime.LONG, Lifetime.MANUAL, Lifetime.HARDCODED) for d in target.data)

class AC23(Threat):
    """Credentials Disclosure."""

    id: str = 'AC23'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Credentials Disclosure'
    details: str = 'If credentials (passwords or certificates) have a long lifetime their disclosure can have severe consequences, if the credentials cannot quickly be revoked and/or rotated.'
    likelihood: str = "Medium"
    severity: str = "High"
    mitigations: str = 'Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.'
    references: str = 'https://pages.nist.gov/800-63-3/sp800-63b.html#sec6'

    def _check_condition(self, target) -> bool:
        return any(d.isCredentials for d in target.data) and target.sink.inScope and any(d.credentialsLife in (Lifetime.UNKNOWN, Lifetime.LONG, Lifetime.MANUAL) for d in target.data)

class AC24(Threat):
    """Use of hardcoded credentials."""

    id: str = 'AC24'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Use of hardcoded credentials'
    details: str = 'Hardcoded credentials (password or certificates) cannot be changed and if these credentials are dislcosed they can be used by attackers to bypass the authentication mechanism.'
    likelihood: str = "High"
    severity: str = "Very high"
    mitigations: str = 'Avoid hardcoded credentials. If you have to use hardcoded credentials make is possible to change the credentials or to deactivate them. A typical design is to use a "first login"-mode which forces the user to create new credentials, on the first login. If the credentials cannot be changed the sole actions in prodcution for the defender is to deactivate/remove the effected product.'
    references: str = 'https://cwe.mitre.org/data/definitions/798.html, https://cwe.mitre.org/data/definitions/259.html, https://cwe.mitre.org/data/definitions/321.html'

    def _check_condition(self, target) -> bool:
        return any(d.isCredentials for d in target.data) and target.sink.inScope and any(d.credentialsLife == Lifetime.HARDCODED for d in target.data)
