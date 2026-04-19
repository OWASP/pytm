"""Data store threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class DS01(Threat):
    """Excavation."""

    id: str = 'DS01'
    target: tuple = (pytm.Server,)
    description: str = 'Excavation'
    details: str = 'An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes. This is achieved by exploring the target via ordinary interactions for the purpose of gathering intelligence about the target, or by sending data that is syntactically invalid or non-standard in an attempt to produce a response that contains the desired data. As a result of these interactions, the adversary is able to obtain information from the target that aids the attacker in making inferences about its security, configuration, or potential vulnerabilities. Examplar exchanges with the target may trigger unhandled exceptions or verbose error messages that reveal information like stack traces, configuration information, path information, or database design. This type of attack also includes the manipulation of query strings in a URI to produce invalid SQL queries, or by trying alternative path values in the hope that the server will return useful information.'
    likelihood: str = "High"
    severity: str = "Medium"
    prerequisites: str = 'An adversary requires some way of interacting with the system.'
    mitigations: str = "Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality."
    example: str = "The adversary may collect this information through a variety of methods including active querying as well as passive observation. By exploiting weaknesses in the design or configuration of the target and its communications, an adversary is able to get the target to reveal more information than intended. Information retrieved may aid the adversary in making inferences about potential weaknesses, vulnerabilities, or techniques that assist the adversary's objectives. This information may include details regarding the configuration or capabilities of the target, clues as to the timing or nature of activities, or otherwise sensitive information. Often this sort of attack is undertaken in preparation for some other type of attack, although the collection of information by itself may in some cases be the end goal of the adversary."
    references: str = 'https://capec.mitre.org/data/definitions/116.html, http://cwe.mitre.org/data/definitions/200.html'

    def _check_condition(self, target) -> bool:
        return (target.controls.sanitizesInput is False or target.controls.validatesInput is False) or target.controls.encodesOutput is False

class DS02(Threat):
    """Try All Common Switches."""

    id: str = 'DS02'
    target: tuple = (pytm.Lambda, pytm.Process)
    description: str = 'Try All Common Switches'
    details: str = 'An attacker attempts to invoke all common switches and options in the target application for the purpose of discovering weaknesses in the target. For example, in some applications, adding a --debug switch causes debugging information to be displayed, which can sometimes reveal sensitive processing or configuration information to an attacker. This attack differs from other forms of API abuse in that the attacker is blindly attempting to invoke options in the hope that one of them will work rather than specifically targeting a known option. Nonetheless, even if the attacker is familiar with the published options of a targeted application this attack method may still be fruitful as it might discover unpublicized functionality.'
    severity: str = "Medium"
    prerequisites: str = 'The attacker must be able to control the options or switches sent to the target.'
    mitigations: str = 'Design: Minimize switch and option functionality to only that necessary for correct function of the command. Implementation: Remove all debug and testing options from production code.'
    example: str = 'Adversary is able to exploit the debug switch to discover unpublicized functionality.'
    references: str = 'https://capec.mitre.org/data/definitions/133.html, http://cwe.mitre.org/data/definitions/912.html'

    def _check_condition(self, target) -> bool:
        return target.environment == 'Production'

class DS03(Threat):
    """Footprinting."""

    id: str = 'DS03'
    target: tuple = (pytm.Server,)
    description: str = 'Footprinting'
    details: str = 'An adversary engages in probing and exploration activities to identify constituents and properties of the target. Footprinting is a general term to describe a variety of information gathering techniques, often used by attackers in preparation for some attack. It consists of using tools to learn as much as possible about the composition, configuration, and security mechanisms of the targeted application, system or network. Information that might be collected during a footprinting effort could include open ports, applications and their versions, network topology, and similar information. While footprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.'
    likelihood: str = "High"
    severity: str = "Very low"
    prerequisites: str = 'An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted. However, some configuration choices may limit the useful information that can be collected during a footprinting attack.'
    mitigations: str = "Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents."
    example: str = "In this example let us look at the website http://www.example.com to get much information we can about Alice. From the website, we find that Alice also runs foobar.org. We type in www example.com into the prompt of the Name Lookup window in a tool, and our result is this IP address: 192.173.28.130 We type the domain into the Name Lookup prompt and we are given the same IP. We can safely say that example and foobar.org are hosted on the same box. But if we were to do a reverse name lookup on the IP, which domain will come up? www.example.com or foobar.org? Neither, the result is nijasvspirates.org. So nijasvspirates.org is the name of the box hosting 31337squirrel.org and foobar.org. So now that we have the IP, let's check to see if nijasvspirates is awake. We type the IP into the prompt in the Ping window. We'll set the interval between packets to 1 millisecond. We'll set the number of seconds to wait until a ping times out to 5. We'll set the ping size to 500 bytes and we'll send ten pings. Ten packets sent and ten packets received. nijasvspirates.org returned a message to my computer within an average of 0.35 seconds for every packet sent. nijasvspirates is alive. We open the Whois window and type nijasvspirates.org into the Query prompt, and whois.networksolutions.com into the Server prompt. This means we'll be asking Network Solutions to tell us everything they know about nijasvspirates.org. The result is this laundry list of info: Registrant: FooBar (nijasvspirates -DOM) p.o.box 11111 SLC, UT 84151 US Domain Name: nijasvspirates.ORG Administrative Contact, Billing Contact: Smith, John jsmith@anonymous.net FooBar p.o.box 11111 SLC, UT 84151 555-555-6103 Technical Contact: Johnson, Ken kj@fierymonkey.org fierymonkey p.o.box 11111 SLC, UT 84151 555-555-3849 Record last updated on 17-Aug-2001. Record expires on 11-Aug-2002. Record created on 11-Aug-2000. Database last updated on 12-Dec-2001 04:06:00 EST. Domain servers in listed order: NS1. fierymonkey.ORG 192.173.28.130 NS2. fierymonkey.ORG 64.192.168.80 A corner stone of footprinting is Port Scanning. Let's port scan nijasvspirates.org and see what kind of services are running on that box. We type in the nijasvspirates IP into the Host prompt of the Port Scan window. We'll start searching from port number 1, and we'll stop at the default Sub7 port, 27374. Our results are: 21 TCP ftp 22 TCP ssh SSH-1.99-OpenSSH_2.30 25 TCP smtp 53 TCP domain 80 TCP www 110 TCP pop3 111 TCP sunrpc 113 TCP ident Just by this we know that Alice is running a website and email, using POP3, SUNRPC (SUN Remote Procedure Call), and ident."
    references: str = 'https://capec.mitre.org/data/definitions/169.html, http://cwe.mitre.org/data/definitions/200.html'

    def _check_condition(self, target) -> bool:
        return target.controls.isHardened is False

class DS04(Threat):
    """XSS Targeting Error Pages."""

    id: str = 'DS04'
    target: tuple = (pytm.Server,)
    description: str = 'XSS Targeting Error Pages'
    details: str = "An adversary distributes a link (or possibly some other query structure) with a request to a third party web server that is malformed and also contains a block of exploit code in order to have the exploit become live code in the resulting error page. When the third party web server receives the crafted request and notes the error it then creates an error message that echoes the malformed message, including the exploit. Doing this converts the exploit portion of the message into to valid language elements that are executed by the viewing browser. When a victim executes the query provided by the attacker the infected error message error message is returned including the exploit code which then runs in the victim's browser. XSS can result in execution of code as well as data leakage (e.g. session cookies can be sent to the attacker). This type of attack is especially dangerous since the exploit appears to come from the third party web server, who the victim may trust and hence be more vulnerable to deception."
    severity: str = "Medium"
    prerequisites: str = 'A third party web server which fails to adequately sanitize messages sent in error pages.The victim must be made to execute a query crafted by the attacker which results in the infected error report.'
    mitigations: str = 'Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.'
    example: str = 'A third party web server fails to adequately sanitize messages sent in error pages. Adversary takes advantage of the data displayed in the error message.'
    references: str = 'https://capec.mitre.org/data/definitions/198.html, http://cwe.mitre.org/data/definitions/81.html'

    def _check_condition(self, target) -> bool:
        return target.controls.encodesOutput is False or target.controls.validatesInput is False or target.controls.sanitizesInput is False

class DS05(Threat):
    """Lifting Sensitive Data Embedded in Cache."""

    id: str = 'DS05'
    target: tuple = (pytm.Server,)
    description: str = 'Lifting Sensitive Data Embedded in Cache'
    details: str = "An attacker examines a target application's cache for sensitive information. Many applications that communicate with remote entities or which perform intensive calculations utilize caches to improve efficiency. However, if the application computes or receives sensitive information and the cache is not appropriately protected, an attacker can browse the cache and retrieve this information. This can result in the disclosure of sensitive information."
    severity: str = "Medium"
    prerequisites: str = 'The target application must store sensitive information in a cache.The cache must be inadequately protected against attacker access.'
    mitigations: str = "Remove potentially sensitive information from cache that is not necessary for the application's functionality."
    example: str = 'An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes. This is achieved by exploring the target via ordinary interactions for the purpose of gathering intelligence about the target, or by sending data that is syntactically invalid or non-standard in an attempt to produce a response that contains the desired data. As a result of these interactions, the adversary is able to obtain information from the target that aids the attacker in making inferences about its security, configuration, or potential vulnerabilities.'
    references: str = 'https://capec.mitre.org/data/definitions/204.html, http://cwe.mitre.org/data/definitions/524.html, http://cwe.mitre.org/data/definitions/311.html'

    def _check_condition(self, target) -> bool:
        return target.usesCache is True

class DS06(Threat):
    """Data Leak."""

    id: str = 'DS06'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Data Leak'
    details: str = 'An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.'
    likelihood: str = "High"
    severity: str = "Very high"
    mitigations: str = 'All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.'
    example: str = 'An application, which connects to a database without TLS, performs a database query in which it compares the password to a stored hash, instead of fetching the hash and comparing it locally.'
    references: str = 'https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html'

    def _check_condition(self, target) -> bool:
        return target.hasDataLeaks()
