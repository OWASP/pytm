import sys
sys.path.append("..")
import unittest
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, Process, Threat, ExternalEntity

class Testpytm(unittest.TestCase):

#Test for all the threats in threats.py - test Threat.apply() function

    def test_IN01(self):
        lambda1 = Lambda('mylambda')
        process1 = Process('myprocess')
        lambda1.usesEnvironmentVariables = True
        lambda1.sanitizesInput = False
        lambda1.checksInputBounds = False
        process1.usesEnvironmentVariables = True 
        process1.sanitizesInput = False 
        process1.checksInputBounds = False
        ThreatObj = Threat('IN01', "Buffer Overflow via Environment Variables", 'target.usesEnvironmentVariables is True and target.sanitizesInput is False and target.checksInputBounds is False', (Lambda,Process),  "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(process1))

    def test_IN02(self):
        process1 = Process('myprocess')
        process1.checksInputBounds = False
        ThreatObj = Threat('IN02', "Overflow Buffers", "target.checksInputBounds is False", Process, "details", "High", "mitigations", "example" )
        self.assertTrue(ThreatObj.apply(process1))

    def test_IN03(self):
        web = Server('Web')
        web.sanitizesInput = False
        web.encodesOutput = False
        ThreatObj = Threat('IN03', "Server Side Include (SSI) Injection", 'target.sanitizesInput is False or target.encodesOutput is False', Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_CR01(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = 'HTTP'
        web.usesVPN = False
        web.usesSessionTokens = True
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.usesVPN = False
        user_to_web.usesSessionTokens = True
        ThreatObj = Threat('CR01', "Session Sidejacking", "(target.protocol == 'HTTP' or target.usesVPN is False) and target.usesSessionTokens is True", (Dataflow, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_IN04(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.validatesHeaders = False
        web.protocol = 'HTTP'
        ThreatObj = Threat('IN04', "HTTP Request Splitting", "(target.validatesInput is False or target.validatesHeaders is False) and target.protocol =='HTTP'", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_CR02(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = 'HTTP'
        web.sanitizesInput = False
        web.encodesOutput = False
        web.usesSessionTokens = True
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.sanitizesInput = False
        user_to_web.encodesOutput = False
        user_to_web.usesSessionTokens = True
        ThreatObj = Threat('CR02', "Cross Site Tracing", "(target.protocol == 'HTTP' and target.usesSessionTokens is True) and (target.sanitizesInput is False or target.validatesInput is False)", (Dataflow, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_IN05(self):
        process1 = Process("Process1")
        process1.validatesInput = False
        ThreatObj = Threat('IN05', "Command Line Execution through SQL Injection", "target.validatesInput is False", Process, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))

    def test_IN06(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = 'SOAP'
        web.sanitizesInput = False
        web.validatesInput = False
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'SOAP'
        user_to_web.sanitizesInput = False
        user_to_web.validatesInput = False
        ThreatObj = Threat('IN06', "SQL Injection through SOAP Parameter Tampering", "target.protocol == 'SOAP' and (target.sanitizesInput is False or target.validatesInput is False)", (Dataflow, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_SC01(self):
        process1 = Process("Process1")
        process1.implementsNonce = False
        process1.data = 'JSON'
        ThreatObj = Threat("SC01", "JSON Hijacking (aka JavaScript Hijacking)", "target.implementsNonce is False and target.data =='JSON'", Process, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))

    def test_LB01(self):
        process1 = Process("Process1")
        process1.implementsAPI = True
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1 = Lambda("Lambda1")
        lambda1.implementsAPI = True
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        ThreatObj = Threat("LB01", "API Manipulation", "target.implementsAPI is True and (target.validatesInput is False or target.sanitizesInput is False)", (Process, Lambda), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_AA01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesSource = False
        web.authenticatesSource = False
        ThreatObj = Threat("AA01", "Authentication Abuse/ByPass", "target.authenticatesSource is False", (Server, Process), "details", "High", "mitigations", "example")
        result = ThreatObj.apply(process1)
        self.assertTrue(result)
        self.assertTrue(ThreatObj.apply(web))

    def test_DS01(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat("DS01", "Excavation", "(target.sanitizesInput is False or target.validatesInput is False) or target.encodesOutput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_DE01(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.isEncrypted = False
        ThreatObj = Threat("DE01", "Interception", "target.protocol == 'HTTP' or target.isEncrypted is False", Dataflow, "details", "High", "mitigations", "example")  
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DE02(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        web.validatesInput = False
        web.sanitizesInput = False
        process1.validatesInput = False
        process1.sanitizesInput = False
        ThreatObj = Threat("DE02", "Double Encoding", "target.validatesInput is False or target.sanitizesInput is False", (Server, Process), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(process1))

    def test_API01(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        lambda1.implementsAPI = True
        ThreatObj = Threat("API01", "Exploit Test APIs", "target.implementsAPI is True", (Process,Lambda), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_AC01(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        db = Datastore("DB")
        web.hasAccessControl = False
        web.authorizesSource = True
        process1.hasAccessControl = False
        process1.authorizesSource = False
        db.hasAccessControl = False
        db.authorizesSource = False
        ThreatObj = Threat("AC01", "Privilege Abuse", "target.hasAccessControl is False or target.authorizesSource is False", (Server, Process, Datastore), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_IN07(self):
        process1 = Process("Process1")
        process1.usesSecureFunctions = False
        ThreatObj = Threat("IN07", "Buffer Manipulation", "target.usesSecureFunctions is False", Process, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))

    def test_AC02(self):
        db = Datastore("DB")
        db.isShared = True
        ThreatObj = Threat("AC02", "Shared Data Manipulation", "target.isShared is True", Datastore, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(db))

    def test_DO01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.handlesResourceConsumption = False
        process1.isResilient = False
        web.handlesResourceConsumption = False
        web.isResilient = False
        ThreatObj = Threat("DO01", "Flooding", "target.handlesResourceConsumption is False or target.isResilient is False", (Process, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_HA01(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat("HA01", "Path Traversal", "target.validatesInput is False and target.sanitizesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_AC03(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.usesEnvironmentVariables = True
        process1.implementsAuthenticationScheme = False
        process1.validatesInput = False
        process1.authorizesSource = False
        lambda1.usesEnvironmentVariables = True
        lambda1.implementsAuthenticationScheme = False
        lambda1.validatesInput = False
        ThreatObj = Threat("AC03", "Subverting Environment Variable Values", "target.usesEnvironmentVariables is True and (target.authorizesSource is False or target.implementsAuthenticationScheme is False or target.validatesInput is False)", (Process, Lambda), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_DO02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        db = Datastore("DB")
        process1.handlesResourceConsumption = False
        lambda1.handlesResourceConsumption = False
        web.handlesResourceConsumption = False
        db.handlesResourceConsumption = False
        ThreatObj = Threat("DO02", "Excessive Allocation", "target.handlesResourceConsumption is False", (Process, Server, Datastore, Lambda), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_DS02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.environment = 'Production'
        lambda1.environment = 'Production'
        ThreatObj = Threat("DS02", "Try All Common Switches", "target.environment == 'Production'", (Lambda, Process), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_IN08(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat("IN08", "Format String Injection", "target.validatesInput is False or target.sanitizesInput is False", (Lambda, Process, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(web))

    def test_IN09(self):
        web = Server("Web Server") 
        web.validatesInput = False
        ThreatObj = Threat("IN09", "LDAP Injection", "target.validatesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_IN10(self):
        web = Server("Web Server") 
        web.validatesInput = False
        ThreatObj = Threat("IN10", "Parameter Injection", "target.validatesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_IN11(self):
        web = Server("Web Server") 
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat("IN11", "Relative Path Traversal", "target.validatesInput is False or target.sanitizesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_IN12(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.checksInputBounds = False
        process1.validatesInput = False
        lambda1.checksInputBounds = False
        lambda1.validatesInput = False
        ThreatObj = Threat("IN12", "Client-side Injection-induced Buffer Overflow", "target.checksInputBounds is False and target.validatesInput is False", (Lambda, Process), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_AC04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        user_to_web.authorizesSource = False
        ThreatObj = Threat("AC04", "XML Schema Poisoning", "target.data == 'XML' and target.authorizesSource is False", Dataflow, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DO03(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        ThreatObj = Threat("DO03", "XML Ping of the Death", "target.data == 'XML'", Dataflow, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_AC05(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.providesIntegrity = False
        process1.authorizesSource = False
        web.providesIntegrity = False
        web.authorizesSource = False
        ThreatObj = Threat("AC05", "Content Spoofing", "target.providesIntegrity is False or target.authorizesSource is False", (Process,Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_IN13(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.validatesInput = False
        lambda1.validatesInput = False
        ThreatObj = Threat("IN13", "Command Delimiters", "target.validatesInput is False", (Lambda, Process), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_IN14(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.validatesInput = False
        lambda1.validatesInput = False
        web.validatesInput = False
        ThreatObj = Threat("IN14", "Input Data Manipulation", "target.validatesInput is False", (Process, Lambda, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(web))

    def test_DE03(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.isEncrypted = False
        user_to_web.usesVPN = False
        ThreatObj = Threat("DE03", "Sniffing Attacks", "(target.protocol == 'HTTP' or target.isEncrypted is False) or target.usesVPN is False", Dataflow, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_CR03(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.implementsAuthenticationScheme = False
        web.implementsAuthenticationScheme = False
        ThreatObj = Threat("CR03", "Dictionary-based Password Attack", "target.implementsAuthenticationScheme is False", (Process, Server), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_API02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        process1.validatesInput = False
        lambda1.implementsAPI = True
        lambda1.validatesInput = False
        ThreatObj = Threat("API02", "Exploit Script-Based APIs", "target.implementsAPI is True and target.validatesInput is False", (Process, Lambda), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_HA02(self):
        EE = ExternalEntity("EE")
        EE.hasPhysicalAccess = True
        ThreatObj = Threat("HA02", "White Box Reverse Engineering", "target.hasPhysicalAccess is True", ExternalEntity, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(EE))

    def test_DS03(self):
        web = Server("Web Server")
        web.isHardened = False
        ThreatObj = Threat("DS03", "Footprinting", "target.isHardened is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_AC06(self):
        web = Server("Web Server")
        web.isHardened = False
        web.hasAccessControl = False
        ThreatObj = Threat("AC06", "Using Malicious Files", "target.isHardened is False or target.hasAccessControl is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_HA03(self):
        web = Server("Web Server")
        web.validatesHeaders = False
        web.encodesOutput = False
        web.isHardened = False
        ThreatObj = Threat("HA03", "Web Application Fingerprinting", "target.validatesHeaders is False or target.encodesOutput is False or target.isHardened is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_SC02(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat("SC02", "XSS Targeting Non-Script Elements", "target.validatesInput is False or target.encodesOutput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_AC07(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        ThreatObj = Threat("AC07", "Exploiting Incorrectly Configured Access Control Security Levels", "target.hasAccessControl is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_IN15(self):
        web = Server("Web Server")
        web.protocol = 'IMAP'
        web.protocol = 'SMTP'
        web.sanitizesInput = False
        ThreatObj = Threat("IN15", "IMAP/SMTP Command Injection", "(target.protocol == 'IMAP' or target.protocol == 'SMTP') and target.sanitizesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_HA04(self):
        EE = ExternalEntity("ee")
        EE.hasPhysicalAccess = True
        ThreatObj = Threat("HA04", "Reverse Engineering", "target.hasPhysicalAccess is True", ExternalEntity, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(EE))

    def test_SC03(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        web.hasAccessControl = False
        ThreatObj = Threat("SC03", "Embedding Scripts within Scripts", "target.validatesInput is False or target.sanitizesInput is False or target.hasAccessControl is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_IN16(self):
        web = Server("Web Server")
        web.validatesInput = False
        ThreatObj = Threat("IN16", "PHP Remote File Inclusion", "target.validatesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_AA02(self):
        web = Server("Web Server")
        process1 = Process("process")
        web.authenticatesSource = False
        process1.authenticatesSource = False
        ThreatObj = Threat("AA02", "Principal Spoof", "target.authenticatesSource is False", (Server, Process), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(process1))

    def test_CR04(self):
        web = Server("Web Server")
        web.usesSessionTokens = True
        web.implementsNonce = False
        ThreatObj = Threat("CR04", "Session Credential Falsification through Forging", "target.usesSessionTokens is True and target.implementsNonce is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_DO04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML'
        user_to_web.handlesResources = False
        ThreatObj = Threat("DO04", "XML Entity Expansion", "target.data == 'XML' and target.handlesResources is False", Dataflow, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DS04(self):
        web = Server("Web Server")
        web.encodesOutput = False
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat("DS04", "XSS Targeting Error Pages", "target.encodesOutput is False or target.validatesInput is False or target.sanitizesInput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_SC04(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat("SC04", "XSS Using Alternate Syntax", "target.sanitizesInput is False or target.validatesInput is False or target.encodesOutput is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_CR05(self):
        web = Server("Web Server")
        db = Datastore("db")
        web.usesEncryptionAlgorithm != 'RSA'
        web.usesEncryptionAlgorithm != 'AES'
        db.usesEncryptionAlgorithm != 'RSA'
        db.usesEncryptionAlgorithm != 'AES'
        ThreatObj = Threat("CR05", "Encryption Brute Forcing", "target.usesEncryptionAlgorithm != 'RSA' or target.usesEncryptionAlgorithm != 'AES'", (Server,Datastore), "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_AC08(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        ThreatObj = Threat("AC08", "Manipulate Registry Information", "target.hasAccessControl is False", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

    def test_DS05(self):
        web = Server("Web Server")
        web.usesCache = True
        ThreatObj = Threat("DS05", "Lifting Sensitive Data Embedded in Cache", "target.usesCache is True", Server, "details", "High", "mitigations", "example")
        self.assertTrue(ThreatObj.apply(web))

if __name__ == '__main__':
    unittest.main()   
