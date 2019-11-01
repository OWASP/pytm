import sys
sys.path.append("..")
import unittest
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, Process, Threat, ExternalEntity
import json
import os
from os.path import dirname

with open(os.path.abspath(os.path.join(dirname(__file__), '..')) + "/threatlib/threats.json", "r") as threat_file:
    threats_json = json.load(threat_file)
    
class Testpytm(unittest.TestCase):
    
#Test for all the threats in threats.py - test Threat.apply() function
    def test_INP01(self):
        lambda1 = Lambda('mylambda')
        process1 = Process('myprocess')
        lambda1.usesEnvironmentVariables = True
        lambda1.sanitizesInput = False
        lambda1.checksInputBounds = False
        process1.usesEnvironmentVariables = True 
        process1.sanitizesInput = False 
        process1.checksInputBounds = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP01"))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(process1))

    def test_INP02(self):
        process1 = Process('myprocess')
        process1.checksInputBounds = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP02"))
        self.assertTrue(ThreatObj.apply(process1))

    def test_INP03(self):
        web = Server('Web')
        web.sanitizesInput = False
        web.encodesOutput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP03"))
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
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "CR01"))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_INP04(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.validatesHeaders = False
        web.protocol = 'HTTP'
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP04"))
        self.assertTrue(ThreatObj.apply(web))

    def test_CR02(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = 'HTTP'
        web.sanitizesInput = False
        web.validatesInput = False
        web.usesSessionTokens = True
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.sanitizesInput = False
        user_to_web.validatesInput = False
        user_to_web.usesSessionTokens = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "CR02"))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_INP05(self):
        web = Server("Web Server")
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP05"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP06(self):
        web = Server("Web Server")
        web.protocol = 'SOAP'
        web.sanitizesInput = False
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP06"))
        self.assertTrue(ThreatObj.apply(web))

    def test_SC01(self):
        process1 = Process("Process1")
        process1.implementsNonce = False
        process1.data = 'JSON'
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "SC01"))
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
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "LB01"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_AA01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesSource = False
        web.authenticatesSource = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AA01"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_DS01(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DS01"))
        self.assertTrue(ThreatObj.apply(web))

    def test_DE01(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.isEncrypted = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DE01")) 
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DE02(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        web.validatesInput = False
        web.sanitizesInput = False
        process1.validatesInput = False
        process1.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DE02"))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(process1))

    def test_API01(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        lambda1.implementsAPI = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "API01"))
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
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC01"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_INP07(self):
        process1 = Process("Process1")
        process1.usesSecureFunctions = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP07"))
        self.assertTrue(ThreatObj.apply(process1))

    def test_AC02(self):
        db = Datastore("DB")
        db.isShared = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC02"))
        self.assertTrue(ThreatObj.apply(db))

    def test_DO01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.handlesResourceConsumption = False
        process1.isResilient = False
        web.handlesResourceConsumption = False
        web.isResilient = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DO01"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_HA01(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "HA01"))
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
        lambda1.authorizesSource = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC03"))
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
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DO02"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_DS02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.environment = 'Production'
        lambda1.environment = 'Production'
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DS02"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_INP08(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP08"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP09(self):
        web = Server("Web Server") 
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP09"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP10(self):
        web = Server("Web Server") 
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP10"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP11(self):
        web = Server("Web Server") 
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP11"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP12(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.checksInputBounds = False
        process1.validatesInput = False
        lambda1.checksInputBounds = False
        lambda1.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP12"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_AC04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        user_to_web.authorizesSource = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC04"))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DO03(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DO03"))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_AC05(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.providesIntegrity = False
        process1.authorizesSource = False
        web.providesIntegrity = False
        web.authorizesSource = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC05"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP13(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.validatesInput = False
        lambda1.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP13"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_INP14(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.validatesInput = False
        lambda1.validatesInput = False
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP14"))
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
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DE03"))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_CR03(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.implementsAuthenticationScheme = False
        web.implementsAuthenticationScheme = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "CR03"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(web))

    def test_API02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        process1.validatesInput = False
        lambda1.implementsAPI = True
        lambda1.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "API02"))
        self.assertTrue(ThreatObj.apply(process1))
        self.assertTrue(ThreatObj.apply(lambda1))

    def test_HA02(self):
        EE = ExternalEntity("EE")
        EE.hasPhysicalAccess = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "HA02"))
        self.assertTrue(ThreatObj.apply(EE))

    def test_DS03(self):
        web = Server("Web Server")
        web.isHardened = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DS03"))
        self.assertTrue(ThreatObj.apply(web))

    def test_AC06(self):
        web = Server("Web Server")
        web.isHardened = False
        web.hasAccessControl = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC06"))
        self.assertTrue(ThreatObj.apply(web))

    def test_HA03(self):
        web = Server("Web Server")
        web.validatesHeaders = False
        web.encodesOutput = False
        web.isHardened = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "HA03"))
        self.assertTrue(ThreatObj.apply(web))

    def test_SC02(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "SC02"))
        self.assertTrue(ThreatObj.apply(web))

    def test_AC07(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC07"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP15(self):
        web = Server("Web Server")
        web.protocol = 'IMAP'
        web.protocol = 'SMTP'
        web.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP15"))
        self.assertTrue(ThreatObj.apply(web))

    def test_HA04(self):
        EE = ExternalEntity("ee")
        EE.hasPhysicalAccess = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "HA04"))
        self.assertTrue(ThreatObj.apply(EE))

    def test_SC03(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        web.hasAccessControl = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "SC03"))
        self.assertTrue(ThreatObj.apply(web))

    def test_INP16(self):
        web = Server("Web Server")
        web.validatesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "INP16"))
        self.assertTrue(ThreatObj.apply(web))

    def test_AA02(self):
        web = Server("Web Server")
        process1 = Process("process")
        web.authenticatesSource = False
        process1.authenticatesSource = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AA02"))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(process1))

    def test_CR04(self):
        web = Server("Web Server")
        web.usesSessionTokens = True
        web.implementsNonce = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "CR04"))
        self.assertTrue(ThreatObj.apply(web))

    def test_DO04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML'
        user_to_web.handlesResources = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DO04"))
        self.assertTrue(ThreatObj.apply(user_to_web))

    def test_DS04(self):
        web = Server("Web Server")
        web.encodesOutput = False
        web.validatesInput = False
        web.sanitizesInput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DS04"))
        self.assertTrue(ThreatObj.apply(web))

    def test_SC04(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "SC04"))
        self.assertTrue(ThreatObj.apply(web))

    def test_CR05(self):
        web = Server("Web Server")
        db = Datastore("db")
        web.usesEncryptionAlgorithm != 'RSA'
        web.usesEncryptionAlgorithm != 'AES'
        db.usesEncryptionAlgorithm != 'RSA'
        db.usesEncryptionAlgorithm != 'AES'
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "CR05"))
        self.assertTrue(ThreatObj.apply(web))
        self.assertTrue(ThreatObj.apply(db))

    def test_AC08(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "AC08"))
        self.assertTrue(ThreatObj.apply(web))

    def test_DS05(self):
        web = Server("Web Server")
        web.usesCache = True
        ThreatObj = Threat(next(item for item in threats_json if item["SID"] == "DS05"))
        self.assertTrue(ThreatObj.apply(web))

if __name__ == '__main__':
    unittest.main()   
