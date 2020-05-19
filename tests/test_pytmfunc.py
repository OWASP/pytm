import sys
sys.path.append("..")

import json
import os
import random
import re
import unittest
from contextlib import contextmanager
from os.path import dirname
from io import StringIO

from pytm import (TM, Action, Actor, Boundary, Dataflow, Datastore, ExternalEntity,
                  Lambda, Process, Server, Threat)


with open(os.path.abspath(os.path.join(dirname(__file__), '..')) + "/pytm/threatlib/threats.json", "r") as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestTM(unittest.TestCase):

    def test_seq(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, 'seq.plantuml')) as x:
            expected = x.read().strip()

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        tm.check()
        with captured_output() as (out, err):
            tm.seq()

        output = out.getvalue().strip()
        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_seq_unused(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, 'seq_unused.plantuml')) as x:
            expected = x.read().strip()

        TM.reset()
        tm = TM("my test tm", description="aaa", ignoreUnused=True)
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)
        Lambda("Unused Lambda")

        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        tm.check()
        with captured_output() as (out, err):
            tm.seq()

        output = out.getvalue().strip()
        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, 'dfd.dot')) as x:
            expected = x.read().strip()

        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        Dataflow(user, web, "User enters comments (*)")
        Dataflow(web, db, "Insert query with comments")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        tm.check()
        with captured_output() as (out, err):
            tm.dfd()

        output = out.getvalue().strip()
        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd_duplicates_ignore(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, 'dfd.dot')) as x:
            expected = x.read().strip()

        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa", onDuplicates=Action.IGNORE)
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        Dataflow(user, web, "User enters comments (*)")
        Dataflow(user, web, "User views comments")
        Dataflow(web, db, "Insert query with comments")
        Dataflow(web, db, "Select query")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        tm.check()
        with captured_output() as (out, err):
            tm.dfd()

        output = out.getvalue().strip()
        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd_duplicates_raise(self):
        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa", onDuplicates=Action.RESTRICT)
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        Dataflow(user, web, "User enters comments (*)")
        Dataflow(user, web, "User views comments")
        Dataflow(web, db, "Insert query with comments")
        Dataflow(web, db, "Select query")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        e = re.escape("Duplicate Dataflow found between Actor(User) and Server(Web Server): Dataflow(User enters comments (*)) is same as Dataflow(User views comments)")
        with self.assertRaisesRegex(ValueError, e):
            tm.check()

    def test_resolve(self):
        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet, inScope=False)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        req = Dataflow(user, web, "User enters comments (*)")
        query = Dataflow(web, db, "Insert query with comments")
        results = Dataflow(db, web, "Retrieve comments")
        resp = Dataflow(web, user, "Show comments (*)")

        TM._BagOfThreats = [
            Threat(SID=klass, target=klass)
            for klass in ["Actor", "Server", "Datastore", "Dataflow"]
        ]
        tm.resolve()

        self.maxDiff = None
        self.assertListEqual([f.id for f in tm.findings], ['Server', 'Datastore', 'Dataflow', 'Dataflow', 'Dataflow', 'Dataflow'])
        self.assertListEqual([f.id for f in user.findings], [])
        self.assertListEqual([f.id for f in web.findings], ["Server"])
        self.assertListEqual([f.id for f in db.findings], ["Datastore"])
        self.assertListEqual([f.id for f in req.findings], ["Dataflow"])
        self.assertListEqual([f.id for f in query.findings], ["Dataflow"])
        self.assertListEqual([f.id for f in results.findings], ["Dataflow"])
        self.assertListEqual([f.id for f in resp.findings], ["Dataflow"])


class Testpytm(unittest.TestCase):
    # Test for all the threats in threats.py - test Threat.apply() function

    def test_INP01(self):
        lambda1 = Lambda('mylambda')
        process1 = Process('myprocess')
        lambda1.usesEnvironmentVariables = True
        lambda1.sanitizesInput = False
        lambda1.checksInputBounds = False
        process1.usesEnvironmentVariables = True 
        process1.sanitizesInput = False 
        process1.checksInputBounds = False
        threat = threats["INP01"]
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(process1))

    def test_INP02(self):
        process1 = Process('myprocess')
        process1.checksInputBounds = False
        threat = threats["INP02"]
        self.assertTrue(threat.apply(process1))

    def test_INP03(self):
        web = Server('Web')
        web.sanitizesInput = False
        web.encodesOutput = False
        threat = threats["INP03"]
        self.assertTrue(threat.apply(web))

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
        threat = threats["CR01"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(user_to_web))

    def test_INP04(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.validatesHeaders = False
        web.protocol = 'HTTP'
        threat = threats["INP04"]
        self.assertTrue(threat.apply(web))

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
        threat = threats["CR02"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(user_to_web))

    def test_INP05(self):
        web = Server("Web Server")
        web.validatesInput = False
        threat = threats["INP05"]
        self.assertTrue(threat.apply(web))

    def test_INP06(self):
        web = Server("Web Server")
        web.protocol = 'SOAP'
        web.sanitizesInput = False
        web.validatesInput = False
        threat = threats["INP06"]
        self.assertTrue(threat.apply(web))

    def test_SC01(self):
        process1 = Process("Process1")
        process1.implementsNonce = False
        process1.data = 'JSON'
        threat = threats["SC01"]
        self.assertTrue(threat.apply(process1))

    def test_LB01(self):
        process1 = Process("Process1")
        process1.implementsAPI = True
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1 = Lambda("Lambda1")
        lambda1.implementsAPI = True
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        threat = threats["LB01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_AA01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesSource = False
        web.authenticatesSource = False
        threat = threats["AA01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_DS01(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        threat = threats["DS01"]
        self.assertTrue(threat.apply(web))

    def test_DE01(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.isEncrypted = False
        threat = threats["DE01"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DE02(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        web.validatesInput = False
        web.sanitizesInput = False
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["DE02"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(process1))

    def test_API01(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        lambda1.implementsAPI = True
        threat = threats["API01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

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
        threat = threats["AC01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_INP07(self):
        process1 = Process("Process1")
        process1.usesSecureFunctions = False
        threat = threats["INP07"]
        self.assertTrue(threat.apply(process1))

    def test_AC02(self):
        db = Datastore("DB")
        db.isShared = True
        threat = threats["AC02"]
        self.assertTrue(threat.apply(db))

    def test_DO01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.handlesResourceConsumption = False
        process1.isResilient = False
        web.handlesResourceConsumption = True
        threat = threats["DO01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_HA01(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        threat = threats["HA01"]
        self.assertTrue(threat.apply(web))

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
        threat = threats["AC03"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_DO02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        db = Datastore("DB")
        process1.handlesResourceConsumption = False
        lambda1.handlesResourceConsumption = False
        web.handlesResourceConsumption = False
        db.handlesResourceConsumption = False
        threat = threats["DO02"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_DS02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.environment = 'Production'
        lambda1.environment = 'Production'
        threat = threats["DS02"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

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
        threat = threats["INP08"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))

    def test_INP09(self):
        web = Server("Web Server") 
        web.validatesInput = False
        threat = threats["INP09"]
        self.assertTrue(threat.apply(web))

    def test_INP10(self):
        web = Server("Web Server") 
        web.validatesInput = False
        threat = threats["INP10"]
        self.assertTrue(threat.apply(web))

    def test_INP11(self):
        web = Server("Web Server") 
        web.validatesInput = False
        web.sanitizesInput = False
        threat = threats["INP11"]
        self.assertTrue(threat.apply(web))

    def test_INP12(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.checksInputBounds = False
        process1.validatesInput = False
        lambda1.checksInputBounds = False
        lambda1.validatesInput = False
        threat = threats["INP12"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_AC04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        user_to_web.authorizesSource = False
        threat = threats["AC04"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DO03(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML' 
        threat = threats["DO03"]
        self.assertTrue(threat.apply(user_to_web))

    def test_AC05(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.providesIntegrity = False
        process1.authorizesSource = False
        web.providesIntegrity = False
        web.authorizesSource = False
        threat = threats["AC05"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_INP13(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.validatesInput = False
        lambda1.validatesInput = False
        threat = threats["INP13"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP14(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.validatesInput = False
        lambda1.validatesInput = False
        web.validatesInput = False
        threat = threats["INP14"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))

    def test_DE03(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.isEncrypted = False
        user_to_web.usesVPN = False
        threat = threats["DE03"]
        self.assertTrue(threat.apply(user_to_web))

    def test_CR03(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.implementsAuthenticationScheme = False
        web.implementsAuthenticationScheme = False
        threat = threats["CR03"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_API02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        process1.validatesInput = False
        lambda1.implementsAPI = True
        lambda1.validatesInput = False
        threat = threats["API02"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_HA02(self):
        EE = ExternalEntity("EE")
        EE.hasPhysicalAccess = True
        threat = threats["HA02"]
        self.assertTrue(threat.apply(EE))

    def test_DS03(self):
        web = Server("Web Server")
        web.isHardened = False
        threat = threats["DS03"]
        self.assertTrue(threat.apply(web))

    def test_AC06(self):
        web = Server("Web Server")
        web.isHardened = False
        web.hasAccessControl = False
        threat = threats["AC06"]
        self.assertTrue(threat.apply(web))

    def test_HA03(self):
        web = Server("Web Server")
        web.validatesHeaders = False
        web.encodesOutput = False
        web.isHardened = False
        threat = threats["HA03"]
        self.assertTrue(threat.apply(web))

    def test_SC02(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.encodesOutput = False
        threat = threats["SC02"]
        self.assertTrue(threat.apply(web))

    def test_AC07(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        threat = threats["AC07"]
        self.assertTrue(threat.apply(web))

    def test_INP15(self):
        web = Server("Web Server")
        web.protocol = 'IMAP'
        web.sanitizesInput = False
        threat = threats["INP15"]
        self.assertTrue(threat.apply(web))

    def test_HA04(self):
        EE = ExternalEntity("ee")
        EE.hasPhysicalAccess = True
        threat = threats["HA04"]
        self.assertTrue(threat.apply(EE))

    def test_SC03(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        web.hasAccessControl = False
        threat = threats["SC03"]
        self.assertTrue(threat.apply(web))

    def test_INP16(self):
        web = Server("Web Server")
        web.validatesInput = False
        threat = threats["INP16"]
        self.assertTrue(threat.apply(web))

    def test_AA02(self):
        web = Server("Web Server")
        process1 = Process("process")
        web.authenticatesSource = False
        process1.authenticatesSource = False
        threat = threats["AA02"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(process1))

    def test_CR04(self):
        web = Server("Web Server")
        web.usesSessionTokens = True
        web.implementsNonce = False
        threat = threats["CR04"]
        self.assertTrue(threat.apply(web))

    def test_DO04(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = 'XML'
        user_to_web.handlesResources = False
        threat = threats["DO04"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DS04(self):
        web = Server("Web Server")
        web.encodesOutput = False
        web.validatesInput = False
        web.sanitizesInput = False
        threat = threats["DS04"]
        self.assertTrue(threat.apply(web))

    def test_SC04(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.validatesInput = False
        web.encodesOutput = False
        threat = threats["SC04"]
        self.assertTrue(threat.apply(web))

    def test_CR05(self):
        web = Server("Web Server")
        db = Datastore("db")
        web.usesEncryptionAlgorithm != 'RSA'
        web.usesEncryptionAlgorithm != 'AES'
        db.usesEncryptionAlgorithm != 'RSA'
        db.usesEncryptionAlgorithm != 'AES'
        threat = threats["CR05"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_AC08(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        threat = threats["AC08"]
        self.assertTrue(threat.apply(web))

    def test_DS05(self):
        web = Server("Web Server")
        web.usesCache = True
        threat = threats["DS05"]
        self.assertTrue(threat.apply(web))

    def test_SC05(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.usesCodeSigning = False
        threat = threats["SC05"]
        self.assertTrue(threat.apply(web))

    def test_INP17(self):
        web = Server("Web Server")
        web.validatesContentType = False
        web.invokesScriptFilters = False
        threat = threats["INP17"]
        self.assertTrue(threat.apply(web))

    def test_AA03(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.authenticatesSource = False
        web.usesStrongSessionIdentifiers = False
        threat = threats["AA03"]
        self.assertTrue(threat.apply(web))

    def test_AC09(self):
        web = Server("Web Server")
        web.hasAccessControl = False
        web.authorizesSource = False
        threat = threats["AC09"]
        self.assertTrue(threat.apply(web))

    def test_INP18(self):
        web = Server("Web Server")
        web.sanitizesInput = False
        web.encodesOutput = False
        threat = threats["INP18"]
        self.assertTrue(threat.apply(web))

    def test_CR06(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.usesVPN = False
        user_to_web.implementsAuthenticationScheme = False
        user_to_web.authorizesSource = False
        threat = threats["CR06"]
        self.assertTrue(threat.apply(user_to_web))

    def test_AC10(self):
        web = Server("Web Server")
        web.usesLatestTLSversion = False
        web.implementsAuthenticationScheme = False
        web.authorizesSource = False
        threat = threats["AC10"]
        self.assertTrue(threat.apply(web))

    def test_CR07(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.data = 'XML'
        threat = threats["CR07"]
        self.assertTrue(threat.apply(user_to_web))

    def test_AA04(self):
        web = Server("Web Server")
        web.implementsServerSideValidation = False
        web.providesIntegrity = False
        web.authorizesSource = False
        threat = threats["AA04"]
        self.assertTrue(threat.apply(web))

    def test_CR08(self):
        user = Actor("User")
        web = Server("Web Server")  
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = 'HTTP'
        user_to_web.usesLatestTLSversion = False
        threat = threats["CR08"]
        self.assertTrue(threat.apply(user_to_web))

    def test_INP19(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP19"]
        self.assertTrue(threat.apply(web))

    def test_INP20(self):
        process1 = Process("process")
        process1.disablesiFrames = False
        threat = threats["INP20"]
        self.assertTrue(threat.apply(process1))

    def test_AC11(self):
        web = Server("Web Server")
        web.usesStrongSessionIdentifiers = False
        threat = threats["AC11"]
        self.assertTrue(threat.apply(web))

    def test_INP21(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP21"]
        self.assertTrue(threat.apply(web))

    def test_INP22(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP22"]
        self.assertTrue(threat.apply(web))

    def test_INP23(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.sanitizesInput = False
        process1.validatesInput = False
        threat = threats["INP23"]
        self.assertTrue(threat.apply(process1))

    def test_DO05(self):
        web = Server("Web Server")
        web.validatesInput = False
        web.sanitizesInput = False
        web.usesXMLParser = True
        threat = threats["DO05"]
        self.assertTrue(threat.apply(web))

    def test_AC12(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.implementsPOLP = False
        threat = threats["AC12"]
        self.assertTrue(threat.apply(process1))

    def test_AC13(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.implementsPOLP = False
        threat = threats["AC13"]
        self.assertTrue(threat.apply(process1))

    def test_AC14(self):
        process1 = Process("Process")
        process1.implementsPOLP = False
        process1.usesEnvironmentVariables = False
        process1.validatesInput = False
        threat = threats["AC14"]
        self.assertTrue(threat.apply(process1))

    def test_INP24(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.checksInputBounds = False
        process1.validatesInput = False
        lambda1.checksInputBounds = False
        lambda1.validatesInput = False
        threat = threats["INP24"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP25(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        threat = threats["INP25"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP26(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.validatesInput = False
        process1.sanitizesInput = False
        lambda1.validatesInput = False
        lambda1.sanitizesInput = False
        threat = threats["INP26"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP27(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP27"]
        self.assertTrue(threat.apply(process1))

    def test_INP28(self):
        web = Server("Web Server")
        process1 = Process("Process")
        web.validatesInput = False
        web.sanitizesInput = False
        web.encodesOutput = False
        process1.validatesInput = False
        process1.sanitizesInput = False
        process1.encodesOutput = False
        threat = threats["INP28"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_INP29(self):
        web = Server("Web Server")
        process1 = Process("Process")
        web.validatesInput = False
        web.sanitizesInput = False
        web.encodesOutput = False
        process1.validatesInput = False
        process1.sanitizesInput = False
        process1.encodesOutput = False
        threat = threats["INP29"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_INP30(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP30"]
        self.assertTrue(threat.apply(process1))

    def test_INP31(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        process1.usesParameterizedInput = False
        threat = threats["INP31"]
        self.assertTrue(threat.apply(process1))

    def test_INP32(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        process1.encodesOutput = False
        threat = threats["INP32"]
        self.assertTrue(threat.apply(process1))

    def test_INP33(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP33"]
        self.assertTrue(threat.apply(process1))

    def test_INP34(self):
        web = Server("web")
        web.checksInputBounds = False
        threat = threats["INP34"]
        self.assertTrue(threat.apply(web))

    def test_INP35(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP35"]
        self.assertTrue(threat.apply(process1))

    def test_DE04(self):
        data = Datastore("DB")
        data.validatesInput = False
        data.implementsPOLP = False
        threat = threats["DE04"]
        self.assertTrue(threat.apply(data))

    def test_AC15(self):
        process1 = Process("Process")
        process1.implementsPOLP = False
        threat = threats["AC15"]
        self.assertTrue(threat.apply(process1))

    def test_INP36(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.encodesHeaders = False
        threat = threats["INP36"]
        self.assertTrue(threat.apply(web))

    def test_INP37(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.encodesHeaders = False
        threat = threats["INP37"]
        self.assertTrue(threat.apply(web))

    def test_INP38(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP38"]
        self.assertTrue(threat.apply(process1))

    def test_AC16(self):
        web = Server("web")
        web.usesStrongSessionIdentifiers = False
        web.encryptsCookies = False
        threat = threats["AC16"]
        self.assertTrue(threat.apply(web))

    def test_INP39(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP39"]
        self.assertTrue(threat.apply(process1))

    def test_INP40(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.sanitizesInput = False
        process1.validatesInput = False
        threat = threats["INP40"]
        self.assertTrue(threat.apply(process1))

    def test_AC17(self):
        web = Server("web")
        web.usesStrongSessionIdentifiers = False
        threat = threats["AC17"]
        self.assertTrue(threat.apply(web))

    def test_AC18(self):
        process1 = Process("Process")
        process1.usesStrongSessionIdentifiers = False
        process1.encryptsCookies = False
        process1.definesConnectionTimeout = False
        threat = threats["AC18"]
        self.assertTrue(threat.apply(process1))

    def test_INP41(self):
        process1 = Process("Process")
        process1.validatesInput = False
        process1.sanitizesInput = False
        threat = threats["INP41"]
        self.assertTrue(threat.apply(process1))

    def test_AC19(self):
        web = Server("web")
        web.usesSessionTokens = True
        web.implementsNonce = False
        threat = threats["AC19"]
        self.assertTrue(threat.apply(web))

    def test_AC20(self):
        process1 = Process("Process")
        process1.definesConnectionTimeout = False
        process1.usesMFA = False
        process1.encryptsSessionData = False
        threat = threats["AC20"]
        self.assertTrue(threat.apply(process1))

    def test_AC21(self):
        process1 = Process("Process")
        process1.implementsCSRFToken = False
        process1.verifySessionIdentifiers = False
        threat = threats["AC21"]
        self.assertTrue(threat.apply(process1))


if __name__ == '__main__':
    unittest.main()
