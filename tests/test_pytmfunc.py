import json
import os
import random
import re
import unittest
import tempfile
from contextlib import redirect_stdout

from pytm import (
    pytm,
    TM,
    Action,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Lambda,
    Lifetime,
    Process,
    Finding,
    Server,
    Threat,
    TLSVersion,
    loads,
)
from pytm.pytm import to_serializable

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
    "r",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}

output_path=tempfile.gettempdir()

class TestTM(unittest.TestCase):
    def test_seq(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "seq.plantuml")) as x:
            expected = x.read().strip()

        TM.reset()
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = True
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)

        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.seq()

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_seq_unused(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "seq_unused.plantuml")) as x:
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

        self.assertTrue(tm.check())
        output = tm.seq()

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))

        with open(os.path.join(dir_path, "dfd.dot")) as x:
            expected = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        net = Boundary("Company net")
        dmz = Boundary("dmz", inBoundary=net)
        backend = Boundary("backend", inBoundary=net)
        user = Actor("User", inBoundary=internet)
        gw = Server("Gateway", inBoundary=dmz)
        web = Server("Web Server", inBoundary=backend)
        db = Datastore("SQL Database", inBoundary=backend, isEncryptedAtRest=True)
        comment = Data("Comment", isStored=True)

        Dataflow(user, gw, "User enters comments (*)")
        Dataflow(gw, web, "Request")
        Dataflow(web, db, "Insert query with comments", data=[comment])
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, gw, "Response")
        Dataflow(gw, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd()

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd_colormap(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))

        with open(os.path.join(dir_path, "dfd_colormap.dot")) as x:
            expected = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        net = Boundary("Company net")
        dmz = Boundary("dmz", inBoundary=net)
        backend = Boundary("backend", inBoundary=net)
        user = Actor("User", inBoundary=internet)
        gw = Server("Gateway", inBoundary=dmz)
        web = Server("Web Server", inBoundary=backend)
        db = Datastore("SQL Database", inBoundary=backend, isEncryptedAtRest=True)
        comment = Data("Comment", isStored=True)

        Dataflow(user, gw, "User enters comments (*)")
        Dataflow(gw, web, "Request")
        Dataflow(web, db, "Insert query with comments", data=[comment])
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, gw, "Response")
        Dataflow(gw, user, "Show comments (*)")

        self.assertTrue(tm.check())
        tm.resolve()
        output = tm.dfd(colormap=True)

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_dfd_duplicates_ignore(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))
        with open(os.path.join(dir_path, "dfd.dot")) as x:
            expected = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa", onDuplicates=Action.IGNORE)
        internet = Boundary("Internet")
        net = Boundary("Company net")
        dmz = Boundary("dmz", inBoundary=net)
        backend = Boundary("backend", inBoundary=net)
        user = Actor("User", inBoundary=internet)
        gw = Server("Gateway", inBoundary=dmz)
        web = Server("Web Server", inBoundary=backend)
        db = Datastore("SQL Database", inBoundary=backend)

        Dataflow(user, gw, "User enters comments (*)")
        Dataflow(user, gw, "User views comments")
        Dataflow(gw, web, "Request")
        Dataflow(web, db, "Insert query with comments")
        Dataflow(web, db, "Select query")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, gw, "Response")
        Dataflow(gw, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd()

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

        e = re.escape(
            "Duplicate Dataflow found between Actor(User) "
            "and Server(Web Server): Dataflow(User enters comments (*)) "
            "is same as Dataflow(User views comments)"
        )
        with self.assertRaisesRegex(ValueError, e):
            tm.check()

    def test_exclude_threats_ignore(self):
        random.seed(0)

        TM.reset()

        excluded_threat = "INP03"
        remaining_threat = "AA01"

        TM._threatsExcluded = [excluded_threat]

        tm = TM("my test tm", description="aaa")
        web = Server("Web")
        web.sanitizesInput = False
        web.encodesOutput = False
        self.assertTrue(threats[excluded_threat].apply(web))
        self.assertTrue(threats[remaining_threat].apply(web))

        tm.resolve()

        self.assertNotIn(excluded_threat, [t.threat_id for t in tm.findings])
        self.assertIn(remaining_threat, [t.threat_id for t in tm.findings])

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

        TM._threats = [
            Threat(SID=klass, target=klass, severity="")
            for klass in ["Actor", "Server", "Datastore", "Dataflow"]
        ]
        tm.resolve()

        self.maxDiff = None
        self.assertEqual(
            [f.threat_id for f in tm.findings],
            ["Server", "Datastore", "Dataflow", "Dataflow", "Dataflow", "Dataflow"],
        )
        self.assertEqual([f.threat_id for f in user.findings], [])
        self.assertEqual([f.threat_id for f in web.findings], ["Server"])
        self.assertEqual([f.threat_id for f in db.findings], ["Datastore"])
        self.assertEqual([f.threat_id for f in req.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in query.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in results.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in resp.findings], ["Dataflow"])

    def test_overrides(self):
        random.seed(0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet, inScope=False)
        web = Server(
            "Web Server",
            overrides=[
                Finding(threat_id="Server", response="mitigated by adding TLS"),
            ],
        )
        db = Datastore(
            "SQL Database",
            inBoundary=server_db,
            overrides=[
                Finding(
                    threat_id="Datastore",
                    response="accepted since inside the trust boundary",
                ),
            ],
        )

        req = Dataflow(user, web, "User enters comments (*)")
        query = Dataflow(web, db, "Insert query with comments")
        results = Dataflow(db, web, "Retrieve comments")
        resp = Dataflow(web, user, "Show comments (*)")

        TM._threats = [
            Threat(SID="Server", severity="High", target="Server", condition="False"),
            Threat(SID="Datastore", target="Datastore", severity="High"),
        ]
        tm.resolve()

        self.maxDiff = None
        self.assertEqual(
            [f.threat_id for f in tm.findings],
            ["Server", "Datastore"],
        )
        self.assertEqual(
            [f.response for f in web.findings], ["mitigated by adding TLS"]
        )
        self.assertEqual(
            [f.response for f in db.findings],
            ["accepted since inside the trust boundary"],
        )

    def test_json_dumps(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "output.json")) as x:
            expected = x.read().strip()
        TM.reset()
        tm = TM(
            "my test tm", description="aaa", threatsFile="pytm/threatlib/threats.json"
        )
        tm.isOrdered = True
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        func = Lambda("Lambda func")
        worker = Process("Task queue worker")
        db = Datastore("SQL Database", inBoundary=server_db)

        cookie = Data(
            name="auth cookie",
            description="auth cookie description",
            classification=Classification.PUBLIC,
        )
        Dataflow(user, web, "User enters comments (*)", note="bbb", data=cookie)
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(web, func, "Call func")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")
        Dataflow(worker, db, "Query for tasks")

        self.assertTrue(tm.check())
        output = json.dumps(tm, default=to_serializable, sort_keys=True, indent=4)

        with open(os.path.join(output_path, "output_current.json"), "w") as x:
            x.write(output)

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_json_loads(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "input.json")) as x:
            contents = x.read().strip()

        TM.reset()
        tm = loads(contents)
        self.assertTrue(tm.check())

        self.maxDiff = None
        self.assertEqual([b.name for b in tm._boundaries], ["Internet", "Server/DB"])
        self.assertEqual(
            [e.name for e in tm._elements],
            [
                "Internet",
                "Server/DB",
                "User",
                "Web Server",
                "SQL Database",
                "Request",
                "Insert",
                "Select",
                "Response",
            ],
        )
        self.assertEqual(
            [f.name for f in tm._flows], ["Request", "Insert", "Select", "Response"]
        )

    def test_report(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "output.md")) as x:
            expected = x.read().strip()

        TM.reset()
        tm = TM(
            "my test tm", description="aaa", threatsFile="pytm/threatlib/threats.json"
        )
        tm.isOrdered = True
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        func = Lambda("Lambda func")
        worker = Process("Task queue worker")
        db = Datastore("SQL Database", inBoundary=server_db)

        cookie = Data(
            name="auth cookie",
            description="auth cookie description",
            classification=Classification.PUBLIC,
        )
        Dataflow(user, web, "User enters comments (*)", note="bbb", data=cookie)
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(web, func, "Call func")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")
        Dataflow(worker, db, "Query for tasks")

        self.assertTrue(tm.check())
        output = tm.report("docs/basic_template.md")

        with open(os.path.join(output_path, "output_current.md"), "w") as x:
            x.write(output)

        with open(os.path.join(output_path, "output_current.md"), "w") as x:
            x.write(output)

        self.maxDiff = None
        self.assertEqual(output.strip(), expected.strip())

    def test_multilevel_dfd(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))

        with open(os.path.join(dir_path, "dfd_level0.txt")) as x:
            level_0 = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )
        with open(os.path.join(dir_path, "dfd_level1.txt")) as x:
            level_1 = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

        TM.reset()
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = False
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet, levels=0)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)
        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd(levels={0})
        with open(os.path.join(output_path, "0.txt"), "w") as x:
            x.write(output)
        self.maxDiff = None
        self.assertEqual(output, level_0)

        TM.reset()
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = False
        internet = Boundary("Internet")
        server_db = Boundary("Server/DB")
        user = Actor("User", inBoundary=internet, levels=1)
        web = Server("Web Server")
        db = Datastore("SQL Database", inBoundary=server_db)
        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, db, "Insert query with comments", note="ccc")
        Dataflow(db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd(levels={1})
        with open(os.path.join(output_path, "1.txt"), "w") as x:
            x.write(output)
        self.maxDiff = None
        self.assertEqual(output, level_1)


class Testpytm(unittest.TestCase):
    # Test for all the threats in threats.py - test Threat.apply() function

    def test_INP01(self):
        lambda1 = Lambda("mylambda")
        process1 = Process("myprocess")
        lambda1.usesEnvironmentVariables = True
        lambda1.controls.sanitizesInput = False
        lambda1.controls.checksInputBounds = False
        process1.usesEnvironmentVariables = True
        process1.controls.sanitizesInput = False
        process1.controls.checksInputBounds = False
        threat = threats["INP01"]
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(process1))

    def test_INP02(self):
        process1 = Process("myprocess")
        process1.controls.checksInputBounds = False
        threat = threats["INP02"]
        self.assertTrue(threat.apply(process1))

    def test_INP03(self):
        web = Server("Web")
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        threat = threats["INP03"]
        self.assertTrue(threat.apply(web))

    def test_CR01(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = "HTTP"
        web.usesVPN = False
        web.usesSessionTokens = True
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.usesVPN = False
        user_to_web.usesSessionTokens = True
        threat = threats["CR01"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(user_to_web))

    def test_INP04(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.validatesHeaders = False
        web.protocol = "HTTP"
        threat = threats["INP04"]
        self.assertTrue(threat.apply(web))

    def test_CR02(self):
        user = Actor("User")
        web = Server("Web Server")
        web.protocol = "HTTP"
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.usesSessionTokens = True
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.controls.sanitizesInput = False
        user_to_web.controls.validatesInput = False
        user_to_web.usesSessionTokens = True
        threat = threats["CR02"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(user_to_web))

    def test_INP05(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP05"]
        self.assertTrue(threat.apply(web))

    def test_INP06(self):
        web = Server("Web Server")
        web.protocol = "SOAP"
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        threat = threats["INP06"]
        self.assertTrue(threat.apply(web))

    def test_SC01(self):
        process1 = Process("Process1")
        process1.implementsNonce = False
        json = Data(name="JSON", description="some JSON data", format="JSON")
        process1.data = json
        threat = threats["SC01"]
        self.assertTrue(threat.apply(process1))

    def test_LB01(self):
        process1 = Process("Process1")
        process1.implementsAPI = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1 = Lambda("Lambda1")
        lambda1.implementsAPI = True
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
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
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["DS01"]
        self.assertTrue(threat.apply(web))

    def test_DE01(self):

        with self.subTest("Default case"):
            user = Actor("User")
            web = Server("Web Server")
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.protocol = "HTTP"
            threat = threats["DE01"]
            self.assertTrue(threat.apply(user_to_web))

        with self.subTest("Success case"):
            user = Actor("User")
            web = Server("Web Server")
            web.minTLSVersion = TLSVersion.TLSv12
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.tlsVersion = TLSVersion.TLSv13
            user_to_web.controls.isEncrypted = True
            user_to_web.controls.authenticatesDestination = True
            user_to_web.controls.checksDestinationRevocation = True
            threat = threats["DE01"]
            self.assertFalse(threat.apply(user_to_web))

        with self.subTest("Dataflow TLS below minimum version"):
            user = Actor("User")
            web = Server("Web Server")
            web.minTLSVersion = TLSVersion.TLSv12
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.tlsVersion = TLSVersion.TLSv11
            user_to_web.controls.isEncrypted = True
            user_to_web.controls.authenticatesDestination = True
            user_to_web.controls.checksDestinationRevocation = True
            threat = threats["DE01"]
            self.assertTrue(threat.apply(user_to_web))

        with self.subTest("Dataflow doesn't authenticate destination"):
            user = Actor("User")
            web = Server("Web Server")
            web.minTLSVersion = TLSVersion.TLSv12
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.tlsVersion = TLSVersion.TLSv13
            user_to_web.controls.isEncrypted = True
            user_to_web.controls.authenticatesDestination = False
            user_to_web.controls.checksDestinationRevocation = True
            threat = threats["DE01"]
            self.assertTrue(threat.apply(user_to_web))

        with self.subTest("Dataflow doesn't check destination revocation"):
            user = Actor("User")
            web = Server("Web Server")
            web.minTLSVersion = TLSVersion.TLSv12
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.tlsVersion = TLSVersion.TLSv13
            user_to_web.controls.isEncrypted = True
            user_to_web.controls.authenticatesDestination = True
            user_to_web.controls.checksDestinationRevocation = False
            threat = threats["DE01"]
            self.assertTrue(threat.apply(user_to_web))

        with self.subTest("Dataflow is response"):
            user = Actor("User")
            web = Server("Web Server")
            web.minTLSVersion = TLSVersion.TLSv12
            user_to_web = Dataflow(user, web, "User enters comments (*)")
            user_to_web.isResponse = True
            user_to_web.tlsVersion = TLSVersion.TLSv13
            user_to_web.controls.isEncrypted = True
            user_to_web.controls.authenticatesDestination = False
            user_to_web.controls.checksDestinationRevocation = False
            threat = threats["DE01"]
            self.assertFalse(threat.apply(user_to_web))

    def test_DE02(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
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
        web.controls.hasAccessControl = False
        web.controls.authorizesSource = True
        process1.controls.hasAccessControl = False
        process1.controls.authorizesSource = False
        db.controls.hasAccessControl = False
        db.controls.authorizesSource = False
        threat = threats["AC01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_INP07(self):
        process1 = Process("Process1")
        process1.controls.usesSecureFunctions = False
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
        process1.controls.handlesResourceConsumption = False
        process1.controls.isResilient = False
        web.handlesResourceConsumption = True
        threat = threats["DO01"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_HA01(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["HA01"]
        self.assertTrue(threat.apply(web))

    def test_AC03(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.usesEnvironmentVariables = True
        process1.controls.implementsAuthenticationScheme = False
        process1.controls.validatesInput = False
        process1.controls.authorizesSource = False
        lambda1.usesEnvironmentVariables = True
        lambda1.controls.implementsAuthenticationScheme = False
        lambda1.controls.validatesInput = False
        lambda1.controls.authorizesSource = False
        threat = threats["AC03"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_DO02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        db = Datastore("DB")
        process1.controls.handlesResourceConsumption = False
        lambda1.controls.handlesResourceConsumption = False
        web.controls.handlesResourceConsumption = False
        db.controls.handlesResourceConsumption = False
        threat = threats["DO02"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_DS02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.environment = "Production"
        lambda1.environment = "Production"
        threat = threats["DS02"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP08(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["INP08"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))

    def test_INP09(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP09"]
        self.assertTrue(threat.apply(web))

    def test_INP10(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP10"]
        self.assertTrue(threat.apply(web))

    def test_INP11(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["INP11"]
        self.assertTrue(threat.apply(web))

    def test_INP12(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.controls.checksInputBounds = False
        process1.controls.validatesInput = False
        lambda1.controls.checksInputBounds = False
        lambda1.controls.validatesInput = False
        threat = threats["INP12"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_AC04(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        user_to_web.authorizesSource = False
        threat = threats["AC04"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DO03(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        threat = threats["DO03"]
        self.assertTrue(threat.apply(user_to_web))

    def test_AC05(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesDestination = False
        proc_to_web = Dataflow(process1, web, "Process calls a web API")
        proc_to_web.protocol = "HTTPS"
        proc_to_web.controls.isEncrypted = True
        threat = threats["AC05"]
        self.assertTrue(threat.apply(proc_to_web))

    def test_INP13(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.controls.validatesInput = False
        lambda1.controls.validatesInput = False
        threat = threats["INP13"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP14(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.controls.validatesInput = False
        lambda1.controls.validatesInput = False
        web.controls.validatesInput = False
        threat = threats["INP14"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))
        self.assertTrue(threat.apply(web))

    def test_DE03(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.controls.isEncrypted = False
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
        process1.controls.validatesInput = False
        lambda1.implementsAPI = True
        lambda1.controls.validatesInput = False
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
        web.controls.hasAccessControl = False
        threat = threats["AC06"]
        self.assertTrue(threat.apply(web))

    def test_HA03(self):
        web = Server("Web Server")
        web.controls.validatesHeaders = False
        web.controls.encodesOutput = False
        web.isHardened = False
        threat = threats["HA03"]
        self.assertTrue(threat.apply(web))

    def test_SC02(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["SC02"]
        self.assertTrue(threat.apply(web))

    def test_AC07(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        threat = threats["AC07"]
        self.assertTrue(threat.apply(web))

    def test_INP15(self):
        web = Server("Web Server")
        web.protocol = "IMAP"
        web.controls.sanitizesInput = False
        threat = threats["INP15"]
        self.assertTrue(threat.apply(web))

    def test_HA04(self):
        EE = ExternalEntity("ee")
        EE.hasPhysicalAccess = True
        threat = threats["HA04"]
        self.assertTrue(threat.apply(EE))

    def test_SC03(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        web.controls.hasAccessControl = False
        threat = threats["SC03"]
        self.assertTrue(threat.apply(web))

    def test_INP16(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
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
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        user_to_web.handlesResources = False
        threat = threats["DO04"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DS04(self):
        web = Server("Web Server")
        web.controls.encodesOutput = False
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["DS04"]
        self.assertTrue(threat.apply(web))

    def test_SC04(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["SC04"]
        self.assertTrue(threat.apply(web))

    def test_CR05(self):
        web = Server("Web Server")
        db = Datastore("db")
        web.controls.usesEncryptionAlgorithm != "RSA"
        web.controls.usesEncryptionAlgorithm != "AES"
        db.controls.usesEncryptionAlgorithm != "RSA"
        db.controls.usesEncryptionAlgorithm != "AES"
        threat = threats["CR05"]
        self.assertTrue(threat.apply(web))
        self.assertTrue(threat.apply(db))

    def test_AC08(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        threat = threats["AC08"]
        self.assertTrue(threat.apply(web))

    def test_DS05(self):
        web = Server("Web Server")
        web.usesCache = True
        threat = threats["DS05"]
        self.assertTrue(threat.apply(web))

    def test_DS06(self):
        threat = threats["DS06"]

        def create_dataflow(
            source=Classification.RESTRICTED,
            sink=Classification.RESTRICTED,
            dataflow=Classification.RESTRICTED,
            data=Classification.RESTRICTED,
            define_data=True,
        ):
            source_ = Server("Source", maxClassification=source)
            sink_ = Datastore("Sink", maxClassification=sink)
            flow_ = Dataflow(source_, sink_, "Flow", maxClassification=dataflow)
            if define_data:
                flow_.data = Data("Data", classification=data)
            return flow_

        with self.subTest("Doesn't apply unless dataflow has data defined"):
            dataflow = create_dataflow(define_data=False)
            self.assertFalse(threat.apply(dataflow))

        with self.subTest("Data classification equals sink, source and dataflow"):
            dataflow = create_dataflow()
            self.assertFalse(threat.apply(dataflow))

        with self.subTest("Data classification is less than sink, source and dataflow"):
            dataflow = create_dataflow(data=Classification.PUBLIC)
            self.assertFalse(threat.apply(dataflow))

        with self.subTest("Data classification exceeds source"):
            dataflow = create_dataflow(source=Classification.PUBLIC)
            self.assertTrue(threat.apply(dataflow))

        with self.subTest("Data classification exceeds sink"):
            dataflow = create_dataflow(sink=Classification.PUBLIC)
            self.assertTrue(threat.apply(dataflow))

        with self.subTest("Data classification exceeds dataflow"):
            dataflow = create_dataflow(dataflow=Classification.PUBLIC)
            self.assertTrue(threat.apply(dataflow))

    def test_SC05(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.controls.usesCodeSigning = False
        threat = threats["SC05"]
        self.assertTrue(threat.apply(web))

    def test_INP17(self):
        web = Server("Web Server")
        web.controls.validatesContentType = False
        web.invokesScriptFilters = False
        threat = threats["INP17"]
        self.assertTrue(threat.apply(web))

    def test_AA03(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.authenticatesSource = False
        web.controls.usesStrongSessionIdentifiers = False
        threat = threats["AA03"]
        self.assertTrue(threat.apply(web))

    def test_AC09(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        web.authorizesSource = False
        threat = threats["AC09"]
        self.assertTrue(threat.apply(web))

    def test_INP18(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        threat = threats["INP18"]
        self.assertTrue(threat.apply(web))

    def test_CR06(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.usesVPN = False
        user_to_web.implementsAuthenticationScheme = False
        user_to_web.authorizesSource = False
        threat = threats["CR06"]
        self.assertTrue(threat.apply(user_to_web))

    def test_AC10(self):
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv11
        web.implementsAuthenticationScheme = False
        web.authorizesSource = False
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        user_to_web.tlsVersion = TLSVersion.SSLv3
        web.inputs = [user_to_web]
        threat = threats["AC10"]
        self.assertTrue(threat.apply(web))

    def test_CR07(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
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
        web.minTLSVersion = TLSVersion.TLSv11
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        user_to_web.tlsVersion = TLSVersion.SSLv3
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
        web.controls.usesStrongSessionIdentifiers = False
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
        process1.controls.hasAccessControl = False
        process1.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        threat = threats["INP23"]
        self.assertTrue(threat.apply(process1))

    def test_DO05(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        web.usesXMLParser = True
        threat = threats["DO05"]
        self.assertTrue(threat.apply(web))

    def test_AC12(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.controls.implementsPOLP = False
        threat = threats["AC12"]
        self.assertTrue(threat.apply(process1))

    def test_AC13(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.controls.implementsPOLP = False
        threat = threats["AC13"]
        self.assertTrue(threat.apply(process1))

    def test_AC14(self):
        process1 = Process("Process")
        process1.controls.implementsPOLP = False
        process1.usesEnvironmentVariables = False
        process1.controls.validatesInput = False
        threat = threats["AC14"]
        self.assertTrue(threat.apply(process1))

    def test_INP24(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.checksInputBounds = False
        process1.controls.validatesInput = False
        lambda1.controls.checksInputBounds = False
        lambda1.controls.validatesInput = False
        threat = threats["INP24"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP25(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        threat = threats["INP25"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP26(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        threat = threats["INP26"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(lambda1))

    def test_INP27(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP27"]
        self.assertTrue(threat.apply(process1))

    def test_INP28(self):
        web = Server("Web Server")
        process1 = Process("Process")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.encodesOutput = False
        threat = threats["INP28"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_INP29(self):
        web = Server("Web Server")
        process1 = Process("Process")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.encodesOutput = False
        threat = threats["INP29"]
        self.assertTrue(threat.apply(process1))
        self.assertTrue(threat.apply(web))

    def test_INP30(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP30"]
        self.assertTrue(threat.apply(process1))

    def test_INP31(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.usesParameterizedInput = False
        threat = threats["INP31"]
        self.assertTrue(threat.apply(process1))

    def test_INP32(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.encodesOutput = False
        threat = threats["INP32"]
        self.assertTrue(threat.apply(process1))

    def test_INP33(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP33"]
        self.assertTrue(threat.apply(process1))

    def test_INP34(self):
        web = Server("web")
        web.controls.checksInputBounds = False
        threat = threats["INP34"]
        self.assertTrue(threat.apply(web))

    def test_INP35(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP35"]
        self.assertTrue(threat.apply(process1))

    def test_DE04(self):
        data = Datastore("DB")
        data.controls.validatesInput = False
        data.controls.implementsPOLP = False
        threat = threats["DE04"]
        self.assertTrue(threat.apply(data))

    def test_AC15(self):
        process1 = Process("Process")
        process1.controls.implementsPOLP = False
        threat = threats["AC15"]
        self.assertTrue(threat.apply(process1))

    def test_INP36(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.controls.encodesHeaders = False
        threat = threats["INP36"]
        self.assertTrue(threat.apply(web))

    def test_INP37(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.controls.encodesHeaders = False
        threat = threats["INP37"]
        self.assertTrue(threat.apply(web))

    def test_INP38(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP38"]
        self.assertTrue(threat.apply(process1))

    def test_AC16(self):
        web = Server("web")
        web.controls.usesStrongSessionIdentifiers = False
        web.controls.encryptsCookies = False
        threat = threats["AC16"]
        self.assertTrue(threat.apply(web))

    def test_INP39(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP39"]
        self.assertTrue(threat.apply(process1))

    def test_INP40(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        threat = threats["INP40"]
        self.assertTrue(threat.apply(process1))

    def test_AC17(self):
        web = Server("web")
        web.controls.usesStrongSessionIdentifiers = False
        threat = threats["AC17"]
        self.assertTrue(threat.apply(web))

    def test_AC18(self):
        process1 = Process("Process")
        process1.controls.usesStrongSessionIdentifiers = False
        process1.controls.encryptsCookies = False
        process1.controls.definesConnectionTimeout = False
        threat = threats["AC18"]
        self.assertTrue(threat.apply(process1))

    def test_INP41(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
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
        process1.controlsdefinesConnectionTimeout = False
        process1.controls.usesMFA = False
        process1.controls.encryptsSessionData = False
        threat = threats["AC20"]
        self.assertTrue(threat.apply(process1))

    def test_AC21(self):
        process1 = Process("Process")
        process1.implementsCSRFToken = False
        process1.verifySessionIdentifiers = False
        threat = threats["AC21"]
        self.assertTrue(threat.apply(process1))

    def test_AC22(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = Data(
            "password", isCredentials=True, credentialsLife=Lifetime.HARDCODED
        )
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        threat = threats["AC22"]
        self.assertTrue(threat.apply(user_to_web))

    def test_DR01(self):
        web = Server("Web Server")
        db = Datastore("Database")
        insert = Dataflow(web, db, "Insert query")
        insert.data = Data("ssn", isPII=True, isStored=True)
        insert.controls.isEncrypted = False
        threat = threats["DR01"]
        self.assertTrue(threat.apply(insert))
