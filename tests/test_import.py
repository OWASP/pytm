import json
import os
import re
import unittest

import importlib

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
    Lambda,
    Process,
    Finding,
    Server,
    Threat,
)
from pytm.pytm import to_serializable

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
    "r",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


class TestTMImport(unittest.TestCase):
    def test_seq(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "import_data/seq.plantuml")) as x:
            expected = x.read().strip()

        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = True
        user = Actor("User", inBoundary=other.internet)
        web = Server("Web Server")

        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.seq()

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_seq_unused(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "import_data/seq_unused.plantuml")) as x:
            expected = x.read().strip()

        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        user = Actor("User", inBoundary=other.internet)
        web = Server("Web Server")

        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(other.db, web, "Retrieve comments")
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

    def test_dfd_duplicates_ignore(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))
        with open(os.path.join(dir_path, "dfd.dot")) as x:
            expected = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

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

        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa", onDuplicates=Action.RESTRICT)
        tm.isOrdered = True
        user = Actor("User", inBoundary=other.internet)
        web = Server("Web Server")

        Dataflow(user, other.web, "User enters comments (*)")
        Dataflow(user, other.web, "User views comments")
        Dataflow(other.web, other.db, "Insert query with comments")
        Dataflow(other.web, other.db, "Select query")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        e = re.escape(
            "Duplicate Dataflow found between Actor(User) "
            "and Server(Web Server): Dataflow(User enters comments (*)) "
            "is same as Dataflow(User views comments)"
        )
        with self.assertRaisesRegex(ValueError, e):
            tm.check()

    def test_exclude_threats_ignore(self):

        excluded_threat = "INP03"
        remaining_threat = "AA01"

        tm = TM("my test tm", description="aaa")
        tm._threatsExcluded = [excluded_threat]
        web = Server("Web")
        web.sanitizesInput = False
        web.encodesOutput = False
        self.assertTrue(threats[excluded_threat].apply(web))
        self.assertTrue(threats[remaining_threat].apply(web))
        tm.resolve()

        self.assertNotIn(excluded_threat, [t.threat_id for t in tm.findings])
        self.assertIn(remaining_threat, [t.threat_id for t in tm.findings])

    def test_resolve(self):
        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        user = Actor("User", inBoundary=other.internet, inScope=False)
        web = Server("Web Server")

        req = Dataflow(user, web, "User enters comments (*)")
        query = Dataflow(web, other.db, "Insert query with comments")
        results = Dataflow(other.db, web, "Retrieve comments")
        resp = Dataflow(web, user, "Show comments (*)")

        tm._threats = [
            Threat(SID=klass, target=klass)
            for klass in ["Actor", "Server", "Datastore", "Dataflow"]
        ]
        self.assertTrue(tm.check())
        tm.resolve()

        self.maxDiff = None
        self.assertEqual(
            [f.threat_id for f in tm.findings],
            ["Server", "Dataflow", "Dataflow", "Dataflow", "Dataflow", "Datastore"],
        )
        self.assertEqual([f.threat_id for f in user.findings], [])
        self.assertEqual([f.threat_id for f in web.findings], ["Server"])
        self.assertEqual([f.threat_id for f in other.db.findings], ["Datastore"])
        self.assertEqual([f.threat_id for f in req.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in query.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in results.findings], ["Dataflow"])
        self.assertEqual([f.threat_id for f in resp.findings], ["Dataflow"])

    def test_overrides(self):
        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        internet = Boundary("Internet")
        user = Actor("User", inBoundary=internet, inScope=False)
        web = Server(
            "Web Server",
            overrides=[
                Finding(threat_id="Server", response="mitigated by adding TLS"),
            ],
        )
        other.db.overrides = [
                Finding(
                    threat_id="Datastore",
                    response="accepted since inside the trust boundary",
                ),
            ]

        Dataflow(user, web, "User enters comments (*)")
        Dataflow(web, other.db, "Insert query with comments")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        tm._threats = [
            Threat(SID="Server", target="Server", condition="False"),
            Threat(SID="Datastore", target="Datastore"),
        ]
        self.assertTrue(tm.check())
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
            [f.response for f in other.db.findings],
            ["accepted since inside the trust boundary"],
        )

    def test_json_dumps(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "output.json")) as x:
            expected = x.read().strip()
        import tests.tm_import as other
        importlib.reload(other)
        tm = TM(
            "my test tm", description="aaa", threatsFile="pytm/threatlib/threats.json"
        )
        tm.isOrdered = True
        internet = Boundary("Internet")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        func = Lambda("Lambda func")
        worker = Process("Task queue worker")

        cookie = Data(
            name="auth cookie",
            description="auth cookie description",
            classification=Classification.PUBLIC,
        )
        Dataflow(user, web, "User enters comments (*)", note="bbb", data=cookie)
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(web, func, "Call func")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")
        Dataflow(worker, other.db, "Query for tasks")

        self.assertTrue(tm.check())
        output = json.dumps(tm, default=to_serializable, sort_keys=True, indent=4)

        with open(os.path.join(dir_path, "output_current.json"), "w") as x:
            x.write(output)

        self.maxDiff = None
        self.assertEqual(output, expected)

    def test_report(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "output.md")) as x:
            expected = x.read().strip()

        import tests.tm_import as other
        importlib.reload(other)
        tm = TM(
            "my test tm", description="aaa", threatsFile="pytm/threatlib/threats.json"
        )
        tm.isOrdered = True
        internet = Boundary("Internet")
        user = Actor("User", inBoundary=internet)
        web = Server("Web Server")
        func = Lambda("Lambda func")
        worker = Process("Task queue worker")

        cookie = Data(
            name="auth cookie",
            description="auth cookie description",
            classification=Classification.PUBLIC,
        )
        Dataflow(user, web, "User enters comments (*)", note="bbb", data=cookie)
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(web, func, "Call func")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")
        Dataflow(worker, other.db, "Query for tasks")

        self.assertTrue(tm.check())
        output = tm.report("docs/template.md")

        with open(os.path.join(dir_path, "output_current.md"), "w") as x:
            x.write(output)

        self.maxDiff = None
        self.assertEqual(output.strip(), expected.strip())

    def test_multilevel_dfd(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        install_path = os.path.dirname(os.path.realpath(pytm.__file__))

        with open(os.path.join(dir_path, "import_data/dfd_level0.txt")) as x:
            level_0 = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )
        with open(os.path.join(dir_path, "import_data/dfd_level1.txt")) as x:
            level_1 = (
                x.read().strip().replace("INSTALL_PATH", os.path.dirname(install_path))
            )

        import tests.tm_import as other
        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = False
        internet = Boundary("Internet")
        user = Actor("User", inBoundary=internet, levels=0)
        web = Server("Web Server")
        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd(levels={0})
        with open(os.path.join(dir_path, "0.txt"), "w") as x:
            x.write(output)
        self.assertEqual(output, level_0)

        importlib.reload(other)
        tm = TM("my test tm", description="aaa")
        tm.isOrdered = False
        internet = Boundary("Internet")
        user = Actor("User", inBoundary=internet, levels=1)
        web = Server("Web Server")
        Dataflow(user, web, "User enters comments (*)", note="bbb")
        Dataflow(web, other.db, "Insert query with comments", note="ccc")
        Dataflow(other.db, web, "Retrieve comments")
        Dataflow(web, user, "Show comments (*)")

        self.assertTrue(tm.check())
        output = tm.dfd(levels={1})
        with open(os.path.join(dir_path, "1.txt"), "w") as x:
            x.write(output)
        self.maxDiff = None
        self.assertEqual(output, level_1)
