import json
import os
import random
import re
import tempfile
import pytest
from contextlib import redirect_stdout

from pytm import (
    pytm,
    TM,
    Action,
    Actor,
    Assumption,
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

output_path = tempfile.gettempdir()

class TestTM:
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

        assert tm.check()
        output = tm.seq()
        assert output == expected

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

        assert tm.check()
        output = tm.seq()
        assert output == expected

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

        assert tm.check()
        output = tm.dfd()

        assert output == expected

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

        assert tm.check()
        tm.resolve()
        output = tm.dfd(colormap=True)

        assert output == expected

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

        assert tm.check()
        output = tm.dfd()

        assert output == expected

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
        with pytest.raises(ValueError, match=e):
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
        assert threats[excluded_threat].apply(web)
        assert threats[remaining_threat].apply(web)

        tm.resolve()

        assert excluded_threat not in [t.threat_id for t in tm.findings]
        assert remaining_threat in [t.threat_id for t in tm.findings]

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

        assert [f.threat_id for f in tm.findings] == [
            "Server",
            "Datastore",
            "Dataflow",
            "Dataflow",
            "Dataflow",
            "Dataflow",
        ]
        assert [f.threat_id for f in user.findings] == []
        assert [f.threat_id for f in web.findings] == ["Server"]
        assert [f.threat_id for f in db.findings] == ["Datastore"]
        assert [f.threat_id for f in req.findings] == ["Dataflow"]
        assert [f.threat_id for f in query.findings] == ["Dataflow"]
        assert [f.threat_id for f in results.findings] == ["Dataflow"]
        assert [f.threat_id for f in resp.findings] == ["Dataflow"]

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
                Finding(
                    threat_id="Server",
                    response="mitigated by adding TLS",
                    cvss="1.234",
                ),
            ],
        )
        db = Datastore(
            "SQL Database",
            inBoundary=server_db,
            overrides=[
                Finding(
                    threat_id="Datastore",
                    response="accepted since inside the trust boundary",
                    cvss="9.876",
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

        assert [f.threat_id for f in tm.findings] == ["Server", "Datastore"]
        assert [f.response for f in web.findings] == ["mitigated by adding TLS"]
        assert [f.cvss for f in web.findings] == ["1.234"]
        assert [f.response for f in db.findings] == [
            "accepted since inside the trust boundary"
        ]
        assert [f.cvss for f in db.findings] == ["9.876"]

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

        assert tm.check()
        output = json.dumps(tm, default=to_serializable, sort_keys=True, indent=4)

        with open(os.path.join(output_path, "output_current.json"), "w") as x:
            x.write(output)

        assert output == expected

    def test_json_loads(self):
        random.seed(0)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "input.json")) as x:
            contents = x.read().strip()

        TM.reset()
        tm = loads(contents)
        assert tm.check()

        assert [b.name for b in tm._boundaries] == ["Internet", "Server/DB"]
        assert [e.name for e in tm._elements] == [
            "Internet",
            "Server/DB",
            "User",
            "Web Server",
            "SQL Database",
            "Request",
            "Insert",
            "Select",
            "Response",
        ]
        assert [f.name for f in tm._flows] == ["Request", "Insert", "Select", "Response"]

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

        assert tm.check()
        output = tm.report("docs/basic_template.md")

        with open(os.path.join(output_path, "output_current.md"), "w") as x:
            x.write(output)

        assert output.strip() == expected.strip()

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

        assert tm.check()
        output = tm.dfd(levels={0})
        with open(os.path.join(output_path, "0.txt"), "w") as x:
            x.write(output)
        assert output == level_0

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

        assert tm.check()
        output = tm.dfd(levels={1})
        with open(os.path.join(output_path, "1.txt"), "w") as x:
            x.write(output)
        assert output == level_1

    def test_element_assumptions(self):
        web = Server("Web Server")
        assumption1 = Assumption("Assumption 1", exclude=["INP01", "INP02"])
        assumption2 = Assumption("Assumption 2", exclude=["INP03"])
        web.assumptions = [assumption1, assumption2]

        assert len(web.assumptions) == 2
        assert web.assumptions[0].name == "Assumption 1"
        assert web.assumptions[0].exclude == {"INP01", "INP02"}
        assert web.assumptions[1].name == "Assumption 2"
        assert web.assumptions[1].exclude == {"INP03"}

        # Test adding an invalid assumption
        with pytest.raises(ValueError):
            web.assumptions = [assumption1, "Invalid Assumption"]

    def test_exclude_threats_by_assumptions(self):
        # Test excluding threats based on assumptions
        web = Server("Web Server")
        assumption = Assumption("Assumption", exclude=["INP03"])
        web.assumptions = [assumption]
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False

        tm = TM("Test TM")
        tm.resolve()

        assert "INP03" not in [f.threat_id for f in web.findings]
        assert "INP03" in [f.threat_id for f in tm.excluded_findings]


class Testpytm:
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
        assert threat.apply(lambda1)
        assert threat.apply(process1)

    def test_INP02(self):
        process1 = Process("myprocess")
        process1.controls.checksInputBounds = False
        threat = threats["INP02"]
        assert threat.apply(process1)

    def test_INP03(self):
        web = Server("Web")
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        threat = threats["INP03"]
        assert threat.apply(web)

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
        assert threat.apply(web)
        assert threat.apply(user_to_web)

    def test_INP04(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.validatesHeaders = False
        web.protocol = "HTTP"
        threat = threats["INP04"]
        assert threat.apply(web)

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
        assert threat.apply(web)
        assert threat.apply(user_to_web)

    def test_INP05(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP05"]
        assert threat.apply(web)

    def test_INP06(self):
        web = Server("Web Server")
        web.protocol = "SOAP"
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        threat = threats["INP06"]
        assert threat.apply(web)

    def test_SC01(self):
        process1 = Process("Process1")
        process1.implementsNonce = False
        json = Data(name="JSON", description="some JSON data", format="JSON")
        process1.data = json
        threat = threats["SC01"]
        assert threat.apply(process1)

    def test_LB01(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.implementsAPI = True
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        threat = threats["LB01"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_AA01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesSource = False
        web.authenticatesSource = False
        threat = threats["AA01"]
        assert threat.apply(process1)
        assert threat.apply(web)

    def test_DS01(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["DS01"]
        assert threat.apply(web)

    def test_DE01(self):
        # Default case
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        threat = threats["DE01"]
        assert threat.apply(user_to_web)

        # Success case
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv12
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.tlsVersion = TLSVersion.TLSv13
        user_to_web.controls.isEncrypted = True
        user_to_web.controls.authenticatesDestination = True
        user_to_web.controls.checksDestinationRevocation = True
        threat = threats["DE01"]
        assert not threat.apply(user_to_web)

        # Dataflow TLS below minimum version
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv12
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.tlsVersion = TLSVersion.TLSv11
        user_to_web.controls.isEncrypted = True
        user_to_web.controls.authenticatesDestination = True
        user_to_web.controls.checksDestinationRevocation = True
        threat = threats["DE01"]
        assert threat.apply(user_to_web)

        # Dataflow doesn't authenticate destination
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv12
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.tlsVersion = TLSVersion.TLSv13
        user_to_web.controls.isEncrypted = True
        user_to_web.controls.authenticatesDestination = False
        user_to_web.controls.checksDestinationRevocation = True
        threat = threats["DE01"]
        assert threat.apply(user_to_web)

        # Dataflow doesn't check destination revocation
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv12
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.tlsVersion = TLSVersion.TLSv13
        user_to_web.controls.isEncrypted = True
        user_to_web.controls.authenticatesDestination = True
        user_to_web.controls.checksDestinationRevocation = False
        threat = threats["DE01"]
        assert threat.apply(user_to_web)

        # Dataflow is response
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
        assert not threat.apply(user_to_web)

    def test_DE02(self):
        web = Server("Web Server")
        process1 = Process("Process1")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["DE02"]
        assert threat.apply(web)
        assert threat.apply(process1)

    def test_API01(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        lambda1.implementsAPI = True
        threat = threats["API01"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

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
        assert threat.apply(process1)
        assert threat.apply(web)
        assert threat.apply(db)

    def test_INP07(self):
        process1 = Process("Process1")
        process1.controls.usesSecureFunctions = False
        threat = threats["INP07"]
        assert threat.apply(process1)

    def test_AC02(self):
        db = Datastore("DB")
        db.isShared = True
        threat = threats["AC02"]
        assert threat.apply(db)

    def test_DO01(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.controls.handlesResourceConsumption = False
        process1.controls.isResilient = False
        web.handlesResourceConsumption = True
        threat = threats["DO01"]
        assert threat.apply(process1)
        assert threat.apply(web)

    def test_HA01(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["HA01"]
        assert threat.apply(web)

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
        assert threat.apply(process1)
        assert threat.apply(lambda1)

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
        assert threat.apply(process1)
        assert threat.apply(lambda1)
        assert threat.apply(web)
        assert threat.apply(db)

    def test_DS02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.environment = "Production"
        lambda1.environment = "Production"
        threat = threats["DS02"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

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
        assert threat.apply(process1)
        assert threat.apply(lambda1)
        assert threat.apply(web)

    def test_INP09(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP09"]
        assert threat.apply(web)

    def test_INP10(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP10"]
        assert threat.apply(web)

    def test_INP11(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["INP11"]
        assert threat.apply(web)

    def test_INP12(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.controls.checksInputBounds = False
        process1.controls.validatesInput = False
        lambda1.controls.checksInputBounds = False
        lambda1.controls.validatesInput = False
        threat = threats["INP12"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_AC04(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        user_to_web.authorizesSource = False
        threat = threats["AC04"]
        assert threat.apply(user_to_web)

    def test_DO03(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        threat = threats["DO03"]
        assert threat.apply(user_to_web)

    def test_AC05(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.authenticatesDestination = False
        proc_to_web = Dataflow(process1, web, "Process calls a web API")
        proc_to_web.protocol = "HTTPS"
        proc_to_web.controls.isEncrypted = True
        threat = threats["AC05"]
        assert threat.apply(proc_to_web)

    def test_INP13(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.controls.validatesInput = False
        lambda1.controls.validatesInput = False
        threat = threats["INP13"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_INP14(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        web = Server("Web Server")
        process1.controls.validatesInput = False
        lambda1.controls.validatesInput = False
        web.controls.validatesInput = False
        threat = threats["INP14"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)
        assert threat.apply(web)

    def test_DE03(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.controls.isEncrypted = False
        user_to_web.usesVPN = False
        threat = threats["DE03"]
        assert threat.apply(user_to_web)

    def test_CR03(self):
        process1 = Process("Process1")
        web = Server("Web Server")
        process1.implementsAuthenticationScheme = False
        web.implementsAuthenticationScheme = False
        threat = threats["CR03"]
        assert threat.apply(process1)
        assert threat.apply(web)

    def test_API02(self):
        process1 = Process("Process1")
        lambda1 = Lambda("Lambda1")
        process1.implementsAPI = True
        process1.controls.validatesInput = False
        lambda1.implementsAPI = True
        lambda1.controls.validatesInput = False
        threat = threats["API02"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_HA02(self):
        EE = ExternalEntity("EE")
        EE.hasPhysicalAccess = True
        threat = threats["HA02"]
        assert threat.apply(EE)

    def test_DS03(self):
        web = Server("Web Server")
        web.isHardened = False
        threat = threats["DS03"]
        assert threat.apply(web)

    def test_AC06(self):
        web = Server("Web Server")
        web.isHardened = False
        web.controls.hasAccessControl = False
        threat = threats["AC06"]
        assert threat.apply(web)

    def test_HA03(self):
        web = Server("Web Server")
        web.controls.validatesHeaders = False
        web.controls.encodesOutput = False
        web.isHardened = False
        threat = threats["HA03"]
        assert threat.apply(web)

    def test_SC02(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["SC02"]
        assert threat.apply(web)

    def test_AC07(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        threat = threats["AC07"]
        assert threat.apply(web)

    def test_INP15(self):
        web = Server("Web Server")
        web.protocol = "IMAP"
        web.controls.sanitizesInput = False
        threat = threats["INP15"]
        assert threat.apply(web)

    def test_HA04(self):
        EE = ExternalEntity("ee")
        EE.hasPhysicalAccess = True
        threat = threats["HA04"]
        assert threat.apply(EE)

    def test_SC03(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["SC03"]
        assert threat.apply(web)

    def test_INP16(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        threat = threats["INP16"]
        assert threat.apply(web)

    def test_AA02(self):
        web = Server("Web Server")
        process1 = Process("process")
        web.authenticatesSource = False
        process1.authenticatesSource = False
        threat = threats["AA02"]
        assert threat.apply(web)
        assert threat.apply(process1)

    def test_CR04(self):
        web = Server("Web Server")
        web.usesSessionTokens = True
        web.implementsNonce = False
        threat = threats["CR04"]
        assert threat.apply(web)

    def test_DO04(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        user_to_web.handlesResources = False
        threat = threats["DO04"]
        assert threat.apply(user_to_web)

    def test_DS04(self):
        web = Server("Web Server")
        web.controls.encodesOutput = False
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        threat = threats["DS04"]
        assert threat.apply(web)

    def test_SC04(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.validatesInput = False
        web.controls.encodesOutput = False
        threat = threats["SC04"]
        assert threat.apply(web)

    def test_CR05(self):
        web = Server("Web Server")
        db = Datastore("db")
        web.controls.usesEncryptionAlgorithm != "RSA"
        web.controls.usesEncryptionAlgorithm != "AES"
        db.controls.usesEncryptionAlgorithm != "RSA"
        db.controls.usesEncryptionAlgorithm != "AES"
        threat = threats["CR05"]
        assert threat.apply(web)
        assert threat.apply(db)

    def test_AC08(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        threat = threats["AC08"]
        assert threat.apply(web)

    def test_DS05(self):
        web = Server("Web Server")
        web.usesCache = True
        threat = threats["DS05"]
        assert threat.apply(web)

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

        # Doesn't apply unless dataflow has data defined
        dataflow = create_dataflow(define_data=False)
        assert not threat.apply(dataflow)

        # Data classification equals sink, source and dataflow
        dataflow = create_dataflow()
        assert not threat.apply(dataflow)

        # Data classification is less than sink, source and dataflow
        dataflow = create_dataflow(data=Classification.PUBLIC)
        assert not threat.apply(dataflow)

        # Data classification exceeds source
        dataflow = create_dataflow(source=Classification.PUBLIC)
        assert threat.apply(dataflow)

        # Data classification exceeds sink
        dataflow = create_dataflow(sink=Classification.PUBLIC)
        assert threat.apply(dataflow)

        # Data classification exceeds dataflow
        dataflow = create_dataflow(dataflow=Classification.PUBLIC)
        assert threat.apply(dataflow)

    def test_SC05(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.controls.usesCodeSigning = False
        threat = threats["SC05"]
        assert threat.apply(web)

    def test_INP17(self):
        web = Server("Web Server")
        web.controls.validatesContentType = False
        web.invokesScriptFilters = False
        threat = threats["INP17"]
        assert threat.apply(web)

    def test_AA03(self):
        web = Server("Web Server")
        web.providesIntegrity = False
        web.authenticatesSource = False
        web.controls.usesStrongSessionIdentifiers = False
        threat = threats["AA03"]
        assert threat.apply(web)

    def test_AC09(self):
        web = Server("Web Server")
        web.controls.hasAccessControl = False
        web.authorizesSource = False
        threat = threats["AC09"]
        assert threat.apply(web)

    def test_INP18(self):
        web = Server("Web Server")
        web.controls.sanitizesInput = False
        web.controls.encodesOutput = False
        threat = threats["INP18"]
        assert threat.apply(web)

    def test_CR06(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        user_to_web.usesVPN = False
        user_to_web.implementsAuthenticationScheme = False
        user_to_web.authorizesSource = False
        threat = threats["CR06"]
        assert threat.apply(user_to_web)

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
        assert threat.apply(web)

    def test_CR07(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTP"
        xml = Data(name="user to web data", description="textual", format="XML")
        user_to_web.data = xml
        threat = threats["CR07"]
        assert threat.apply(user_to_web)

    def test_AA04(self):
        web = Server("Web Server")
        web.implementsServerSideValidation = False
        web.providesIntegrity = False
        web.authorizesSource = False
        threat = threats["AA04"]
        assert threat.apply(web)

    def test_CR08(self):
        user = Actor("User")
        web = Server("Web Server")
        web.minTLSVersion = TLSVersion.TLSv11
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        user_to_web.tlsVersion = TLSVersion.SSLv3
        threat = threats["CR08"]
        assert threat.apply(user_to_web)

    def test_INP19(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP19"]
        assert threat.apply(web)

    def test_INP20(self):
        process1 = Process("process")
        process1.disablesiFrames = False
        threat = threats["INP20"]
        assert threat.apply(process1)

    def test_AC11(self):
        web = Server("Web Server")
        web.controls.usesStrongSessionIdentifiers = False
        threat = threats["AC11"]
        assert threat.apply(web)

    def test_INP21(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP21"]
        assert threat.apply(web)

    def test_INP22(self):
        web = Server("Web Server")
        web.usesXMLParser = False
        web.disablesDTD = False
        threat = threats["INP22"]
        assert threat.apply(web)

    def test_INP23(self):
        process1 = Process("Process")
        process1.controls.hasAccessControl = False
        process1.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        threat = threats["INP23"]
        assert threat.apply(process1)

    def test_DO05(self):
        web = Server("Web Server")
        web.controls.validatesInput = False
        web.controls.sanitizesInput = False
        web.usesXMLParser = True
        threat = threats["DO05"]
        assert threat.apply(web)

    def test_AC12(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.controls.implementsPOLP = False
        threat = threats["AC12"]
        assert threat.apply(process1)

    def test_AC13(self):
        process1 = Process("Process")
        process1.hasAccessControl = False
        process1.controls.implementsPOLP = False
        threat = threats["AC13"]
        assert threat.apply(process1)

    def test_AC14(self):
        process1 = Process("Process")
        process1.controls.implementsPOLP = False
        process1.usesEnvironmentVariables = False
        process1.controls.validatesInput = False
        threat = threats["AC14"]
        assert threat.apply(process1)

    def test_INP24(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.checksInputBounds = False
        process1.controls.validatesInput = False
        lambda1.controls.checksInputBounds = False
        lambda1.controls.validatesInput = False
        threat = threats["INP24"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_INP25(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        threat = threats["INP25"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_INP26(self):
        process1 = Process("Process")
        lambda1 = Lambda("lambda")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        lambda1.controls.validatesInput = False
        lambda1.controls.sanitizesInput = False
        threat = threats["INP26"]
        assert threat.apply(process1)
        assert threat.apply(lambda1)

    def test_INP27(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP27"]
        assert threat.apply(process1)

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
        assert threat.apply(process1)
        assert threat.apply(web)

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
        assert threat.apply(process1)
        assert threat.apply(web)

    def test_INP30(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP30"]
        assert threat.apply(process1)

    def test_INP31(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.usesParameterizedInput = False
        threat = threats["INP31"]
        assert threat.apply(process1)

    def test_INP32(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        process1.controls.encodesOutput = False
        threat = threats["INP32"]
        assert threat.apply(process1)

    def test_INP33(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP33"]
        assert threat.apply(process1)

    def test_INP34(self):
        web = Server("web")
        web.controls.checksInputBounds = False
        threat = threats["INP34"]
        assert threat.apply(web)

    def test_INP35(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP35"]
        assert threat.apply(process1)

    def test_DE04(self):
        data = Datastore("DB")
        data.controls.validatesInput = False
        data.controls.implementsPOLP = False
        threat = threats["DE04"]
        assert threat.apply(data)

    def test_AC15(self):
        process1 = Process("Process")
        process1.controls.implementsPOLP = False
        threat = threats["AC15"]
        assert threat.apply(process1)

    def test_INP36(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.controls.encodesHeaders = False
        threat = threats["INP36"]
        assert threat.apply(web)

    def test_INP37(self):
        web = Server("web")
        web.implementsStrictHTTPValidation = False
        web.controls.encodesHeaders = False
        threat = threats["INP37"]
        assert threat.apply(web)

    def test_INP38(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP38"]
        assert threat.apply(process1)

    def test_AC16(self):
        web = Server("web")
        web.controls.usesStrongSessionIdentifiers = False
        web.controls.encryptsCookies = False
        threat = threats["AC16"]
        assert threat.apply(web)

    def test_INP39(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP39"]
        assert threat.apply(process1)

    def test_INP40(self):
        process1 = Process("Process")
        process1.allowsClientSideScripting = True
        process1.controls.sanitizesInput = False
        process1.controls.validatesInput = False
        threat = threats["INP40"]
        assert threat.apply(process1)

    def test_AC17(self):
        web = Server("web")
        web.controls.usesStrongSessionIdentifiers = False
        threat = threats["AC17"]
        assert threat.apply(web)

    def test_AC18(self):
        process1 = Process("Process")
        process1.controls.usesStrongSessionIdentifiers = False
        process1.controls.encryptsCookies = False
        process1.controls.definesConnectionTimeout = False
        threat = threats["AC18"]
        assert threat.apply(process1)

    def test_INP41(self):
        process1 = Process("Process")
        process1.controls.validatesInput = False
        process1.controls.sanitizesInput = False
        threat = threats["INP41"]
        assert threat.apply(process1)

    def test_AC19(self):
        web = Server("web")
        web.usesSessionTokens = True
        web.implementsNonce = False
        threat = threats["AC19"]
        assert threat.apply(web)

    def test_AC20(self):
        process1 = Process("Process")
        process1.controls.definesConnectionTimeout = False
        process1.controls.usesMFA = False
        process1.controls.encryptsSessionData = False
        threat = threats["AC20"]
        assert threat.apply(process1)

    def test_AC21(self):
        process1 = Process("Process")
        process1.implementsCSRFToken = False
        process1.verifySessionIdentifiers = False
        threat = threats["AC21"]
        assert threat.apply(process1)

    def test_AC23(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = Data(
            "password", isCredentials=True, credentialsLife=Lifetime.LONG
        )
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        threat = threats["AC23"]
        assert threat.apply(user_to_web)

    def test_AC24(self):
        user = Actor("User")
        web = Server("Web Server")
        user_to_web = Dataflow(user, web, "User enters comments (*)")
        user_to_web.data = Data(
            "password", isCredentials=True, credentialsLife=Lifetime.HARDCODED
        )
        user_to_web.protocol = "HTTPS"
        user_to_web.controls.isEncrypted = True
        threat = threats["AC24"]
        assert threat.apply(user_to_web)

    def test_DR01(self):
        web = Server("Web Server")
        db = Datastore("Database")
        insert = Dataflow(web, db, "Insert query")
        insert.data = Data("ssn", isPII=True, isStored=True)
        insert.controls.isEncrypted = False
        threat = threats["DR01"]
        assert threat.apply(insert)
