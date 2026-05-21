import random
import pytest

from pytm.pytm import (
    TM,
    Actor,
    Assumption,
    Boundary,
    Data,
    Dataflow,
    Datastore,
    DatastoreType,
    Finding,
    Process,
    Server,
    Threat,
    UIError,
    encode_threat_data,
)

class TestUniqueNames:
    def test_duplicate_boundary_names_have_different_unique_names(self):
        random.seed(0)
        object_1 = Boundary("foo")
        object_2 = Boundary("foo")

        object_1_uniq_name = object_1._uniq_name()
        object_2_uniq_name = object_2._uniq_name()

        assert object_1_uniq_name != object_2_uniq_name
        assert object_1_uniq_name == "boundary_foo_acf3059e70"
        assert object_2_uniq_name == "boundary_foo_88f2d9c06f"

class TestAttributes:
    def test_write_once(self):
        user = Actor("User")
        with pytest.raises(ValueError):
            user.name = "Computer"

    def test_kwargs(self):
        user = Actor("User", isAdmin=True)
        assert user.isAdmin is True
        user = Actor("User")
        assert user.isAdmin is False
        user.isAdmin = True
        assert user.isAdmin is True

    def test_load_threats(self):
        tm = TM("TM")
        assert len(TM._threats) != 0
        with pytest.raises(UIError):
            tm.threatsFile = "threats.json"
        with pytest.raises(UIError):
            TM("TM", threatsFile="threats.json")

    def test_responses(self):
        tm = TM("my test tm", description="aa", isOrdered=True)
        user = Actor("User")
        web = Server("Web Server")
        db = Datastore("SQL Database")
        http_req = Dataflow(user, web, "http req")
        insert = Dataflow(web, db, "insert data")
        query = Dataflow(web, db, "query")
        query_resp = Dataflow(db, web, "query results", responseTo=query)
        http_resp = Dataflow(web, user, "http resp")
        http_resp.responseTo = http_req
        assert tm.check()
        assert http_req.response == http_resp
        assert http_resp.isResponse is True
        assert query_resp.isResponse is True
        assert query_resp.responseTo == query
        assert query.response == query_resp
        assert insert.response is None
        assert insert.isResponse is False

    def test_defaults(self):
        tm = TM("TM")
        user_data = Data("HTTP")
        user = Actor("User", data=user_data)
        user.controls.authenticatesDestination = True
        json_data = Data("JSON")
        server = Server(
            "Server", port=443, protocol="HTTPS", isEncrypted=True, data=json_data
        )
        sql_resp = Data("SQL resp")
        db = Datastore(
            "PostgreSQL",
            port=5432,
            protocol="PostgreSQL",
            data=sql_resp,
        )
        db.controls.isEncrypted = False
        db.type = DatastoreType.SQL
        worker = Process("Task queue worker")
        req_get_data = Data("HTTP GET")
        req_get = Dataflow(user, server, "HTTP GET", data=req_get_data)
        server_query_data = Data("SQL")
        server_query = Dataflow(server, db, "Query", data=server_query_data)
        result_data = Data("Results")
        result = Dataflow(db, server, "Results", data=result_data, isResponse=True)
        resp_get_data = Data("HTTP Response")
        resp_get = Dataflow(server, user, "HTTP Response", data=resp_get_data, isResponse=True)
        test_assumption = Assumption("test assumption")
        resp_get.assumptions = [test_assumption]
        req_post_data = Data("JSON")
        req_post = Dataflow(user, server, "HTTP POST", data=req_post_data)
        resp_post = Dataflow(server, user, "HTTP Response", isResponse=True)
        test_assumption_exclude = Assumption("test assumption", exclude=["ABCD", "BCDE"])
        resp_post.assumptions = [test_assumption_exclude]
        sql_data = Data("SQL")
        worker_query = Dataflow(worker, db, "Query", data=sql_data)
        Dataflow(db, worker, "Results", isResponse=True)
        cookie = Data("Auth Cookie", carriedBy=[req_get, req_post])
        assert tm.check()
        assert req_get.srcPort == -1
        assert req_get.dstPort == server.port
        assert req_get.controls.isEncrypted == server.controls.isEncrypted
        assert req_get.controls.authenticatesDestination == user.controls.authenticatesDestination
        assert req_get.protocol == server.protocol
        assert user.data.issubset(req_get.data)
        assert server_query.srcPort == -1
        assert server_query.dstPort == db.port
        assert server_query.controls.isEncrypted == db.controls.isEncrypted
        assert server_query.controls.authenticatesDestination == server.controls.authenticatesDestination
        assert server_query.protocol == db.protocol
        assert server.data.issubset(server_query.data)
        assert result.srcPort == db.port
        assert result.dstPort == -1
        assert result.controls.isEncrypted == db.controls.isEncrypted
        assert result.controls.authenticatesDestination is False
        assert result.protocol == db.protocol
        assert db.data.issubset(result.data)
        assert db.assumptions == []
        assert resp_get.srcPort == server.port
        assert resp_get.dstPort == -1
        assert resp_get.controls.isEncrypted == server.controls.isEncrypted
        assert resp_get.controls.authenticatesDestination is False
        assert resp_get.protocol == server.protocol
        assert server.data.issubset(resp_get.data)
        assert resp_get.assumptions == [test_assumption]
        assert req_post.srcPort == -1
        assert req_post.dstPort == server.port
        assert req_post.controls.isEncrypted == server.controls.isEncrypted
        assert req_post.controls.authenticatesDestination == user.controls.authenticatesDestination
        assert req_post.protocol == server.protocol
        assert user.data.issubset(req_post.data)
        assert resp_post.srcPort == server.port
        assert resp_post.dstPort == -1
        assert resp_post.controls.isEncrypted == server.controls.isEncrypted
        assert resp_post.controls.authenticatesDestination is False
        assert resp_post.protocol == server.protocol
        assert server.data.issubset(resp_post.data)
        assert resp_post.assumptions == [test_assumption_exclude]
        assert resp_post.assumptions[0].exclude == set(test_assumption_exclude.exclude)
        assert server.inputs == [req_get, req_post]
        assert server.outputs == [server_query]
        assert worker.inputs == []
        assert worker.outputs == [worker_query]
        assert cookie.carriedBy == [req_get, req_post]
        assert set(cookie.processedBy) == set([user, server])
        assert cookie in req_get.data
        assert set([d.name for d in req_post.data]) == set([cookie.name, "HTTP", "JSON"])

class TestMethod:
    def test_defaults(self):
        tm = TM("my test tm", description="aa", isOrdered=True)
        internet = Boundary("Internet")
        cloud = Boundary("Cloud")
        user = Actor("User", inBoundary=internet)
        server = Server("Server")
        db = Datastore("DB", inBoundary=cloud)
        db.type = DatastoreType.SQL
        func = Datastore("Lambda function", inBoundary=cloud)
        request = Dataflow(user, server, "request")
        response = Dataflow(server, user, "response", isResponse=True)
        user_query = Dataflow(user, db, "user query")
        server_query = Dataflow(server, db, "server query")
        func_query = Dataflow(func, db, "func query")
        default_target = ["Actor", "Boundary", "Dataflow", "Datastore", "Server"]
        testCases = [
            {"target": server, "condition": "target.oneOf(Server, Datastore)"},
            {"target": server, "condition": "not target.oneOf(Actor, Dataflow)"},
            {"target": request, "condition": "target.crosses(Boundary)"},
            {"target": user_query, "condition": "target.crosses(Boundary)"},
            {"target": server_query, "condition": "target.crosses(Boundary)"},
            {"target": func_query, "condition": "not target.crosses(Boundary)"},
            {"target": func_query, "condition": "not target.enters(Boundary)"},
            {"target": func_query, "condition": "not target.exits(Boundary)"},
            {"target": request, "condition": "not target.enters(Boundary)"},
            {"target": request, "condition": "target.exits(Boundary)"},
            {"target": response, "condition": "target.enters(Boundary)"},
            {"target": response, "condition": "not target.exits(Boundary)"},
            {"target": user, "condition": "target.inside(Boundary)"},
            {"target": func, "condition": "not any(target.inputs)"},
            {
                "target": server,
                "condition": "any(f.sink.oneOf(Datastore) and f.sink.type == DatastoreType.SQL "
                "for f in target.outputs)",
            },
        ]
        assert tm.check()
        for case in testCases:
            t = Threat(SID="", target=default_target, condition=case["condition"])
            assert t.apply(case["target"]), f"Failed to match {case['target']} against {case['condition']}"

class TestFunction:
    def test_encode_threat_data(self):
        findings = [
            Finding(
                description="A test description",
                severity="High",
                id="1",
                threat_id="INP01",
                cvss="9.876",
                response="A test response",
            ),
            Finding(
                description="An escape test <script>",
                severity="Medium",
                id="2",
                threat_id="INP02",
                cvss="1.234",
                response="A test response",
                assumption=Assumption("Test Assumption", exclude=["INP02"]),
            )
        ]
        encoded_findings = encode_threat_data(findings)
        assert len(encoded_findings) == 2
        assert encoded_findings[0].description == "A test description"
        assert encoded_findings[0].severity == "High"
        assert encoded_findings[0].id == "1"
        assert encoded_findings[0].threat_id == "INP01"
        assert encoded_findings[0].cvss == "9.876"
        assert encoded_findings[0].response == "A test response"
        assert encoded_findings[1].description == "An escape test &lt;script&gt;"
        assert encoded_findings[1].severity == "Medium"
        assert encoded_findings[1].id == "2"
        assert encoded_findings[1].threat_id == "INP02"
        assert encoded_findings[1].cvss == "1.234"
        assert encoded_findings[1].response == "A test response"
