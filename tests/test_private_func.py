import random
import unittest

from pytm.pytm import (
    TM,
    Actor,
    Boundary,
    Data,
    Dataflow,
    Datastore,
    DatastoreType,
    Process,
    Server,
    Threat,
    UIError,
)


class TestUniqueNames(unittest.TestCase):
    def test_duplicate_boundary_names_have_different_unique_names(self):
        random.seed(0)
        object_1 = Boundary("foo")
        object_2 = Boundary("foo")

        object_1_uniq_name = object_1._uniq_name()
        object_2_uniq_name = object_2._uniq_name()

        self.assertNotEqual(object_1_uniq_name, object_2_uniq_name)
        self.assertEqual(object_1_uniq_name, "boundary_foo_acf3059e70")
        self.assertEqual(object_2_uniq_name, "boundary_foo_88f2d9c06f")


class TestAttributes(unittest.TestCase):
    def test_write_once(self):
        user = Actor("User")
        with self.assertRaises(ValueError):
            user.name = "Computer"

    def test_kwargs(self):
        user = Actor("User", isAdmin=True)
        self.assertEqual(user.isAdmin, True)
        user = Actor("User")
        self.assertEqual(user.isAdmin, False)
        user.isAdmin = True
        self.assertEqual(user.isAdmin, True)

    def test_load_threats(self):
        tm = TM("TM")
        self.assertNotEqual(len(TM._threats), 0)
        with self.assertRaises(UIError):
            tm.threatsFile = "threats.json"

        with self.assertRaises(UIError):
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

        self.assertTrue(tm.check())

        self.assertEqual(http_req.response, http_resp)
        self.assertIs(http_resp.isResponse, True)

        self.assertIs(query_resp.isResponse, True)
        self.assertEqual(query_resp.responseTo, query)
        self.assertEqual(query.response, query_resp)

        self.assertIsNone(insert.response)
        self.assertIs(insert.isResponse, False)

    def test_defaults(self):
        tm = TM("TM")
        user_data = Data("HTTP")
        user = Actor("User", data=user_data)
        user.controls.authenticatesDestination=True

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
        db.controls.isEncrypted=False
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

        req_post_data = Data("JSON")
        req_post = Dataflow(user, server, "HTTP POST", data=req_post_data)
        resp_post = Dataflow(server, user, "HTTP Response", isResponse=True)
        
        sql_data = Data("SQL")
        worker_query = Dataflow(worker, db, "Query", data=sql_data)
        Dataflow(db, worker, "Results", isResponse=True)

        cookie = Data("Auth Cookie", carriedBy=[req_get, req_post])

        self.assertTrue(tm.check())

        self.assertEqual(req_get.srcPort, -1)
        self.assertEqual(req_get.dstPort, server.port)
        self.assertEqual(req_get.controls.isEncrypted, server.controls.isEncrypted)
        self.assertEqual(
            req_get.controls.authenticatesDestination, user.controls.authenticatesDestination
        )
        self.assertEqual(req_get.protocol, server.protocol)
        self.assertTrue(user.data.issubset(req_get.data))

        self.assertEqual(server_query.srcPort, -1)
        self.assertEqual(server_query.dstPort, db.port)
        self.assertEqual(server_query.controls.isEncrypted, db.controls.isEncrypted)
        self.assertEqual(
            server_query.controls.authenticatesDestination, server.controls.authenticatesDestination
        )
        self.assertEqual(server_query.protocol, db.protocol)
        self.assertTrue(server.data.issubset(server_query.data))

        self.assertEqual(result.srcPort, db.port)
        self.assertEqual(result.dstPort, -1)
        self.assertEqual(result.controls.isEncrypted, db.controls.isEncrypted)
        self.assertEqual(result.controls.authenticatesDestination, False)
        self.assertEqual(result.protocol, db.protocol)
        self.assertTrue(db.data.issubset(result.data))

        self.assertEqual(resp_get.srcPort, server.port)
        self.assertEqual(resp_get.dstPort, -1)
        self.assertEqual(resp_get.controls.isEncrypted, server.controls.isEncrypted)
        self.assertEqual(resp_get.controls.authenticatesDestination, False)
        self.assertEqual(resp_get.protocol, server.protocol)
        self.assertTrue(server.data.issubset(resp_get.data))

        self.assertEqual(req_post.srcPort, -1)
        self.assertEqual(req_post.dstPort, server.port)
        self.assertEqual(req_post.controls.isEncrypted, server.controls.isEncrypted)
        self.assertEqual(
            req_post.controls.authenticatesDestination, user.controls.authenticatesDestination
        )
        self.assertEqual(req_post.protocol, server.protocol)
        self.assertTrue(user.data.issubset(req_post.data))

        self.assertEqual(resp_post.srcPort, server.port)
        self.assertEqual(resp_post.dstPort, -1)
        self.assertEqual(resp_post.controls.isEncrypted, server.controls.isEncrypted)
        self.assertEqual(resp_post.controls.authenticatesDestination, False)
        self.assertEqual(resp_post.protocol, server.protocol)
        self.assertTrue(server.data.issubset(resp_post.data))

        self.assertListEqual(server.inputs, [req_get, req_post])
        self.assertListEqual(server.outputs, [server_query])
        self.assertListEqual(worker.inputs, [])
        self.assertListEqual(worker.outputs, [worker_query])

        self.assertListEqual(cookie.carriedBy, [req_get, req_post])
        self.assertSetEqual(set(cookie.processedBy), set([user, server]))
        self.assertIn(cookie, req_get.data)
        self.assertSetEqual(
            set([d.name for d in req_post.data]), set([cookie.name, "HTTP", "JSON"])
        )


class TestMethod(unittest.TestCase):
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

        self.assertTrue(tm.check())

        for case in testCases:
            t = Threat(SID="", target=default_target, condition=case["condition"])
            self.assertTrue(
                t.apply(case["target"]),
                "Failed to match {} against {}".format(
                    case["target"],
                    case["condition"],
                ),
            )
