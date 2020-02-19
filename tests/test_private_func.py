import sys
sys.path.append("..")
import unittest

from pytm.pytm import _uniq_name, Actor, Boundary, Dataflow, Datastore, Server, TM


class TestUniqueNames(unittest.TestCase):
    def test_duplicate_boundary_names_have_different_unique_names(self):
        object_1 = Boundary("foo")
        object_2 = Boundary("foo")

        object_1_uniq_name = _uniq_name(object_1.name, object_1.uuid)
        object_2_uniq_name = _uniq_name(object_2.name, object_2.uuid)

        self.assertNotEqual(object_1_uniq_name, object_2_uniq_name)


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
        self.assertNotEqual(len(TM._BagOfThreats), 0)
        with self.assertRaises(FileNotFoundError):
            tm.threatsFile = "threats.json"

        with self.assertRaises(FileNotFoundError):
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

        tm.check()

        self.assertEqual(http_req.response, http_resp)
        self.assertIs(http_resp.isResponse, True)

        self.assertIs(query_resp.isResponse, True)
        self.assertEqual(query_resp.responseTo, query)
        self.assertEqual(query.response, query_resp)

        self.assertIsNone(insert.response)
        self.assertIs(insert.isResponse, False)

    def test_defaults(self):
        tm = TM("TM")
        user = Actor("User", data="HTTP")
        server = Server(
            "Server", port=443, protocol="HTTPS", isEncrypted=True, data="JSON"
        )
        db = Datastore(
            "PostgreSQL",
            isSQL=True,
            port=5432,
            protocol="PostgreSQL",
            isEncrypted=False,
            data="SQL resp",
        )

        req_get = Dataflow(user, server, "HTTP GET")
        query = Dataflow(server, db, "Query", data="SQL")
        result = Dataflow(db, server, "Results", isResponse=True)
        resp_get = Dataflow(server, user, "HTTP Response", isResponse=True)

        req_post = Dataflow(user, server, "HTTP POST", data="JSON")
        resp_post = Dataflow(server, user, "HTTP Response", isResponse=True)

        tm.check()

        self.assertEqual(req_get.srcPort, -1)
        self.assertEqual(req_get.dstPort, server.port)
        self.assertEqual(req_get.isEncrypted, server.isEncrypted)
        self.assertEqual(req_get.protocol, server.protocol)
        self.assertEqual(req_get.data, user.data)

        self.assertEqual(query.srcPort, -1)
        self.assertEqual(query.dstPort, db.port)
        self.assertEqual(query.isEncrypted, db.isEncrypted)
        self.assertEqual(query.protocol, db.protocol)
        self.assertNotEqual(query.data, server.data)

        self.assertEqual(result.srcPort, db.port)
        self.assertEqual(result.dstPort, -1)
        self.assertEqual(result.isEncrypted, db.isEncrypted)
        self.assertEqual(result.protocol, db.protocol)
        self.assertEqual(result.data, db.data)

        self.assertEqual(resp_get.srcPort, server.port)
        self.assertEqual(resp_get.dstPort, -1)
        self.assertEqual(resp_get.isEncrypted, server.isEncrypted)
        self.assertEqual(resp_get.protocol, server.protocol)
        self.assertEqual(resp_get.data, server.data)

        self.assertEqual(req_post.srcPort, -1)
        self.assertEqual(req_post.dstPort, server.port)
        self.assertEqual(req_post.isEncrypted, server.isEncrypted)
        self.assertEqual(req_post.protocol, server.protocol)
        self.assertNotEqual(req_post.data, user.data)

        self.assertEqual(resp_post.srcPort, server.port)
        self.assertEqual(resp_post.dstPort, -1)
        self.assertEqual(resp_post.isEncrypted, server.isEncrypted)
        self.assertEqual(resp_post.protocol, server.protocol)
        self.assertEqual(resp_post.data, server.data)
