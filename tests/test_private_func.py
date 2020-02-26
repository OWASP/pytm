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
