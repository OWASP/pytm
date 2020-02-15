import unittest

from pytm.pytm import TM, Actor, Boundary, _uniq_name


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
