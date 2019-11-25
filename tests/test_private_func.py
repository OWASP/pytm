import sys
sys.path.append("..")
import unittest

from pytm.pytm import _uniq_name, Boundary


class TestUniqueNames(unittest.TestCase):
    def test_duplicate_boundary_names_have_different_unique_names(self):
        object_1 = Boundary("foo")
        object_2 = Boundary("foo")

        object_1_uniq_name = _uniq_name(object_1.name, object_1.uuid)
        object_2_uniq_name = _uniq_name(object_2.name, object_2.uuid)

        self.assertNotEqual(object_1_uniq_name, object_2_uniq_name)
