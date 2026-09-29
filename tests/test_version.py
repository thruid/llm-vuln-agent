import unittest

from vulnerability.version import compare, version_in_range


class TestCompare(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(compare("9.0.50", "9.0.50"), 0)

    def test_less(self):
        self.assertLess(compare("9.0.50", "9.0.54"), 0)

    def test_greater(self):
        self.assertGreater(compare("10.0.0", "9.0.50"), 0)

    def test_suffix(self):
        self.assertLess(compare("2.4.41", "2.4.41p1"), 0)


class TestRange(unittest.TestCase):
    def test_lt(self):
        self.assertTrue(version_in_range("9.0.50", "<9.0.54"))

    def test_ge_false(self):
        self.assertFalse(version_in_range("9.0.50", ">=9.0.54"))

    def test_dash_inclusive(self):
        self.assertTrue(version_in_range("9.0.20", "9.0.0 - 9.0.53"))
        self.assertFalse(version_in_range("9.0.54", "9.0.0 - 9.0.53"))

    def test_compound_and(self):
        self.assertTrue(version_in_range("9.0.50", ">=8.0.0 <9.0.51"))
        self.assertFalse(version_in_range("9.0.52", ">=8.0.0 <9.0.51"))

    def test_star(self):
        self.assertTrue(version_in_range("1.2.3", "*"))

    def test_comma_or(self):
        self.assertTrue(version_in_range("2.3.20", "2.3.5 - 2.3.31, 2.5 - 2.5.10"))

    def test_list_input(self):
        self.assertTrue(version_in_range("9.0.50", ["<9.0.54"]))


if __name__ == "__main__":
    unittest.main()
