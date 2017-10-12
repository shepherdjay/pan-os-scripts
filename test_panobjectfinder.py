import datetime
import os
import shutil
import tempfile
from unittest import TestCase
from unittest.mock import patch

import xmltodict
import panobjectfinder

TEST_FILE_DIR = "testfiles/"


def get_test_path(file):
    path = os.path.join(os.path.dirname(__file__), TEST_FILE_DIR + file)
    return path


class TestPanObjectFinder(TestCase):
    def test_merge_dictionaries(self):
        dict1 = {'a': 1}
        dict2 = {'b': 2}
        expected_dict = {'a': 1, 'b': 2}

        resulted_dict, errors = panobjectfinder.merge_dictionaries(dict1, dict2)
        self.assertDictEqual(expected_dict, resulted_dict)
        self.assertEqual(errors, [])

    def test_merge_dictionaries_with_errors(self):
        dict1 = {'a': 1}
        dict2 = {'a': 2}
        expected_dict = {}
        expected_errors = ['a']

        resulted_dict, errors = panobjectfinder.merge_dictionaries(dict1, dict2)
        self.assertDictEqual(expected_dict, resulted_dict)
        self.assertEqual(errors, expected_errors)

    def test_merge_dictionaries_different_sizes_and_errors(self):
        dict1 = {'a': 1, 'b': 2}
        dict2 = {'b': 3, 'c': 4, 'd': 5}
        expected_dict = {'a': 1, 'c': 4, 'd': 5}
        expected_errors = ['b']

        resulted_dict, errors = panobjectfinder.merge_dictionaries(dict1, dict2)
        self.assertDictEqual(expected_dict, resulted_dict)
        self.assertEqual(errors, expected_errors)
