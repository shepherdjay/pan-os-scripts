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


class TestFunctionalTest(TestCase):
    @patch('panobjectfinder.retrieve_firewall_configuration')
    def test_take_config_and_output_expected_excel_file(self, mock_config):
        with open(get_test_path('pushed_shared_policy.xml'), 'r') as file:
            mock_config.returnvalue = file.read()
        self.fail("Working on test")


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

    def test_find_address(self):
        expected_result = {'DOC1': '10.1.1.1/32', 'DOC2': '10.2.2.2/32'}
        with open(get_test_path('pushed_shared_policy.xml'), mode='r') as file:
            firewall_config = file.read()
        objectlist = ['DOC1', 'DOC2']

        result = panobjectfinder.find_address_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)

    def test_find_address_groups(self):
        expected_result = {'Documentation Group': ['DOC1', 'DOC2', 'RANGE', 'Google']}
        with open(get_test_path('pushed_shared_policy.xml'), mode='r') as file:
            firewall_config = file.read()
        objectlist = ['Documentation Group']

        result = panobjectfinder.find_address_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)
