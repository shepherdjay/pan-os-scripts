import os
from unittest import TestCase
from unittest.mock import patch
import panobjectfinder

TEST_FILE_DIR = "testfiles/"


def get_test_path(file):
    path = os.path.join(os.path.dirname(__file__), TEST_FILE_DIR + file)
    return path


class TestFunctionalTest(TestCase):
    @patch('panobjectfinder.retrieve_firewall_configuration_as_xml')
    def test_take_config_and_output_expected_excel_file(self, mock_firewall_config):
        with open(get_test_path('pushed_shared_policy.xml'), 'r') as file:
            mock_firewall_config.return_value = file.read()

        expected_address_groups = {'AllPowerful': ['Google']}
        expected_members = {'Google': 'www.google.com', 'DOC1': '10.1.1.1/32'}

        address_groups, members = panobjectfinder.do_things("test_firewall", "fake-api", ['DOC1', 'AllPowerful'])
        self.assertDictEqual(expected_members, members)
        self.assertDictEqual(expected_address_groups, address_groups)


class TestPanObjectFinderDictionaries(TestCase):
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


class TestPanObjectFinderFinders(TestCase):
    def setUp(self):
        with open(get_test_path('pushed_shared_policy.xml'), mode='r') as file:
            firewall_config = file.read()
        return firewall_config

    def test_find_address(self):
        expected_result = {'DOC1': '10.1.1.1/32', 'DOC2': '10.2.2.2/32'}
        firewall_config = self.setUp()
        objectlist = ['DOC1', 'DOC2']

        result = panobjectfinder.find_address_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)

    def test_find_address_not_there(self):
        expected_result = {}
        firewall_config = self.setUp()
        objectlist = ['nothing']

        result = panobjectfinder.find_address_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)

    def test_find_address_groups(self):
        expected_result = {'Documentation Group': ['DOC1', 'DOC2', 'RANGE', 'Google']}
        firewall_config = self.setUp()
        objectlist = ['Documentation Group']

        result = panobjectfinder.find_address_group_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)

    def test_find_address_groups_not_there(self):
        expected_result = {}
        firewall_config = self.setUp()
        objectlist = ['A Nonexistent Group']

        result = panobjectfinder.find_address_group_objects(firewall_config, objectlist)
        self.assertDictEqual(result, expected_result)

    def test_address_group_and_addresses(self):
        expected_address_groups = {'Documentation Group': ['DOC1', 'DOC2', 'RANGE', 'Google']}
        expected_members = {'DOC1': '10.1.1.1/32', 'DOC2': '10.2.2.2/32', 'RANGE': '10.3.3.0-10.3.3.220',
                            'Google': 'www.google.com'}
        firewall_config = self.setUp()
        objectlist = ['Documentation Group']

        address_groups, members = panobjectfinder.find_group_and_member(firewall_config, objectlist)
        self.assertDictEqual(expected_address_groups, address_groups)
        self.assertDictEqual(expected_members, members)
