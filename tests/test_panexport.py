import datetime
import os
import shutil
import tempfile
from unittest import TestCase
from unittest.mock import patch
from collections import OrderedDict

import xmltodict
from pandas import read_excel

from panosscripts import panexport

TEST_FILE_DIR = "testfiles/"


def get_test_path(file):
    path = os.path.join(os.path.dirname(__file__), TEST_FILE_DIR + file)
    return path


class TestPanExport(TestCase):
    def test_pad_digits(self):
        number_to_pad = 5
        expected = "05"

        padded = panexport.pad_to_two_digits(number_to_pad)

        self.assertEqual(padded, expected)

    @patch('panosscripts.panexport.datetime')
    def test_filename_format(self, mock_now):
        firewall = "test_firewall"
        expected_filename = "2016-01-01-{}-combined-rules.xlsx".format(firewall)
        mock_now.now.return_value = datetime.date(year=2016, month=1, day=1)

        filename = panexport.get_filename(firewall)

        self.assertEqual(filename, expected_filename)

    def test_safe_get_simple(self):
        key = "key"
        test_dict = {
            key: 0
        }

        output_nokey = panexport.safeget(test_dict, "nokey")
        output_key = panexport.safeget(test_dict, "key")

        self.assertEqual(output_nokey, [])
        self.assertEqual(output_key, [0])

    def test_safe_get_nested(self):
        key1 = "key1"
        key2 = "key2"
        nested_dict = {
            key1: {
                key2: "success"
            }
        }

        output_nokey = panexport.safeget(nested_dict, "key1", "nokey")
        output_key = panexport.safeget(nested_dict, "key1", "key2")

        self.assertEqual(output_nokey, [])
        self.assertEqual(output_key, ["success"])


class FileTests(TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def doCleanups(self):
        shutil.rmtree(self.tmp_dir)

    def excel_to_dictionary(self, filepath):
        """
        Uses pandas to convert an excel sheet to a python dictionary.
        :param filepath: Path to excel file
        :return: Python Dictionary
        """
        data = read_excel(filepath)
        return [OrderedDict(row) for i, row in data.iterrows()]

    def test_write_to_excel(self):
        self.maxDiff = None
        test_filename = os.path.join(self.tmp_dir, "test_write_to_excel.xlsx")
        with open(get_test_path('test_rules.xml'), mode='r') as file:
            example_rules = xmltodict.parse(file.read())['rules']['entry']

        panexport.write_to_excel(rule_list=example_rules,
                                 filename=test_filename,
                                 headers_to_remove=panexport.HEADERS_REMOVE,
                                 preferred_header_order=panexport.HEADERS_ORDER,
                                 default_map=panexport.HEADERS_DEFAULT_MAP)

        golden_file = self.excel_to_dictionary(get_test_path("panexport_golden_output.xlsx"))
        test_file = self.excel_to_dictionary(test_filename)

        self.assertEqual(golden_file, test_file)
