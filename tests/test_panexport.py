import datetime
import os
from unittest import TestCase
from unittest.mock import patch

import panexport


def get_path(file):
    path = os.path.join(os.path.dirname(__file__), file)
    return path


class TestHelperFunctions(TestCase):
    def test_pad_digits(self):
        number_to_pad = 5
        expected = "05"

        padded = panexport.pad_to_two_digits(number_to_pad)

        self.assertEqual(padded, expected)

    @patch('panexport.datetime')
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
