import os
from unittest import TestCase

import pancompare


def get_path(file):
    path = os.path.join(os.path.dirname(__file__), file)
    return path


class PancompareTests(TestCase):
    def test_standard_hex(self):
        self.assertEqual(pancompare.hex_to_ipv6('2607f8b0400a0806000000000000200a'),
                         '2607:f8b0:400a:0806:0000:0000:0000:200a')

    def test_dataplane_no_match(self):
        """
        This test processes the dataplane no match file which should contain no rules that match the
        included filters test file.
        :return:
        """
        script_config = pancompare.Config(get_path('testfiles/filters_test.yml'))
        with open(get_path('testfiles/raw_dataplane_nomatch.txt'), 'r') as file:
            test_rule = file.read()
        filters = script_config.rule_filters
        self.assertTrue(type(pancompare.filter_dataplane_rules(test_rule, filters) is None))
