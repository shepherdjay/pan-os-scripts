import os
from unittest import TestCase

import netaddr

import pancompare

TEST_FILE_DIR = "testfiles/"


def get_path(file):
    path = os.path.join(os.path.dirname(__file__), TEST_FILE_DIR + file)
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
        script_config = pancompare.Config(get_path('filters_test.yml'))
        with open(get_path('raw_dataplane_nomatch.txt'), 'r') as file:
            test_rule = file.read()
        filters = script_config.rule_filters

        self.assertTrue(type(pancompare.filter_dataplane_rules(test_rule, filters) is None))

    def test_map_to_address(self):
        host = pancompare.map_to_address("192.168.1.1")
        network = pancompare.map_to_address("192.168.0.1/32")

        self.assertIsInstance(host, netaddr.IPAddress)
        self.assertIsInstance(network, netaddr.IPNetwork)

    def test_empty_filter(self):
        """
        This test is for Issue 16 in which the filters are not actually optional.
        :return: 
        """
        script_config = pancompare.Config(get_path('filters_test_issue16.yml'))
        with open(get_path('raw_dataplane_nomatch.txt'), 'r') as file:
            test_rule = file.read()
        filters = script_config.rule_filters
        expected_rule_list = {'Test Dataplane', 'IPV6 New Version'}

        filtered_rule_list = pancompare.filter_dataplane_rules(test_rule, filters)

        self.assertEqual(expected_rule_list, filtered_rule_list)

    def test_class_method_properly_formatted_filters_equal(self):
        """
        Verify that post Issue16 fix a fully provided filter is the same as sanatized
        :return:
        """
        script_config = pancompare.Config(get_path('filters_test.yml'))
        self.assertEqual(script_config.rule_filters, script_config.rule_filters_old)
