from unittest import TestCase

import pancompare


class PancompareTests(TestCase):
    def test_standard_hex(self):
        self.assertEqual(pancompare.hex_to_ipv6('2607f8b0400a0806000000000000200a'),
                         '2607:f8b0:400a:0806:0000:0000:0000:200a')

    def test_rule_match(self):
        script_config = pancompare.Config('testfiles/filters_test.yml')
        with open('testfiles/test_rule.txt', 'r') as file:
            test_rule = file.read()
        filters = script_config.rule_filters
        self.assertTrue(type(pancompare.filter_dataplane_rules(test_rule, filters) is None))
