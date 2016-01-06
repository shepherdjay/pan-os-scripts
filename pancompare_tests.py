from unittest import TestCase
import pancompare


class PancompareTests(TestCase):
    def test_standard_hex(self):
        self.assertEqual(pancompare.hex_to_ipv6('2607f8b0400a0806000000000000200a'), '2607:f8b0:400a:0806:0000:0000:0000:200a')

