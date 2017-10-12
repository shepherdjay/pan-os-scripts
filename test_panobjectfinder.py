import datetime
import os
import shutil
import tempfile
from unittest import TestCase
from unittest.mock import patch

import xmltodict

TEST_FILE_DIR = "testfiles/"


def get_test_path(file):
    path = os.path.join(os.path.dirname(__file__), TEST_FILE_DIR + file)
    return path


class TestPanObjectFinder(TestCase):
    def test_merge_dictionaries(self):
        return True

    def test_merge_dictionaries_with_errors(self):
        return True
