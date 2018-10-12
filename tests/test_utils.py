"""Tests for utils module."""

import json
import unittest

from nvdlib import model
from nvdlib.collection import Collection

from toolkit import utils
from toolkit.preprocessing.handlers import GitHubHandler, StatusError

TEST_REFERENCE_HTTP = 'http://github.com/user/project/blob/master'
TEST_REFERENCE_HTTPS = 'https://github.com/user/project/blob/master'
TEST_REFERENCE_WRONG = 'http://gitlab.com/user/project/blob/master'

TEST_REFERENCE_PATTERNS = {
    TEST_REFERENCE_HTTP: True,
    TEST_REFERENCE_HTTPS: True,
    TEST_REFERENCE_WRONG: False,
}


class TestUtils(unittest.TestCase):
    """Tests for utils module."""

    def test_classproperty(self):
        """Test classproperty decorator."""
        class Sample:
            _secret = 'secret'

            # noinspection PyMethodParameters
            @utils.classproperty
            def secret(cls):
                return cls._secret

        # check readability
        self.assertEqual(Sample.secret, 'secret')

        # check overwrite protection and delete protections
        # # TODO: solve these -- should raise
        # with pytest.raises(AttributeError):
        #     # setter
        #     Sample.secret = 'not_so_secret'
        #     # delete
        #     del Sample.secret

    def test_check_attributes(self):
        """Test utils.check_attributes() function."""
        # should not raise
        ret = utils.check_attributes(['attribute'])

        self.assertIsNone(ret)

        # raises
        with self.assertRaises(TypeError):
            utils.check_attributes('attribute')

    def test_has_reference(self):
        """Test utils.has_reference() function."""
        # Create sample extensible cve object for testing
        cve = type('', (), {})
        cve.references = TEST_REFERENCE_PATTERNS.keys()
        # test urls
        ret = utils.has_reference(cve, url=TEST_REFERENCE_HTTP)
        self.assertTrue(ret)

        for k, v in TEST_REFERENCE_PATTERNS.items():  # pylint: disable=invalid-name
            # test  patterns
            cve.references = [k]
            ret = utils.has_reference(cve, pattern='github')
            self.assertEqual(ret, v)

    def test_get_reference(self):
        """Test utils.get_reference() function."""
        # Create sample extensible cve object for testing
        doc = type('', (), {})
        doc.cve = type('', (), {})

        class _Reference:
            def __init__(self, s): self.url = s  # pylint: disable=multiple-statements

        doc.cve.references = [
            _Reference(k) for k in TEST_REFERENCE_PATTERNS.keys()
        ]

        # test urls
        ret = utils.get_reference(doc, url=TEST_REFERENCE_HTTP)

        self.assertEqual(ret, TEST_REFERENCE_HTTP)

        for k, v in TEST_REFERENCE_PATTERNS.items():  # pylint: disable=invalid-name
            # test  patterns
            doc.cve.references = [_Reference(k)]
            ret = utils.get_reference(doc, pattern='github')

            self.assertEqual(ret, [None, k][v])

    def test_find_(self):
        """Test utils.find_ function."""
        word = 'project'
        # test case insensitive (default)
        sample = 'This document belongs to the Project.'
        found = utils.find_(word, sample)

        self.assertIsNotNone(found)
        self.assertEqual(found.lower(), word.lower())

        # test case sensitive
        sample = 'This document belongs to the Project.'
        found = utils.find_(word, sample, ignore_case=False)

        self.assertIsNone(found)

    def test_nvd_to_dataframe(self):
        """Test NVD feed transformation to pandas.DataFrame object."""
        from pandas import DataFrame

        with open("data/nvdcve-1.0-sample.json", 'r') as f:
            data = json.load(f)['CVE_Items']

        docs = [
            model.Document.from_data(d)
            for d in data
        ]

        collection = Collection(docs)

        df = utils.nvd_to_dataframe(collection)

        self.assertIsNotNone(df)
        self.assertIsInstance(df, DataFrame)

        # test with handler - should not raise despite missing gh token,
        #  but catch anyway
        try:
            df = utils.nvd_to_dataframe(collection, handler=GitHubHandler)
        except StatusError:
            pass

        self.assertIsNotNone(df)
        self.assertIsInstance(df, DataFrame)
