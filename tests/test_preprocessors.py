"""Tests for preprocessors module."""

import re
import typing
import unittest

from collections import namedtuple
from nltk import WordNetLemmatizer, SnowballStemmer
from sklearn.pipeline import Pipeline

from toolkit.preprocessing import \
    NVDFeedPreprocessor, \
    LabelPreprocessor,\
    NLTKPreprocessor

from toolkit.transformers import Hook
from toolkit.config import GITHUB_BASE_URL
from toolkit.utils import clear


# ----- TEST DATA -----

TEST_SENT = "Test sentence, better not to worry too much."
TEST_DATA = [
    "Test sentence, better not to worry too much.",
    "Test sentence, better not to worry too much.",
]

TEST_REPOSITORY = GITHUB_BASE_URL + 'python/cpython'

# create TestCVE type
TestCVE = type('TestCVE', (), {})

# set up cve attributes and their values
TEST_CVE_ATTR = ['cve_id', 'references', 'description']
TEST_CVE_ATTR_VALS = ('cve_id', [TEST_REPOSITORY], 'description')

# assign attributes
_ = [
    setattr(TestCVE, attr, val)
    for attr, val in zip(TEST_CVE_ATTR, TEST_CVE_ATTR_VALS)
]

TEST_CVE = TestCVE()

# -----


class TestNLTKPreprocessor(unittest.TestCase):
    """Tests for NLTKPreprocessor class."""

    def test_init(self):
        """Test NLTKPreprocessor initialization."""
        # default parameters
        prep = NLTKPreprocessor()

        self.assertIsInstance(prep, NLTKPreprocessor)

        # custom parameters
        prep = NLTKPreprocessor(
            stopwords=True,
            lower=True
        )

        self.assertIsNotNone(prep._stopwords)  # pylint: disable=protected-access
        self.assertIsInstance(prep, NLTKPreprocessor)

        # raises
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _ = NLTKPreprocessor(
                feed_attributes='attribute'
            )

        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _ = NLTKPreprocessor(
                output_attributes='attribute'
            )

    def test_tokenize(self):
        """Test NLTKPreprocessor `tokenize` method."""
        prep = NLTKPreprocessor(
            stopwords=True,
            lower=True
        )
        result = prep.tokenize(TEST_SENT)
        self.assertIsInstance(result, typing.Iterable)

        # check that punctuation has been gotten rid of
        self.assertFalse(any(re.match(u"[,.]", t[0][0]) for t in result))
        # check that the list contains elements of same type
        self.assertTrue(all(isinstance(t[0], type(t[1])) for t in result))

        # tag_correction
        prep = NLTKPreprocessor(
            tag_dict={'NUM': 'BUM'}
        )

        result_corrected = prep.tokenize(TEST_SENT)
        self.assertTrue(all([
            c[1] == 'BUM' for c, r in zip(result_corrected, result)
            if r[1] == 'NUM'
        ]))

        # stemmer and lemmatizer
        prep = NLTKPreprocessor(
            lemmatizer=WordNetLemmatizer(),
            stemmer=SnowballStemmer(language='english')
        )

        result = prep.tokenize(TEST_SENT)
        self.assertIsInstance(result, typing.Iterable)

        # check that punctuation has been gotten rid of
        self.assertFalse(any(re.match(u"[,.]", t[0][0]) for t in result))
        # check that the list contains elements of same type
        self.assertTrue(all(isinstance(t[0], type(t[1])) for t in result))

        # raises
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _ = prep.tokenize(['stream'])

    def test_fit_transform(self):
        """Test NLTKPreprocessor `fit_transform` method."""
        # custom parameters
        prep = NLTKPreprocessor(
            stopwords=True,
            lower=True
        )
        # test without feed argument and simple data
        transform = prep.fit_transform(X=TEST_DATA)

        self.assertTrue(len(transform), len(TEST_DATA))
        # check that the array is not empty
        self.assertTrue(any(transform))

        # create series to simulate output of LabelPreprocessor and make
        # use of `feed_attributes` argument
        Series = namedtuple('Series', 'description label')
        data = [
            Series(d, 'label')
            for d in TEST_DATA
        ]

        transform = prep.fit_transform(X=data, feed_attributes=['description'])

        self.assertTrue(len(transform), len(data))
        # check that the array is not empty
        self.assertTrue(any(transform))

        # perform transformation and output labels as well
        transform = prep.fit_transform(X=data,
                                       feed_attributes=['description'],
                                       output_attributes=['label'])

        self.assertTrue(len(transform), len(data))
        # check that the array is not empty
        self.assertTrue(any(transform))

        # raises
        with self.assertRaises(TypeError):
            _ = prep.fit_transform(
                X=data,
                feed_attributes='attribute'
            )

        with self.assertRaises(TypeError):
            _ = prep.fit_transform(
                X=data,
                output_attributes='attribute'
            )

    def test_inverse_transform(self):
        """Test NLTKPreprocessor `inverse_transform` method."""
        prep = NLTKPreprocessor()

        # test without feed argument and simple data
        transform = prep.fit_transform(X=TEST_DATA)

        inversed = NLTKPreprocessor.inverse_transform(transform)

        self.assertTrue(len(inversed), len(transform))
        # check that the array is not empty
        self.assertTrue(any(inversed))

    def test_pipeline(self):
        """Test NLTKPreprocessor as a single pipeline unit."""
        # should not raise, since NLTKPreprocessor does implement `fit `
        # and `transform` methods
        _ = Pipeline([
            ('preprocessor', NLTKPreprocessor)
        ])


class TestNVDFeedPreprocessor(unittest.TestCase):
    """Tests for NVDFeedPreprocessor class."""

    def test_init(self):
        """Test NVDFeedPreprocessor `__init__` method."""
        # default parameters
        prep = NVDFeedPreprocessor()

        self.assertIsInstance(prep, NVDFeedPreprocessor)

        # custom parameters
        prep = NVDFeedPreprocessor(
            attributes=['cve_id']
        )
        self.assertIsInstance(prep, NVDFeedPreprocessor)

    def test_fit_transform(self):
        """Test NVDFeedPreprocessor `fit_transform` method."""
        # default parameters
        prep = NVDFeedPreprocessor()
        result, = prep.fit_transform(X=[TEST_CVE])

        # result should return default handler attributes
        self.assertEqual(result.user, 'python')
        self.assertEqual(result.project, 'cpython')
        self.assertEqual(result.cve_id, 'cve_id')
        self.assertIsNotNone(result.repository)
        self.assertIsNotNone(result.references)

        # custom parameters
        prep = NVDFeedPreprocessor(
            attributes=TEST_CVE_ATTR  # only extract cve_id
        )
        result, = prep.fit_transform(X=[TEST_CVE])

        self.assertEqual(result.user, 'python')
        self.assertEqual(result.project, 'cpython')
        self.assertEqual(result.cve_id, 'cve_id')
        self.assertIsNotNone(result.repository)
        self.assertIsNotNone(result.references)
        # plus description and CVE_ATTR_VALS
        self.assertEqual(result[-len(TEST_CVE_ATTR):], TEST_CVE_ATTR_VALS)
        self.assertEqual(result.description, 'description')

    def test_filter_by_handler(self):
        """Test NVDFeedPreprocessor `_filter_by_handler` method."""
        prep = NVDFeedPreprocessor()

        # make another cve
        cve_without_ref = TestCVE()
        # add reasonable reference
        cve_without_ref.references = 'non-matching-reference'
        cves = [cve_without_ref]
        cves = prep._filter_by_handler(cves)  # pylint: disable=protected-access

        # check that cves list is empty
        self.assertFalse(any(cves))

        # noinspection PyTypeChecker
        cves = [TEST_CVE]
        cves = list(prep._filter_by_handler(cves))  # pylint: disable=protected-access

        self.assertTrue(any(cves))

        # check that cves list is not empty
        self.assertIsInstance(cves[0], TestCVE)

    # noinspection PyUnresolvedReferences
    def test_get_cve_attributes(self):
        """Test NVDFeedPreprocessor `_get_cve_attributes` method."""
        prep = NVDFeedPreprocessor()
        cve_tuple, = prep._filter_by_handler(cves=[TestCVE()])
        result = prep._get_cve_attributes(cve_tuple)  # pylint: disable=protected-access

        self.assertIsInstance(result, tuple)
        self.assertEqual(result.repository, TEST_REPOSITORY)
        self.assertIsInstance(result.references, list)

    def test_pipeline(self):
        """Test NVDFeedPreprocessor as a single pipeline unit."""
        # should not raise, since NLTKPreprocessor does implement `fit`
        # and `transform` methods
        _ = Pipeline([
            ('preprocessor', NVDFeedPreprocessor)
        ])


class TestLabelPreprocessor(unittest.TestCase):
    """Tests for LabelPreprocessor class."""

    def test_init(self):
        """Test LabelPreprocessor initialization."""
        hook = Hook(key='label', func=lambda x: x)
        attributes = ['project']

        label_prep = LabelPreprocessor(feed_attributes=attributes,
                                       hook=hook)

        self.assertIsInstance(label_prep, LabelPreprocessor)
        self.assertIsInstance(label_prep._hook, Hook)  # pylint: disable=protected-access

    @clear
    def test_fit_transform(self):
        """Test LabelPreprocessor `fit_transform` method."""
        hook = Hook(key='label', func=lambda p, d: 'label')
        attributes = ['project', 'description']

        test_data = [TEST_CVE]

        # prepare the data for label preprocessor
        feed_prep = NVDFeedPreprocessor(attributes, skip_duplicity=True)
        test_data = feed_prep.transform(X=test_data)

        label_prep = LabelPreprocessor(feed_attributes=attributes,
                                       output_attributes=['description'],
                                       hook=hook)

        result = label_prep.fit_transform(test_data)

        # check not empty
        self.assertTrue(any(result))
        # check that correct label is returned by the Hook
        label = result[0].label
        self.assertEqual(label, 'label')
