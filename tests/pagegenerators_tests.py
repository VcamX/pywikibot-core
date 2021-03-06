#!/usr/bin/python
# -*- coding: utf-8  -*-
"""Test pagegenerators module."""
#
# (C) Pywikibot team, 2009-2015
#
# Distributed under the terms of the MIT license.
from __future__ import unicode_literals

__version__ = '$Id$'

import calendar
import datetime
import os
import sys

from distutils.version import LooseVersion

import pywikibot
from pywikibot import pagegenerators, date

from pywikibot.pagegenerators import (
    PagesFromTitlesGenerator,
    PreloadingGenerator,
)

from tests import _data_dir
from tests.aspects import (
    unittest,
    TestCase,
    DeprecationTestCase,
    WikidataTestCase,
    DefaultSiteTestCase,
    RecentChangesTestCase,
)
from tests.thread_tests import GeneratorIntersectTestCase

en_wp_page_titles = (
    # just a bunch of randomly selected titles for English Wikipedia tests
    u"Eastern Sayan",
    u"The Addams Family (pinball)",
    u"Talk:Nowy Sącz",
    u"Talk:Battle of Węgierska Górka",
    u"Template:!",
    u"Template:Template",
)

en_wp_nopage_titles = (
    u"Cities in Burkina Faso",
    u"Talk:Hispanic (U.S. Census)",
    u"Talk:Stołpce",
    u"Template:!/Doc",
    u"Template:!/Meta",
    u"Template:Template/Doc",
    u"Template:Template/Meta",
)


class TestDryPageGenerators(TestCase):

    """Test pagegenerators methods."""

    family = 'wikipedia'
    code = 'en'

    dry = True

    titles = en_wp_page_titles + en_wp_nopage_titles

    def setUp(self):
        super(TestDryPageGenerators, self).setUp()
        self.site = self.get_site()

    def assertFunction(self, obj):
        self.assertTrue(hasattr(pagegenerators, obj))
        self.assertTrue(hasattr(getattr(pagegenerators, obj), '__call__'))

    def test_module_import(self):
        self.assertIn("pywikibot.pagegenerators", sys.modules)

    def test_PagesFromTitlesGenerator(self):
        self.assertFunction("PagesFromTitlesGenerator")
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        self.assertPagelistTitles(gen, self.titles)

    def test_NamespaceFilterPageGenerator(self):
        self.assertFunction("NamespaceFilterPageGenerator")
        site = self.site
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, site)
        gen = pagegenerators.NamespaceFilterPageGenerator(gen, 0, site)
        self.assertEqual(len(tuple(gen)), 3)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, site)
        gen = pagegenerators.NamespaceFilterPageGenerator(gen, 1, site)
        self.assertEqual(len(tuple(gen)), 4)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, site)
        gen = pagegenerators.NamespaceFilterPageGenerator(gen, 10, site)
        self.assertEqual(len(tuple(gen)), 6)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, site)
        gen = pagegenerators.NamespaceFilterPageGenerator(gen, (1, 10), site)
        self.assertEqual(len(tuple(gen)), 10)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, site)
        gen = pagegenerators.NamespaceFilterPageGenerator(gen,
                                                          ('Talk', 'Template'),
                                                          site)
        self.assertEqual(len(tuple(gen)), 10)

    def test_RegexFilterPageGenerator(self):
        self.assertFunction("RegexFilterPageGenerator")
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, '/doc')
        self.assertPagelistTitles(gen,
                                  ('Template:!/Doc', 'Template:Template/Doc'))
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, '/doc',
                                                      quantifier='none')
        self.assertEqual(len(tuple(gen)), 11)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['/doc', '/meta'])
        self.assertPagelistTitles(gen,
                                  ('Template:!/Doc',
                                   'Template:!/Meta',
                                   'Template:Template/Doc',
                                   'Template:Template/Meta'))
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['/doc', '/meta'],
                                                      quantifier='none')
        self.assertEqual(len(tuple(gen)), 9)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['/doc', '/meta'],
                                                      quantifier='all')
        self.assertPagelistTitles(gen, [])
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['Template', '/meta'],
                                                      quantifier='all')
        self.assertPagelistTitles(gen, ('Template:Template/Meta', ))
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['template', '/meta'],
                                                      quantifier='any')
        self.assertPagelistTitles(gen,
                                  ('Template:Template',
                                   'Template:!/Meta',
                                   'Template:Template/Doc',
                                   'Template:Template/Meta'))
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles,
                                                      site=self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['template', '/meta'],
                                                      quantifier='any',
                                                      ignore_namespace=False)
        self.assertEqual(len(tuple(gen)), 6)
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles,
                                                      site=self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['template', '/meta'],
                                                      quantifier='all',
                                                      ignore_namespace=False)
        self.assertPagelistTitles(gen,
                                  ('Template:!/Meta',
                                   'Template:Template/Meta'))
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles,
                                                      site=self.site)
        gen = pagegenerators.RegexFilterPageGenerator(gen, ['template', '/meta'],
                                                      quantifier='none',
                                                      ignore_namespace=False)
        self.assertEqual(len(tuple(gen)), 7)

    def test_RegexBodyFilterPageGenerator(self):
        self.assertFunction("RegexBodyFilterPageGenerator")
        gen = pagegenerators.PagesFromTitlesGenerator(self.titles,
                                                      site=self.site)
        pages = []
        for p in gen:
            p.text = u"This is the content of %s as a sample" % p.title()
            pages.append(p)
        gen = pagegenerators.RegexBodyFilterPageGenerator(iter(pages), '/doc')
        self.assertPagelistTitles(gen,
                                  ('Template:!/Doc', 'Template:Template/Doc'))
        gen = pagegenerators.RegexBodyFilterPageGenerator(iter(pages), 'This')
        self.assertPagelistTitles(gen, self.titles)
        gen = pagegenerators.RegexBodyFilterPageGenerator(iter(pages), 'talk',
                                                          quantifier='none')
        self.assertEqual(len(tuple(gen)), 9)


class EdittimeFilterPageGeneratorTestCase(TestCase):

    """Test EdittimeFilterPageGenerator."""

    family = 'wikipedia'
    code = 'en'

    titles = en_wp_page_titles

    def test_first_edit(self):
        expect = (
            u'The Addams Family (pinball)',
            u'Talk:Nowy Sącz',
            u'Template:Template',
        )
        gen = PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, first_edit_end=datetime.datetime(2006, 1, 1))
        self.assertPagelistTitles(gen, titles=expect, site=self.site)

        gen = PagesFromTitlesGenerator(self.titles, self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, first_edit_start=datetime.datetime(2006, 1, 1))
        opposite_pages = list(gen)
        self.assertTrue(all(isinstance(p, pywikibot.Page)
                            for p in opposite_pages))
        self.assertTrue(all(p.title not in expect for p in opposite_pages))

    def test_last_edit(self):
        two_days_ago = datetime.datetime.now() - datetime.timedelta(days=2)
        nine_days_ago = datetime.datetime.now() - datetime.timedelta(days=9)

        gen = PagesFromTitlesGenerator(['Wikipedia:Sandbox'], self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, last_edit_start=two_days_ago)
        self.assertEqual(len(list(gen)), 1)

        gen = PagesFromTitlesGenerator(['Wikipedia:Sandbox'], self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, last_edit_end=two_days_ago)
        self.assertEqual(len(list(gen)), 0)

        gen = PagesFromTitlesGenerator(['Template:Sidebox'], self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, last_edit_end=nine_days_ago)
        self.assertEqual(len(list(gen)), 1)

        gen = PagesFromTitlesGenerator(['Template:Sidebox'], self.site)
        gen = pagegenerators.EdittimeFilterPageGenerator(
            gen, last_edit_start=nine_days_ago)
        self.assertEqual(len(list(gen)), 0)


class TestRepeatingGenerator(RecentChangesTestCase):

    """Test RepeatingGenerator."""

    def test_RepeatingGenerator(self):
        items = list(
            pagegenerators.RepeatingGenerator(self.site.recentchanges,
                                              key_func=lambda x: x['revid'],
                                              sleep_duration=10,
                                              reverse=True,
                                              namespaces=[0],
                                              total=self.length)
        )
        self.assertEqual(len(items), self.length)
        timestamps = [pywikibot.Timestamp.fromISOformat(item['timestamp'])
                      for item in items]
        self.assertEqual(sorted(timestamps), timestamps)
        self.assertTrue(all(item['ns'] == 0 for item in items))
        self.assertEqual(len(set(item['revid'] for item in items)), self.length)


class TestTextfilePageGenerator(DefaultSiteTestCase):

    """Test loading pages from a textfile."""

    dry = True

    title_columns = {
        'case-sensitive': 0,
        'first-letter': 1,
    }

    expected_titles = (
        ('file', 'File'),
        ('bracket', 'Bracket'),
        ('MediaWiki:Test', 'MediaWiki:Test'),
        ('under score', 'Under score'),
        ('Upper case', 'Upper case'),
    )

    def test_brackets(self):
        filename = os.path.join(_data_dir, 'pagelist-brackets.txt')
        site = self.get_site()
        titles = list(pagegenerators.TextfilePageGenerator(filename, site))
        self.assertEqual(len(titles), len(self.expected_titles))
        expected_titles = [
            expected_title[self.title_columns[site.namespaces[page.namespace()].case]]
            for expected_title, page in zip(self.expected_titles, titles)]
        self.assertPageTitlesEqual(titles, expected_titles)

    def test_lines(self):
        filename = os.path.join(_data_dir, 'pagelist-lines.txt')
        site = self.get_site()
        titles = list(pagegenerators.TextfilePageGenerator(filename, site))
        self.assertEqual(len(titles), len(self.expected_titles))
        expected_titles = [
            expected_title[self.title_columns[site.namespaces[page.namespace()].case]]
            for expected_title, page in zip(self.expected_titles, titles)]
        self.assertPageTitlesEqual(titles, expected_titles)


class TestYearPageGenerator(DefaultSiteTestCase):

    """Test the year page generator."""

    def test_basic(self):
        site = self.get_site()
        # Some languages are missing (T85681)
        if (site.lang not in date.formats['YearBC']) or (site.lang not in date.formats['YearAD']):
            raise unittest.SkipTest('Date formats for this language are missing from date.py')
        start = -20
        end = 2026

        i = 0
        for page in pagegenerators.YearPageGenerator(start, end, site):
            self.assertIsInstance(page, pywikibot.Page)
            self.assertEqual(date.formatYear(site.lang, start + i), page.title())
            self.assertNotEqual(page.title(), "0")
            i += 1
            if start + i == 0:
                i += 1
        self.assertEqual(start + i - 1, end)


class TestDayPageGenerator(DefaultSiteTestCase):

    """Test the day page generator."""

    @classmethod
    def setUpClass(cls):
        super(TestDayPageGenerator, cls).setUpClass()
        cls.site = cls.get_site()
        cls.fd = date.FormatDate(cls.site)

    def _run_test(self, startMonth=1, endMonth=12, year=2000):
        params = {
            'startMonth': startMonth,
            'endMonth': endMonth,
            'site': self.site,
        }
        if year != 2000:
            params['year'] = year
        # use positional parameter
        gen1 = pagegenerators.DayPageGenerator(startMonth, endMonth, self.site,
                                               year)
        # use keyworded parameter and default for year
        gen2 = pagegenerators.DayPageGenerator(**params)

        for page in gen1:
            self.assertIsInstance(page, pywikibot.Page)
            self.assertTrue(page.isAutoTitle)

        expected = []
        for month in range(startMonth, endMonth + 1):
            for day in range(1, calendar.monthrange(year, month)[1] + 1):
                expected.append(self.fd(month, day))

        self.assertPageTitlesEqual(gen2, expected)

    def test_basic(self):
        """General test for day page generator."""
        self._run_test()

    def test_year_2001(self):
        """Test for day page generator of year 2001."""
        self._run_test(2, year=2001)

    def test_year_2100(self):
        """Test for day page generator of year 2100."""
        self._run_test(endMonth=2, year=2100)

    def test_start_0(self):
        """Test for day page generator with startMonth 0."""
        self.assertRaises(calendar.IllegalMonthError, self._run_test, 0)

    def test_end_13(self):
        """Test for day page generator with endMonth 13."""
        self.assertRaises(calendar.IllegalMonthError, self._run_test, 12, 13)


class TestPreloadingGenerator(DefaultSiteTestCase):

    """Test preloading generator on lists."""

    def test_basic(self):
        """Test PreloadingGenerator with a list of pages."""
        mainpage = self.get_mainpage()
        links = list(self.site.pagelinks(mainpage, total=10))
        count = 0
        for page in PreloadingGenerator(links, step=20):
            self.assertIsInstance(page, pywikibot.Page)
            self.assertIsInstance(page.exists(), bool)
            if page.exists():
                self.assertEqual(len(page._revisions), 1)
                self.assertIsNotNone(page._revisions[page._revid].text)
                self.assertFalse(hasattr(page, '_pageprops'))
            count += 1
        self.assertEqual(len(links), count)

    def test_low_step(self):
        """Test PreloadingGenerator with a list of pages."""
        mainpage = self.get_mainpage()
        links = list(self.site.pagelinks(mainpage, total=20))
        count = 0
        for page in PreloadingGenerator(links, step=10):
            self.assertIsInstance(page, pywikibot.Page)
            self.assertIsInstance(page.exists(), bool)
            if page.exists():
                self.assertEqual(len(page._revisions), 1)
                self.assertIsNotNone(page._revisions[page._revid].text)
                self.assertFalse(hasattr(page, '_pageprops'))
            count += 1
        self.assertEqual(len(links), count)


class TestDequePreloadingGenerator(DefaultSiteTestCase):

    """Test preloading generator on lists."""

    def test_deque_preloading(self):
        """Test pages being added to a DequePreloadingGenerator."""
        mainpage = self.get_mainpage()

        pages = pywikibot.tools.DequeGenerator([mainpage])
        gen = pagegenerators.DequePreloadingGenerator(pages)
        pages_out = list()
        for page in gen:
            pages_out.append(page)
            # Add a page to the generator
            if not page.isTalkPage():
                pages.extend([page.toggleTalkPage()])

        self.assertTrue(all(isinstance(page, pywikibot.Page) for page in pages_out))
        self.assertIn(mainpage, pages_out)
        self.assertIn(mainpage.toggleTalkPage(), pages_out)
        self.assertEqual(len(pages_out), 2)
        self.assertTrue(pages_out[1].isTalkPage())


class TestPreloadingItemGenerator(WikidataTestCase):

    """Test preloading item generator."""

    def test_non_item_gen(self):
        """Test TestPreloadingItemGenerator with ReferringPageGenerator."""
        site = self.get_site()
        instance_of_page = pywikibot.Page(site, 'Property:P31')
        ref_gen = pagegenerators.ReferringPageGenerator(instance_of_page, total=5)
        gen = pagegenerators.PreloadingItemGenerator(ref_gen)
        self.assertTrue(all(isinstance(item, pywikibot.ItemPage) for item in gen))


class DryFactoryGeneratorTest(TestCase):

    """Dry tests for pagegenerators.GeneratorFactory."""

    family = 'wikipedia'
    code = 'en'

    dry = True

    def test_one_namespace(self):
        gf = pagegenerators.GeneratorFactory(site=self.get_site())
        gf.handleArg('-ns:2')
        self.assertEqual(gf.namespaces, set([2]))

    def test_two_namespaces(self):
        gf = pagegenerators.GeneratorFactory(site=self.get_site())
        gf.handleArg('-ns:2')
        gf.handleArg('-ns:Talk')
        self.assertEqual(gf.namespaces, set([2, 1]))

    def test_two_named_namespaces(self):
        gf = pagegenerators.GeneratorFactory(site=self.get_site())
        gf.handleArg('-ns:Talk,File')
        self.assertEqual(gf.namespaces, set([1, 6]))

    def test_two_numeric_namespaces(self):
        gf = pagegenerators.GeneratorFactory(site=self.get_site())
        gf.handleArg('-ns:1,6')
        self.assertEqual(gf.namespaces, set([1, 6]))

    def test_immutable_namespaces_on_read(self):
        gf = pagegenerators.GeneratorFactory(site=self.get_site())
        gf.handleArg('-ns:1,6')
        self.assertEqual(gf.namespaces, set([1, 6]))
        self.assertIsInstance(gf.namespaces, frozenset)
        gf.handleArg('-ns:0')
        self.assertEqual(gf.namespaces, set([1, 6]))


class TestItemClaimFilterPageGenerator(WikidataTestCase):

    """Test item claim filter page generator generator."""

    def _simple_claim_test(self, prop, claim, qualifiers, valid):
        """
        Test given claim on sample (India) page.

        @param prop: the property to check
        @type prop: str
        @param claim: the claim the property should contain
        @param qualifiers: qualifiers to check or None
        @type qualifiers: dict or None
        @param valid: true if the page should be yielded by the generator,
            false otherwise
        @type valid: bool
        """
        item = pywikibot.ItemPage(self.get_repo(), 'Q668')
        gen = pagegenerators.ItemClaimFilterPageGenerator([item], prop,
                                                          claim, qualifiers)
        pages = set(gen)
        self.assertEqual(len(pages), 1 if valid else 0)

    def _get_council_page(self):
        """Return United Nations Security Council Wikidata page."""
        site = self.get_site()
        return pywikibot.Page(site, 'Q37470')

    def test_valid_qualifiers(self):
        """Test ItemClaimFilterPageGenerator on sample page using valid qualifiers."""
        qualifiers = {
            'P580': pywikibot.WbTime(1950, 1, 1, precision=9,
                                     site=self.get_site()),
            'P582': '1951',
        }
        self._simple_claim_test('P463', self._get_council_page(), qualifiers,
                                True)

    def test_invalid_qualifiers(self):
        """Test ItemClaimFilterPageGenerator on sample page using invalid qualifiers."""
        qualifiers = {
            'P580': 1950,
            'P582': pywikibot.WbTime(1960, 1, 1, precision=9,
                                     site=self.site),
        }
        self._simple_claim_test('P463', self._get_council_page(), qualifiers,
                                False)

    def test_nonexisting_qualifiers(self):
        """
        Test ItemClaimFilterPageGenerator on sample page.

        The item does not have the searched qualifiers.
        """
        qualifiers = {
            'P370': pywikibot.WbTime(1950, 1, 1, precision=9,
                                     site=self.get_site()),
            'P232': pywikibot.WbTime(1960, 1, 1, precision=9,
                                     site=self.get_site()),
        }
        self._simple_claim_test('P463', self._get_council_page(), qualifiers,
                                False)

    def test_no_qualifiers(self):
        """Test ItemClaimFilterPageGenerator on sample page without qualifiers."""
        self._simple_claim_test('P474', '+91', None, True)
        self._simple_claim_test('P463', 'Q37470', None, True)
        self._simple_claim_test('P625', '21,78', None, True)
        self._simple_claim_test('P625', '21,78.05,0.01', None, False)


class TestFactoryGenerator(DefaultSiteTestCase):

    """Test pagegenerators.GeneratorFactory."""

    def test_ns(self):
        gf = pagegenerators.GeneratorFactory()
        gf.handleArg('-ns:1')
        gen = gf.getCombinedGenerator()
        self.assertIsNone(gen)

    def test_allpages_default(self):
        gf = pagegenerators.GeneratorFactory()
        self.assertTrue(gf.handleArg('-start:!'))
        gf.handleArg('-limit:10')
        gf.handleArg('-step:5')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertLessEqual(len(pages), 10)
        for page in pages:
            self.assertIsInstance(page, pywikibot.Page)
            self.assertEqual(page.namespace(), 0)

    def test_allpages_ns(self):
        gf = pagegenerators.GeneratorFactory()
        self.assertTrue(gf.handleArg('-start:!'))
        gf.handleArg('-limit:10')
        gf.handleArg('-ns:1')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertLessEqual(len(pages), 10)
        self.assertPagesInNamespaces(gen, 1)

    def test_regexfilter_default(self):
        gf = pagegenerators.GeneratorFactory()
        # Matches titles with the same two or more continous characters
        self.assertTrue(gf.handleArg('-titleregex:(.)\\1+'))
        gf.handleArg('-limit:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = list(gen)
        self.assertLessEqual(len(pages), 10)
        for page in pages:
            self.assertIsInstance(page, pywikibot.Page)
            self.assertRegex(page.title().lower(), '(.)\\1+')

    def test_regexfilter_ns_after(self):
        """Bug: T85389: -ns after -titleregex is ignored with a warning."""
        gf = pagegenerators.GeneratorFactory()
        self.assertTrue(gf.handleArg('-titleregex:.*'))
        gf.handleArg('-ns:1')
        gf.handleArg('-limit:10')
        gen = gf.getCombinedGenerator()
        pages = list(gen)
        self.assertGreater(len(pages), 0)
        self.assertLessEqual(len(pages), 10)
        self.assertPagesInNamespaces(pages, 0)

    def test_regexfilter_ns_first(self):
        gf = pagegenerators.GeneratorFactory()
        # Workaround for Bug: T85389
        # Give -ns before -titleregex (as for -newpages)
        gf.handleArg('-ns:1')
        self.assertTrue(gf.handleArg('-titleregex:.*'))
        gf.handleArg('-limit:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = list(gen)
        self.assertGreater(len(pages), 0)
        self.assertLessEqual(len(pages), 10)
        self.assertPagesInNamespaces(pages, 1)

    def test_regexfilter_two_ns_first(self):
        gf = pagegenerators.GeneratorFactory()
        gf.handleArg('-ns:3,1')
        self.assertRaisesRegex(
            TypeError,
            'allpages module does not support multiple namespaces',
            gf.handleArg,
            '-titleregex:.*')

    def test_prefixing_default(self):
        gf = pagegenerators.GeneratorFactory()
        self.assertTrue(gf.handleArg('-prefixindex:a'))
        gf.handleArg('-limit:10')
        gf.handleArg('-step:5')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertLessEqual(len(pages), 10)
        for page in pages:
            self.assertIsInstance(page, pywikibot.Page)
            self.assertTrue(page.title().lower().startswith('a'))

    def test_prefixing_ns(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-ns:1')
        gf.handleArg('-prefixindex:a')
        gf.handleArg("-limit:10")
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, 1)

    def test_newpages_default(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-newpages')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertGreater(len(pages), 0)
        self.assertLessEqual(len(pages), 60)

    def test_newpages_ns_default(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-newpages:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, 0)

    def test_newpages_ns(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-ns:1')
        gf.handleArg('-newpages:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, 1)

    def test_recentchanges_ns_default(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-recentchanges:50')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespacesAll(gen, set([0, 1, 2]), skip=True)

    def test_recentchanges_ns(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-ns:1')
        gf.handleArg('-recentchanges:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, 1)

    def test_recentchanges_ns_multi(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-ns:1')
        gf.handleArg('-ns:3')
        gf.handleArg('-recentchanges:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, set([1, 3]))


class TestFactoryGeneratorWikibase(WikidataTestCase):

    """Test pagegenerators.GeneratorFactory on Wikibase site."""

    def test_onlyif(self):
        """Test -onlyif without qualifiers."""
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-page:Q15745378')
        gf.handleArg('-onlyif:P357=International Journal of Minerals\, '
                     'Metallurgy\, and Materials')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertEqual(len(set(gen)), 1)

    def test_onlyifnot(self):
        """Test -onlyifnot without qualifiers."""
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-page:Q15745378')
        gf.handleArg('-onlyifnot:P357=International Journal of Minerals\, '
                     'Metallurgy\, and Materials')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertEqual(len(set(gen)), 0)

    def test_onlyif_qualifiers(self):
        """Test -onlyif with qualifiers."""
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-page:Q668')
        gf.handleArg('-onlyif:P47=Q837,P805=Q3088768')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertEqual(len(set(gen)), 1)

    def test_searchitem(self):
        """Test -searchitem."""
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-searchitem:abc')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertGreater(len(set(gen)), 0)

    def test_searchitem_language(self):
        """Test -searchitem with custom language specified."""
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-searchitem:pl:abc')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-searchitem:en:abc')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages2 = set(gen)
        self.assertNotEqual(pages, pages2)


class TestLogeventsFactoryGenerator(DefaultSiteTestCase,
                                    DeprecationTestCase):

    """Test GeneratorFactory with pagegenerators.LogeventsPageGenerator."""

    user = True

    @unittest.expectedFailure
    def test_logevents_parse(self):
        gf = pagegenerators.GeneratorFactory()
        self.assertFalse(gf.handleArg("-log"))
        self.assertFalse(gf.handleArg("-log:text_here"))
        # TODO: Throw an error for incorrect logtypes
        self.assertRaises(gf.handleArg("-this_will_never_be_a_typelog"),
                          Exception)

    def test_logevents_default(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        self.assertTrue(gf.handleArg('-newuserslog'))
        self.assertOneDeprecationParts('The usage of "-newuserslog"',
                                       '-logevents:"newusers,,500"')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertLessEqual(len(pages), 500)
        self.assertTrue(all(isinstance(item, pywikibot.Page) for item in pages))

    def test_logevents_default_multi(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        self.assertTrue(gf.handleArg('-newuserslog:10'))
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)
        self.assertLessEqual(len(pages), 10)
        self.assertTrue(all(isinstance(item, pywikibot.Page) for item in pages))

    def test_logevents_ns(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        gf.handleArg('-ns:1')
        gf.handleArg('-newuserslog:10')
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        self.assertPagesInNamespaces(gen, 1)
        self.assertTrue(all(isinstance(item, pywikibot.Page) for item in gen))

    def test_logevents_user_multi(self):
        gf = pagegenerators.GeneratorFactory(site=self.site)
        user = self.get_site().user()
        self.assertTrue(gf.handleArg('-newuserslog:' + user + ';10'))
        gen = gf.getCombinedGenerator()
        self.assertIsNotNone(gen)
        pages = set(gen)

        if not pages:
            raise unittest.SkipTest('No user creation log entries for ' + user)

        # TODO: Check if the pages generated correspond to the user
        # (no easy way of checking from pages)

        self.assertLessEqual(len(pages), 10)
        self.assertTrue(all(isinstance(item, pywikibot.Page) for item in pages))


class PageGeneratorIntersectTestCase(DefaultSiteTestCase,
                                     GeneratorIntersectTestCase):

    """Page intersect_generators test cases."""

    def test_intersect_newpages_twice(self):
        site = self.get_site()
        self.assertEqualItertools(
            [pagegenerators.NewpagesPageGenerator(site=site, total=10),
             pagegenerators.NewpagesPageGenerator(site=site, total=10)])

    def test_intersect_newpages_and_recentchanges(self):
        site = self.get_site()
        self.assertEqualItertools(
            [pagegenerators.NewpagesPageGenerator(site=site, total=50),
             pagegenerators.RecentChangesPageGenerator(site=site, total=200)])


class EnglishWikipediaPageGeneratorIntersectTestCase(GeneratorIntersectTestCase):

    """Page intersect_generators test cases."""

    family = 'wikipedia'
    code = 'en'

    def test_intersect_newpages_csd(self):
        site = self.get_site()
        self.assertEqualItertools([
            pagegenerators.NewpagesPageGenerator(site=site, total=10),
            pagegenerators.CategorizedPageGenerator(
                pywikibot.Category(
                    site, 'Category:Candidates_for_speedy_deletion'))]
        )


class LiveRCPageGeneratorTestCase(RecentChangesTestCase):

    """Test case for Live Recent Changes pagegenerator."""

    @classmethod
    def setUpClass(cls):
        super(LiveRCPageGeneratorTestCase, cls).setUpClass()
        try:
            import socketIO_client  # noqa
        except ImportError:
            raise unittest.SkipTest('socketIO_client not available')

        if LooseVersion(socketIO_client.__version__) >= LooseVersion('0.6.1'):
            raise unittest.SkipTest(
                'socketIO_client %s not supported by Wikimedia-Stream'
                % socketIO_client.__version__)

    def test_RC_pagegenerator_result(self):
        import logging
        lgr = logging.getLogger('socketIO_client')
        lgr.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        lgr.addHandler(ch)

        site = self.get_site()
        pagegenerator = pagegenerators.LiveRCPageGenerator(site,
                                                           total=self.length)
        entries = list(pagegenerator)
        self.assertEqual(len(entries), self.length)

        testentry = entries[0]
        self.assertEqual(testentry.site, site)
        self.assertTrue(hasattr(testentry, '_rcinfo'))

        rcinfo = testentry._rcinfo
        self.assertEqual(rcinfo['server_name'], site.hostname())
        self.assertEqual(rcinfo['wiki'], site.dbName())

        for key in ["id", "type", "namespace", "title", "comment", "timestamp",
                    "user", "bot"]:
            self.assertIn(key, rcinfo.keys())


class TestUnconnectedPageGenerator(DefaultSiteTestCase):

    """Test UnconnectedPageGenerator."""

    def test_unconnected_with_repo(self):
        """Test that the ItemPage returned raises NoPage."""
        if not self.site.data_repository():
            raise unittest.SkipTest('Site is not using a Wikibase repository')
        cnt = 0
        for page in pagegenerators.UnconnectedPageGenerator(self.site, total=5):
            self.assertRaises(pywikibot.NoPage, pywikibot.ItemPage.fromPage,
                              page)
            cnt += 1
        self.assertLessEqual(cnt, 5)

    def test_unconnected_without_repo(self):
        """Test that it raises a ValueError on sites without repository."""
        if self.site.data_repository():
            raise unittest.SkipTest('Site is using a Wikibase repository')
        with self.assertRaises(ValueError):
            for page in pagegenerators.UnconnectedPageGenerator(self.site,
                                                                total=5):
                assert False  # this shouldn't be reached

if __name__ == "__main__":
    try:
        unittest.main()
    except SystemExit:
        pass
