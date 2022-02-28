#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
#
# Copyright 2021 Costas Tyfoxylos, Jenda Brands, Theodoor Scholte
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
configuration package.

Import all parts from configuration here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""


__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


ACCOUNT_THRESHOLDS = [{'label': 'A',
                       'critical_high': 0,
                       'medium': 10,
                       'low': 20,
                       'days_open_less_than': 999},
                      {'label': 'B',
                       'critical_high': 10,
                       'medium': 20,
                       'low': 40,
                       'days_open_less_than': 999},
                      {'label': 'C',
                       'critical_high': 15,
                       'medium': 30,
                       'low': 60,
                       'days_open_less_than': 999},
                      {'label': 'D',
                       'critical_high': 20,
                       'medium': 40,
                       'low': 80,
                       'days_open_less_than': 999},
                      {'label': 'E',
                       'critical_high': 25,
                       'medium': 50,
                       'low': 100,
                       'days_open_less_than': 999}
                      ]

LANDING_ZONE_THRESHOLDS = [{'label': 'A',
                            'percentage': 90},
                           {'label': 'B',
                            'percentage': 70},
                           {'label': 'C',
                            'percentage': 50},
                           {'label': 'D',
                            'percentage': 30},
                           {'label': 'E',
                            'percentage': 20}
                           ]

DEFAULT_SECURITY_HUB_FILTER = {'UpdatedAt': [{'DateRange': {'Value': 7,
                                                    'Unit': 'DAYS'}}
                                             ],
                       'ComplianceStatus': [{'Value': 'FAILED',
                                             'Comparison': 'EQUALS'}]}


DEFAULT_SECURITY_HUB_FRAMEWORKS = ('cis', 'aws-foundational-security-best-practices')
