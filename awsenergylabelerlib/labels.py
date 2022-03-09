#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: labels.py
#
# Copyright 2022 Costas Tyfoxylos, Jenda Brands, Theodoor Scholte
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
schemas package.

Import all parts from schemas here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import logging
from dataclasses import dataclass

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''08-04-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''labels'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


@dataclass
class AggregateEnergyLabel:
    """Models an energy label averaging multiple account labels."""

    label: str
    best_label: str
    worst_label: str


@dataclass
class AggregateAccountsEnergyLabel(AggregateEnergyLabel):
    """Models an energy label averaging multiple accounts."""

    accounts_measured: str


@dataclass
class LandingZoneEnergyLabel(AggregateEnergyLabel):
    """Models the landing zone energy label."""

    coverage: str


@dataclass
class AccountEnergyLabel:
    """Models the account energy label."""

    label: str = "F"
    number_of_critical_high_findings: int = 9999
    number_of_medium_findings: int = 9999
    number_of_low_findings: int = 9999
    max_days_open: int = 9999
