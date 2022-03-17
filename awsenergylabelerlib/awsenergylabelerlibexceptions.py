#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsenergylabelerlibexceptions.py
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
Custom exception code for awsenergylabelerlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__credits__ = ["Costas Tyfoxylos", "Jenda Brands", "Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class InvalidFrameworks(Exception):
    """The frameworks provided are not valid."""


class InvalidAccountListProvided(Exception):
    """The list of accounts provided are not valid AWS accounts."""


class InvalidRegionListProvided(Exception):
    """The list of regions provided are not valid AWS regions."""


class MutuallyExclusiveArguments(Exception):
    """The arguments provided are mutually exclusive and only one of the should be provided."""


class InvalidOrNoCredentials(Exception):
    """Invalid or no credentials were provided from the environment."""


class NoAccess(Exception):
    """The credentials provided do not provide access to the resources."""


class NoRegion(Exception):
    """No region is set on the environment or provided to the library."""


class InvalidRegion(Exception):
    """The region provided is not valid."""


class AccountsNotPartOfLandingZone(Exception):
    """If accounts ids are provided but are not part of the landing zone."""


class UnableToRetrieveSecurityHubRegions(Exception):
    """Could not retrieve the regions security hub is active in."""


class InvalidPath(Exception):
    """The path provided is not valid."""
