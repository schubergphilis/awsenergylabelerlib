#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_validations.py
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
test_validations
----------------------------------
Tests for `awsenergylabelerlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import unittest
from awsenergylabelerlib import (is_valid_account_id,
                                 are_valid_account_ids,
                                 validate_account_ids,
                                 InvalidAccountListProvided)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''11-03-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__credits__ = ["Costas Tyfoxylos", "Jenda Brands", "Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestValidations(unittest.TestCase):

    def test_valid_account_id(self):
        self.assertTrue(is_valid_account_id('123456789123'))
        self.assertFalse(is_valid_account_id('12345678912'))
        self.assertTrue(is_valid_account_id('023456789123'))
        self.assertFalse(is_valid_account_id('123456789123a'))
        self.assertFalse(is_valid_account_id('123456789123a'))
        self.assertFalse(is_valid_account_id('garbage'))
        self.assertFalse(is_valid_account_id([]))
        self.assertFalse(is_valid_account_id({}))

    def test_valid_account_ids(self):
        self.assertTrue(are_valid_account_ids(['123456789123', '223456789123']))
        self.assertTrue(are_valid_account_ids(['023456789123', '223456789123']))
        self.assertFalse(are_valid_account_ids(['12345678913', '223456789123']))
        self.assertFalse(are_valid_account_ids(['12345678913', '2234567891234']))
        self.assertFalse(are_valid_account_ids(['garbage', '223456789123']))
        self.assertFalse(are_valid_account_ids('123456789123,223456789123'))
        self.assertFalse(are_valid_account_ids(',223456789123'))
        self.assertFalse(are_valid_account_ids({}))

    def test_account_ids_validation(self):
        self.assertEqual([], validate_account_ids(None))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids(['123456789123', '223456789123']))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids(('123456789123', '223456789123')))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids({'123456789123', '223456789123'}))
        self.assertTrue(['223456789123'] == validate_account_ids({'', '223456789123'}))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids('123456789123,223456789123'))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids('123456789123-223456789123'))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids('123456789123|223456789123'))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids('123456789123 223456789123'))
        self.assertTrue(['123456789123', '223456789123'] == validate_account_ids('123456789123#223456789123'))
        with self.assertRaises(InvalidAccountListProvided):
            validate_account_ids({'a': 3})
        with self.assertRaises(InvalidAccountListProvided):
            validate_account_ids(['1234567891', '223456789123'])
        with self.assertRaises(InvalidAccountListProvided):
            validate_account_ids(['12345678912', '2234567891232'])
        with self.assertRaises(InvalidAccountListProvided):
            validate_account_ids(['1234567891a2', '223456789123'])
