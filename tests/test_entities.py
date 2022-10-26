#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_entities.py
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
test_entities
----------------------------------
Tests for `entities` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import unittest
from .mocks import OrganizationsZone, AuditZone
from awsenergylabelerlib import OrganizationsZone as OrganizationsZoneUnPatched
from awsenergylabelerlib import AuditZone as AuditZoneUnPatched
from awsenergylabelerlib import (AccountsNotPartOfZone,
                                 InvalidOrNoCredentials)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''15-03-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__credits__ = ["Costas Tyfoxylos", "Jenda Brands", "Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestOrganizationsZone(unittest.TestCase):

    def test_instantiation(self):
        with self.assertRaises(AccountsNotPartOfZone):
            OrganizationsZone('TEST', 'eu-west-1', allowed_account_ids=['123456789123'])
        with self.assertRaises(AccountsNotPartOfZone):
            OrganizationsZone('TEST', 'eu-west-1', denied_account_ids=['123456789123'])
        self.assertTrue(str(OrganizationsZone('TEST', 'eu-west-1')) == 'TEST organizations zone')


    def test_no_credentials(self):
        import os
        os.environ = {}
        with self.assertRaises(InvalidOrNoCredentials):
            OrganizationsZoneUnPatched('TEST', 'eu-west-1')

    def test_allowed_accounts(self):
        allowed_account_id = '100000000001'
        organizations_zone = OrganizationsZone('TEST', 'eu-west-1', allowed_account_ids=[allowed_account_id])
        allowed_accounts = organizations_zone.get_allowed_accounts()
        self.assertTrue(len(allowed_accounts) == 1)
        self.assertTrue(allowed_accounts[0].id == allowed_account_id)
        allowed_account_ids = ['100000000001', '100000000002', '100000000003']
        organizations_zone = OrganizationsZone('TEST', 'eu-west-1', allowed_account_ids=allowed_account_ids)
        allowed_accounts = organizations_zone.get_allowed_accounts()
        self.assertTrue(len(allowed_accounts) == len(allowed_account_ids))
        self.assertTrue(sorted([account.id for account in allowed_accounts]) == allowed_account_ids)

    def test_denied_accounts(self):
        denied_account_id = '100000000001'
        organizations_zone = OrganizationsZone('TEST', 'eu-west-1', denied_account_ids=[denied_account_id])
        accounts = organizations_zone.get_not_denied_accounts()
        self.assertTrue(len(accounts) == len(organizations_zone.accounts) - 1)
        self.assertTrue(denied_account_id not in [account.id for account in accounts])
        denied_account_ids = ['100000000001', '100000000002', '100000000003']
        organizations_zone = OrganizationsZone('TEST', 'eu-west-1', denied_account_ids=denied_account_ids)
        accounts = organizations_zone.get_not_denied_accounts()
        self.assertTrue(len(accounts) == len(organizations_zone.accounts) - len(denied_account_ids))
        account_ids = [account.id for account in accounts]
        self.assertTrue(set(denied_account_id) - set(account_ids) == set(denied_account_id))


class TestAuditZone(unittest.TestCase):

    def test_instantiation(self):
        with self.assertRaises(AccountsNotPartOfZone):
            AuditZone('TEST', 'eu-west-1', allowed_account_ids=['123456789123'])
        with self.assertRaises(AccountsNotPartOfZone):
            AuditZone('TEST', 'eu-west-1', denied_account_ids=['123456789123'])
        self.assertTrue(str(AuditZone('TEST', 'eu-west-1')) == 'TEST audit zone')


    def test_no_credentials(self):
        import os
        os.environ = {'AWS_ACCESS_KEY_ID': 'GARBAGE',
                      'AWS_SECRET_ACCESS_KEY': 'GARBAGE',
                      'AWS_SESSION_TOKEN': 'GARBAGE'}
        with self.assertRaises(InvalidOrNoCredentials):
            AuditZoneUnPatched('TEST', 'eu-west-1')

    def test_allowed_accounts(self):
        allowed_account_id = '100000000001'
        audit_zone = AuditZone('TEST', 'eu-west-1', allowed_account_ids=[allowed_account_id])
        allowed_accounts = audit_zone.get_allowed_accounts()
        self.assertTrue(len(allowed_accounts) == 1)
        self.assertTrue(allowed_accounts[0].id == allowed_account_id)
        allowed_account_ids = ['100000000001', '100000000002', '100000000003']
        audit_zone = AuditZone('TEST', 'eu-west-1', allowed_account_ids=allowed_account_ids)
        allowed_accounts = audit_zone.get_allowed_accounts()
        self.assertTrue(len(allowed_accounts) == len(allowed_account_ids))
        self.assertTrue(sorted([account.id for account in allowed_accounts]) == allowed_account_ids)

    def test_denied_accounts(self):
        denied_account_id = '100000000001'
        audit_zone = AuditZone('TEST', 'eu-west-1', denied_account_ids=[denied_account_id])
        accounts = audit_zone.get_not_denied_accounts()
        self.assertTrue(len(accounts) == len(audit_zone.accounts) - 1)
        self.assertTrue(denied_account_id not in [account.id for account in accounts])
        denied_account_ids = ['100000000001', '100000000002', '100000000003']
        audit_zone = AuditZone('TEST', 'eu-west-1', denied_account_ids=denied_account_ids)
        accounts = audit_zone.get_not_denied_accounts()
        self.assertTrue(len(accounts) == len(audit_zone.accounts) - len(denied_account_ids))
        account_ids = [account.id for account in accounts]
        self.assertTrue(set(denied_account_id) - set(account_ids) == set(denied_account_id))
