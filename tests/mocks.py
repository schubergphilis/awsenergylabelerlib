#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: mocks.py
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
mocks
----------------------------------

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging
from datetime import datetime

from awsenergylabelerlib import AwsAccount
from awsenergylabelerlib import EnergyLabeler as EnergyLabelerToMock
from awsenergylabelerlib import OrganizationsZone as OrganizationsZoneToMock
from awsenergylabelerlib import SecurityHub as SecurityHubToMock
from awsenergylabelerlib.entities import Finding

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''15-03-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__credits__ = ["Costas Tyfoxylos", "Jenda Brands", "Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''mocks'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class OrganizationsZone(OrganizationsZoneToMock):

    @staticmethod
    def _get_client(_):
        return None

    @property
    def accounts(self):
        with open('tests/fixtures/accounts.json') as ifile:
            accounts_data = json.loads(ifile.read())
        return [AwsAccount(account.get('id'), account.get('name'), self.account_thresholds)
                for account in accounts_data]


class AuditZone(OrganizationsZone):
    """Implements the same accounts as the landing zone for the tests."""


def adjust_datetime_offset_to_now(finding):
    offset = finding.updated_at - finding.created_at
    now = datetime.now()
    now_text = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    adjusted_creation_date = now - offset
    adjusted_creation_date_text = adjusted_creation_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    payload = {'CreatedAt': adjusted_creation_date_text,
               'FirstObservedAt': adjusted_creation_date_text,
               'LastObservedAt': now_text,
               'UpdatedAt': now_text}
    finding._data.update(payload)
    return finding


class SecurityHub(SecurityHubToMock):

    @staticmethod
    def _get_sts_client():
        return None

    @staticmethod
    def _get_ec2_client(region):
        return None

    def _describe_ec2_regions(self):
        with open('tests/fixtures/regions.json') as ifile:
            return json.loads(ifile.read())

    @property
    def _sts_client_config_region(self):
        return 'eu-west-1'

    def _get_aggregating_region(self):
        return None

    def get_findings(self, query_filter):
        with open('tests/fixtures/findings.json') as ifile:
            all_findings = [adjust_datetime_offset_to_now(Finding(data))
                            for data in json.loads(ifile.read())]
        accounts_to_filter = query_filter.get('AwsAccountId')
        if not accounts_to_filter:
            return all_findings
        account_ids_to_keep = [account.get('Value') for account in accounts_to_filter
                               if account.get('Comparison') == 'EQUALS']
        account_ids_to_discard = [account.get('Value') for account in accounts_to_filter
                                  if account.get('Comparison') == 'NOT_EQUALS']
        account_matching_findings = [finding for finding in all_findings
                                     if all([finding.aws_account_id in account_ids_to_keep,
                                             finding.aws_account_id not in account_ids_to_discard])]
        return account_matching_findings


from awsenergylabelerlib.awsenergylabelerlib import SUPPORTED_ZONE_TYPES

class EnergyLabeler(EnergyLabelerToMock):
    """Energy labeler mock."""

    @staticmethod
    def _initialize_security_hub(region, allowed_regions, denied_regions):
        return SecurityHub(region=region,
                           allowed_regions=allowed_regions,
                           denied_regions=denied_regions)
