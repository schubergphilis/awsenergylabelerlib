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

from awsenergylabelerlib.configuration import (ACCOUNT_THRESHOLDS,
                                               LANDING_ZONE_THRESHOLDS,
                                               DEFAULT_SECURITY_HUB_FILTER,
                                               DEFAULT_SECURITY_HUB_FRAMEWORKS)
from awsenergylabelerlib.schemas import account_thresholds_schema, landing_zone_thresholds_schema

from awsenergylabelerlib import AwsAccount
from awsenergylabelerlib.entities import Finding
from awsenergylabelerlib import EnergyLabeler as EnergyLabelerToMock
from awsenergylabelerlib import LandingZone as LandingZoneToMock
from awsenergylabelerlib import SecurityHub as SecurityHubToMock

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


class LandingZone(LandingZoneToMock):

    @staticmethod
    def _get_client():
        return None

    @property
    def accounts(self):
        with open('tests/fixtures/accounts.json') as ifile:
            accounts_data = json.loads(ifile.read())
        return [AwsAccount(account.get('id'), account.get('name'), self.account_thresholds)
                for account in accounts_data]


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
            return [Finding(data) for data in json.loads(ifile.read())]


class EnergyLabeler(EnergyLabelerToMock):
    """Energy labeler mock."""

    def __init__(self,
                 landing_zone_name,
                 region=None,
                 account_thresholds=ACCOUNT_THRESHOLDS,
                 landing_zone_thresholds=LANDING_ZONE_THRESHOLDS,
                 security_hub_filter=DEFAULT_SECURITY_HUB_FILTER,
                 frameworks=DEFAULT_SECURITY_HUB_FRAMEWORKS,
                 allowed_account_ids=None,
                 denied_account_ids=None,
                 allowed_regions=None,
                 denied_regions=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.account_thresholds = account_thresholds_schema.validate(account_thresholds)
        self.landing_zone_thresholds = landing_zone_thresholds_schema.validate(landing_zone_thresholds)
        self._security_hub_filter = security_hub_filter
        self._frameworks = SecurityHub.validate_frameworks(frameworks)
        self._landing_zone = LandingZone(landing_zone_name,
                                         self.landing_zone_thresholds,
                                         self.account_thresholds,
                                         allowed_account_ids,
                                         denied_account_ids)
        self._security_hub = SecurityHub(region=region,
                                         allowed_regions=allowed_regions,
                                         denied_regions=denied_regions)
        self._account_labels_counter = None
        self._query_filter = None
        self._landing_zone_energy_label = None
        self._labeled_accounts_energy_label = None
        self._landing_zone_labeled_accounts = None
