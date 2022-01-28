#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: awsenergylabelerlib.py
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
Main code for awsenergylabelerlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import re
from collections import Counter
import requests

import pandas as pd

from .awsenergylabelerlibexceptions import (InvalidAccountListProvided,
                                            InvalidRegionListProvided,
                                            MutuallyExclusiveArguments)
from .configuration import ACCOUNT_THRESHOLDS, LANDING_ZONE_THRESHOLDS, SECURITY_HUB_FILTER
from .entities import SecurityHub, LandingZone, AwsAccount
from .schemas import account_thresholds_schema, security_hub_filter_schema, landing_zone_thresholds_schema

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__credits__ = ["Costas Tyfoxylos", "Jenda Brands", "Theodoor Scholte"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


# This is the main prefix used for logging
LOGGER_BASENAME = '''awsenergylabelerlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class EnergyLabeler:  # pylint: disable=too-many-instance-attributes, too-many-arguments
    """Labeling accounts and landing zone based on findings and label configurations."""

    def __init__(self,
                 landing_zone_name,
                 region=None,
                 frameworks=('cis', 'aws-foundational-security-best-practices'),
                 landing_zone_thresholds=None,
                 account_thresholds=None,
                 security_hub_filter=None,
                 allow_list=None,
                 deny_list=None,
                 allowed_regions=None,
                 denied_regions=None,
                 single_account=False):
        if all([allow_list, deny_list]):
            raise MutuallyExclusiveArguments('allow_list and deny_list are mutually exclusive.')
        if all([allowed_regions, denied_regions]):
            raise MutuallyExclusiveArguments('allowed_regions and denied_regions are mutually exclusive.')
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.landing_zone_thresholds = landing_zone_thresholds_schema.validate(landing_zone_thresholds) if \
            landing_zone_thresholds else LANDING_ZONE_THRESHOLDS
        self.account_thresholds = account_thresholds_schema.validate(account_thresholds) if account_thresholds \
            else ACCOUNT_THRESHOLDS
        self.security_hub_filter = security_hub_filter_schema.validate(security_hub_filter) if security_hub_filter \
            else SECURITY_HUB_FILTER
        self._landing_zone = LandingZone(landing_zone_name, self.landing_zone_thresholds, self.account_thresholds) \
            if not single_account else None
        self.allow_list = self._validate_account_ids(allow_list, self._landing_zone.account_ids) if allow_list else []
        self.deny_list = self._validate_account_ids(deny_list, self._landing_zone.account_ids) if deny_list else []
        self.allowed_regions = self._validate_regions(allowed_regions) if allowed_regions else []
        self.denied_regions = self._validate_regions(denied_regions) if denied_regions else []
        self.landing_zone_name = landing_zone_name
        self._security_hub = SecurityHub(query_filter=self.security_hub_filter,
                                         region=region,
                                         allowed_regions=self.allowed_regions,
                                         denied_regions=self.denied_regions)
        self._frameworks = frameworks if self._security_hub.validate_frameworks(frameworks) \
            else ('cis', 'aws-foundational-security-best-practices')  # pylint: disable=no-member
        self._account_labels_counter = None
        self.single_account = single_account

    @property
    def security_hub_findings(self):
        """Security hub findings."""
        return self._security_hub.get_findings_for_frameworks(self._frameworks)  # pylint: disable=no-member

    @property
    def security_hub_measurement_data(self):
        """Measurement data from security hub findings."""
        return self._security_hub.get_findings_measurement_data_for_frameworks(self._frameworks)  # pylint: disable=no-member

    @staticmethod
    def _validate_account_ids(accounts, all_landing_zone_accounts):

        def validate_account(account):
            return all([len(account) == 12, account.isdigit()])

        def validate_accounts(accounts_):
            return all([validate_account(account) for account in accounts_])

        if not isinstance(accounts, (list, tuple, str)):
            raise InvalidAccountListProvided(f'Only list, tuple or string of accounts is accepted input, '
                                             f'received: {accounts}')
        if isinstance(accounts, str):
            accounts = [accounts] if validate_account(accounts) else re.split('[^0-9]', accounts)
        accounts = list({account for account in accounts if account})
        if not all([validate_accounts(accounts),
                    set(all_landing_zone_accounts).issuperset(set(accounts))]):
            raise InvalidAccountListProvided(f'The list of accounts provided is not a list with valid AWS IDs'
                                             f' {accounts}')
        return accounts

    @staticmethod
    def _validate_regions(regions):

        def get_available_regions():
            """The regions that security hub can be active in.

            Returns:
                regions (list): A list of strings of the regions that security hub can be active in.

            """
            url = 'https://api.regional-table.region-services.aws.a2z.com/index.json'
            response = requests.get(url)
            if not response.ok:
                LOGGER.error('Failed to retrieve applicable AWS regions')
                return []
            return [entry.get('id', '').split(':')[1]
                    for entry in response.json().get('prices')
                    if entry.get('id').startswith('securityhub')]
        all_available_regions = get_available_regions()

        def validate_region(region):
            return region in all_available_regions

        def get_invalid_regions(regions_):
            return set(regions_) - set(all_available_regions)

        if not isinstance(regions, (list, tuple, str)):
            raise InvalidRegionListProvided(f'Only list, tuple or string of regions is accepted input, '
                                            f'received: {regions}')
        if isinstance(regions, str):
            regions = [regions] if validate_region(regions) else re.split(r'\s', regions)

        invalid_regions = get_invalid_regions(regions)
        if invalid_regions:
            raise InvalidRegionListProvided(f'The list of regions provided is not a list with valid AWS regions'
                                            f' {invalid_regions}')
        return regions

    def _get_valid_account_ids(self):
        if self.allow_list:
            self._logger.debug(f'Working on allow list {self.allow_list}')
            account_ids = [account.id for account in self._landing_zone.get_allowed_accounts(self.allow_list)]
        elif self.deny_list:
            self._logger.debug(f'Working on deny list {self.deny_list}')
            account_ids = [account.id for account in self._landing_zone.get_not_denied_accounts(self.deny_list)]
        else:
            self._logger.debug('Working on all landing zone accounts')
            account_ids = [account.id for account in self._landing_zone.accounts]
        return account_ids

    @property
    def labeled_accounts(self):
        """Labeled accounts."""
        self._account_labels_counter = Counter()
        labeled_accounts = []
        labels = []
        self._logger.debug('Retrieving security hub findings')
        dataframe_measurements = pd.DataFrame(self.security_hub_measurement_data)
        valid_account_ids = self._get_valid_account_ids() if not self.single_account else []
        if self.single_account:
            for account in dataframe_measurements['Account ID'].unique():
                self._logger.debug(f'Calculating energy label for account {account}')
                account = AwsAccount(account, account, None, self.account_thresholds)
                labels.append(account.calculate_energy_label(dataframe_measurements))
                labeled_accounts.append(account)
        else:
            for account in self._landing_zone.accounts:
                self._logger.debug(f'Calculating energy label for account {account.id}')
                labels.append(account.calculate_energy_label(dataframe_measurements))
                if account.id in valid_account_ids:
                    self._logger.debug(f'Account id {account.id} is a required one, adding to the final report')
                    labeled_accounts.append(account)
        self._account_labels_counter.update(labels)
        return labeled_accounts

    @property
    def landing_zone_energy_label(self):
        """Energy label of the landing zone."""
        self._logger.debug(f'Landing zone accounts labeled are {len(self.labeled_accounts)}')
        return self._create_energy_label(self._account_labels_counter)

    @property
    def labeled_accounts_energy_label(self):
        """Energy label of the labeled accounts."""
        account_counter = Counter()
        for account in self.labeled_accounts:
            account_counter.update(account.energy_label)
        return self._create_energy_label(account_counter)

    def _create_energy_label(self, accounts_counter):
        number_of_accounts = sum(accounts_counter.values())
        self._logger.debug(f'Number of accounts calculated are {number_of_accounts}')
        account_sums = []
        labels = []
        calculated_label = "F"
        for threshold in self.landing_zone_thresholds:
            label = threshold.get('label')
            percentage = threshold.get('percentage')
            labels.append(label)
            account_sums.append(accounts_counter.get(label, 0))
            self._logger.debug(f'Calculating for labels {labels} with threshold {percentage} '
                               f'and sums of {account_sums}')
            if sum(account_sums) / number_of_accounts * 100 >= percentage:
                self._logger.debug(f'Found a match with label {label}')
                calculated_label = label
                break
        return calculated_label
