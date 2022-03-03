#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: entities.py
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
entities package.

Import all parts from entities here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import logging
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

import boto3
import botocore.errorfactory
import botocore.exceptions
import pandas as pd
import requests
from botocore.config import Config
from cachetools import cached, TTLCache
from opnieuw import retry

from .awsenergylabelerlibexceptions import (InvalidFrameworks,
                                            InvalidOrNoCredentials,
                                            NoAccess,
                                            NoRegion,
                                            InvalidRegionListProvided, InvalidAccountListProvided,
                                            MutuallyExclusiveArguments)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

from .configuration import DEFAULT_SECURITY_HUB_FRAMEWORKS, DEFAULT_SECURITY_HUB_FILTER

from .schemas import security_hub_filter_schema

LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class LandingZone:  # pylint: disable=too-many-instance-attributes
    """Models the landing zone and retrieves accounts from it."""

    # pylint: disable=too-many-arguments
    def __init__(self, name, thresholds, account_thresholds, allow_list=None, deny_list=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.organizations = self._get_client()
        self.name = name
        self.thresholds = thresholds
        self.account_thresholds = account_thresholds
        self.allow_list = self._validate_account_ids(allow_list, self.account_ids)
        self.deny_list = self._validate_account_ids(deny_list, self.account_ids)
        self._account_ids_to_be_labeled = None

    @staticmethod
    def _get_client():
        """Provides the client to organizations.

        Returns:
            boto3 organizations client

        Raises:
            InvalidOrNoCredentials if credentials are not provided or are insufficient.

        """
        try:
            client = boto3.client('organizations')
            client.describe_organization()
        except (botocore.exceptions.NoCredentialsError,
                client.exceptions.AccessDeniedException,  # noqa
                botocore.exceptions.ClientError) as msg:
            raise InvalidOrNoCredentials(msg) from None
        return client

    def __repr__(self):
        return f'{self.name} landing zone'

    @property
    def account_ids(self):
        """Accounts ids of the accounts.

        Returns:
            List of account ids for provided accounts

        """
        return [account.id for account in self.accounts]

    @property
    @cached(cache=TTLCache(maxsize=1000, ttl=600))
    def accounts(self):
        """Accounts of the landing zone.

        Returns:
            List of accounts retrieved

        Raises:
            NoAccess: If insufficient access from credentials.

        """
        aws_accounts = []
        paginator = self.organizations.get_paginator('list_accounts')
        iterator = paginator.paginate()
        try:
            for page in iterator:
                for account in page['Accounts']:
                    account = AwsAccount(account.get('Id'), account.get('Name'), self.account_thresholds)
                    aws_accounts.append(account)
            return aws_accounts
        except self.organizations.exceptions.AccessDeniedException as msg:
            raise NoAccess(msg) from None

    def get_allowed_accounts(self):
        """Retrieves allowed accounts based on an allow list.

        Returns:
            The list of accounts based on the allowed list.

        """
        return [account for account in self.accounts if account.id in self.allow_list]

    def get_not_denied_accounts(self):
        """Retrieves allowed accounts based on an deny list.

        Returns:
            The list of accounts not on the deny list.

        """
        return [account for account in self.accounts if account.id not in self.deny_list]

    @property
    def account_ids_to_be_labeled(self):
        """Account IDs for accounts to be labeled according to the allow or deny list arguments.

        Returns:
            account_ids (list): A list of account IDs to be labeled.

        """
        if self._account_ids_to_be_labeled is None:
            if self.allow_list:
                self._logger.debug(f'Working on allow list {self.allow_list}')
                self._account_ids_to_be_labeled = [account.id
                                                   for account in self.get_allowed_accounts()]
            elif self.deny_list:
                self._logger.debug(f'Working on deny list {self.deny_list}')
                self._account_ids_to_be_labeled = [account.id
                                                   for account in self.get_not_denied_accounts()]
            else:
                self._logger.debug('Working on all landing zone accounts')
                self._account_ids_to_be_labeled = [account.id for account in self.accounts]
        return self._account_ids_to_be_labeled

    @staticmethod
    def _validate_account_ids(accounts, all_landing_zone_accounts):
        if not accounts:
            return []

        def validate_account(account):
            return all([len(account) == 12, account.isdigit(), not account.startswith('0')])

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

    def get_labeled_accounts_energy_label(self, security_hub_findings_data):
        """Labeled accounts."""
        self._account_labels_counter = Counter()
        labeled_accounts = []
        labels = []
        self._logger.debug('Calculating on security hub findings')
        dataframe_measurements = pd.DataFrame(security_hub_findings_data)
        for account in self.accounts:
            if account.id in self.account_ids_to_be_labeled:
                self._logger.debug(f'Calculating energy label for account {account.id}')
                labels.append(account.calculate_energy_label(dataframe_measurements))
                self._logger.debug(f'Account id {account.id} is a required one, adding to the final report')
                labeled_accounts.append(account)
        self._account_labels_counter.update(labels)
        return labeled_accounts

    def get_energy_label(self, accounts_counter):
        """Calculates and returns the energy label of the Landing Zone.

        Args:
            accounts_counter:

        Returns:
            energy_label (LandingZoneEnergyLabel): The labeling object of the landing zone.

        """
        number_of_accounts = sum(accounts_counter.values())
        self._logger.debug(f'Number of accounts calculated are {number_of_accounts}')
        account_sums = []
        labels = []
        calculated_label = "F"
        for threshold in self.thresholds:
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


@dataclass
class AwsAccount:  # pylint: disable=too-many-instance-attributes
    """Models the aws account that can label itself."""

    id: str  # pylint: disable=invalid-name
    name: str
    account_thresholds: list
    energy_label: str = "F"
    number_of_critical_high_findings: int = 0
    number_of_medium_findings: int = 0
    number_of_low_findings: int = 0
    max_days_open: int = 0

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def calculate_energy_label(self, findings_measurements_frame):
        """Calculates the energy label for the account.

        Args:
            findings_measurements_frame: Dataframe with the measurements on findings from security hub.

        Returns:
            The energy label of the account based on the provided configuration.

        """
        df = findings_measurements_frame  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Account ID'] == self.id) & (df['Workflow State'] != 'RESOLVED')]
            number_of_critical_findings = open_findings[open_findings['Severity'] == 'CRITICAL'].shape[0]
            number_of_high_findings = open_findings[open_findings['Severity'] == 'HIGH'].shape[0]
            self.number_of_critical_high_findings = number_of_critical_findings + number_of_high_findings
            self.number_of_medium_findings = open_findings[open_findings['Severity'] == 'MEDIUM'].shape[0]
            self.number_of_low_findings = open_findings[open_findings['Severity'] == 'LOW'].shape[0]
            open_findings_low_or_higher = open_findings[(open_findings['Severity'] == 'LOW') |
                                                        (open_findings['Severity'] == 'MEDIUM') |
                                                        (open_findings['Severity'] == 'HIGH') |
                                                        (open_findings['Severity'] == 'CRITICAL')]
            self.max_days_open = max(open_findings_low_or_higher['Days Open']) \
                if open_findings_low_or_higher['Days Open'].shape[0] > 0 else 0

            self._logger.debug(f'Calculating for account {self.id} '
                               f'with number of critical+high findings '
                               f'{self.number_of_critical_high_findings}, '
                               f'number of medium findings {self.number_of_medium_findings}, '
                               f'number of low findings {self.number_of_low_findings}, '
                               f'and findings have been open for over '
                               f'{self.max_days_open} days')
            for threshold in self.account_thresholds:
                if all(self.number_of_critical_high_findings <= threshold['critical_high'],
                       self.number_of_medium_findings <= threshold['medium'],
                       self.number_of_low_findings <= threshold['low'],
                       self.max_days_open < threshold['days_open_less_than']):
                    self.energy_label = threshold['label']
                    self._logger.debug(f'Energy Label for account {self.id} '
                                       f'has been calculated: {self.energy_label}')
                    break
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(f'Could not calculate energy label for account {self.id}, using the default "F"')
        return self.energy_label


@dataclass
class Finding:  # pylint: disable=too-many-public-methods
    """Models a finding."""

    _data: dict

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def aws_account_id(self):
        """Account id."""
        return self._data.get('AwsAccountId')

    @property
    def region(self):
        """Region."""
        return self._data.get('Region')

    @property
    def id(self):  # pylint: disable=invalid-name
        """ID."""
        return self._data.get('Id')

    @property
    def severity(self):
        """Severity."""
        return self._data.get('Severity', {}).get('Label')

    @property
    def title(self):
        """Title."""
        return self._data.get('Title')

    @property
    def description(self):
        """Description."""
        return self._data.get('Description')

    @property
    def remediation_recommendation_text(self):
        """Textual recommendation for remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Text')

    @property
    def remediation_recommendation_url(self):
        """URL for more information on the remediation."""
        return self._data.get('Remediation', {}).get('Recommendation', {}).get('Url')

    @property
    def standards_guide_arn(self):
        """Arn of the compliance standard."""
        return self._data.get('ProductFields', {}).get('StandardsGuideArn')

    @property
    def resources(self):
        """A list of resource dicts."""
        return self._data.get('Resources', [{}])

    @property
    def resource_types(self):
        """Resource type."""
        return [resource.get('Type') for resource in self._data.get('Resources', [{}])]

    @property
    def resource_ids(self):
        """Resource ids."""
        return [resource.get('Id') for resource in self._data.get('Resources', [{}])]

    @property
    def generator_id(self):
        """Generator id."""
        return self._data.get('GeneratorId')

    @property
    def types(self):
        """Types."""
        return self._data.get('Types')

    @property
    def is_cis(self):
        """Is this cis framework finding."""
        return '/cis-aws' in self.generator_id

    @property
    def is_pci_dss(self):
        """Is this pic dss framework finding."""
        return 'pci-dss/' in self.generator_id

    @property
    def is_aws_foundational_security_best_practices(self):
        """Is this aws foundational security best practices framework finding."""
        return 'aws-foundational-security-best-practices' in self.generator_id

    @property
    def workflow_status(self):
        """Workflow status."""
        return self._data.get('Workflow', {}).get('Status')

    @property
    def record_state(self):
        """Record status."""
        return self._data.get('RecordState')

    @property
    def compliance_framework(self):
        """Compliance framework."""
        return 'aws-foundational-security-best-practices' if self.is_aws_foundational_security_best_practices \
            else 'cis-aws' if self.is_cis \
            else 'pci-dss' if self.is_pci_dss \
            else ''

    @property
    def rule_id(self):
        """Rule id."""
        return self._data.get('ProductFields', {}).get('RuleId')

    @property
    def compliance_status(self):
        """Compliance status."""
        return self._data.get('Compliance', {}).get('Status')

    @property
    def compliance_control(self):
        """Compliance control."""
        return self._data.get('Compliance Control')

    @property
    def first_observed_at(self):
        """First observed at."""
        return self._parse_date_time(self._data.get('FirstObservedAt'))

    @property
    def last_observed_at(self):
        """Last observed at."""
        return self._parse_date_time(self._data.get('LastObservedAt'))

    @property
    def created_at(self):
        """Created at."""
        return self._parse_date_time(self._data.get('CreatedAt'))

    @property
    def updated_at(self):
        """Updated at."""
        return self._parse_date_time(self._data.get('UpdatedAt'))

    @staticmethod
    def _parse_date_time(datetime_string):
        try:
            return datetime.strptime(datetime_string, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            return None

    @property
    def days_open(self):
        """Days open."""
        if self.workflow_status == 'RESOLVED':
            return 0
        first_observation = self.first_observed_at or self.created_at
        last_observation = self.last_observed_at or datetime.now()
        try:
            return (last_observation - first_observation).days
        except Exception:  # pylint: disable=broad-except
            self._logger.exception('Could not calculate number of days open, '
                                   'last or first observation date is missing.')
            return -1

    @property
    def original_payload(self):
        """Original payload."""
        return self._data

    @property
    def measurement_data(self):
        """Measurement data for computing the energy label."""
        return {
            'Finding ID': self.id,
            'Account ID': self.aws_account_id,
            'Severity': self.severity,
            'Workflow State': self.workflow_status,
            'Days Open': self.days_open
        }


class SecurityHub:
    """Models security hub and can retrieve findings."""

    frameworks = {'cis', 'pci-dss', 'aws-foundational-security-best-practices'}

    def __init__(self, region=None, allowed_regions=None, denied_regions=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        if all([allowed_regions, denied_regions]):
            raise MutuallyExclusiveArguments('allowed_regions and denied_regions are mutually exclusive.')
        self.allowed_regions = self._validate_regions(allowed_regions)
        self.denied_regions = self._validate_regions(denied_regions)
        self.sts = boto3.client('sts')
        self.ec2 = self._get_client(region)
        self._aws_regions = None
        self.aws_region = region if region in self.regions else self.sts._client_config.region_name  # noqa

    @staticmethod
    def _get_client(region):
        kwargs = {}
        if region:
            config = Config(region_name=region)
            kwargs = dict(config=config)
        try:
            client = boto3.client('ec2', **kwargs)
            client.describe_regions()
        except (botocore.exceptions.NoRegionError,
                botocore.exceptions.InvalidRegionError,
                botocore.exceptions.EndpointConnectionError) as msg:
            raise NoRegion(msg) from None
        except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as msg:
            raise InvalidOrNoCredentials(msg) from None
        return client

    @staticmethod
    def _validate_regions(regions):
        if regions is None:
            return regions

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

    @property
    def regions(self):
        """Regions."""
        if self._aws_regions is None:
            self._aws_regions = [region.get('RegionName')
                                 for region in self.ec2.describe_regions().get('Regions')
                                 if not region.get('OptInStatus', '') == 'not-opted-in']
            self._logger.debug(f'Regions in EC2 that were opted in are : {self._aws_regions}')

        if self.allowed_regions:
            self._aws_regions = set(self._aws_regions).intersection(set(self.allowed_regions))
            self._logger.debug(f'Working on allowed regions {self._aws_regions}')
        elif self.denied_regions:
            self._logger.debug(f'Excluding denied regions {self.denied_regions}')
            self._aws_regions = set(self._aws_regions) - set(self.denied_regions)
            self._logger.debug(f'Working on non-denied regions {self._aws_regions}')
        else:
            self._logger.debug('Working on all regions')
        return self._aws_regions

    @staticmethod
    def validate_frameworks(frameworks):
        """Validates provided frameworks.

        Args:
            frameworks: One or more of the frameworks to validate according to an accepted list.

        Returns:
            True if frameworks are valid False otherwise.

        """
        if not isinstance(frameworks, (list, tuple, set)):
            frameworks = [frameworks]
        if set(frameworks).issubset(SecurityHub.frameworks):
            return frameworks
        raise InvalidFrameworks

    @retry(retry_on_exceptions=botocore.exceptions.ClientError)
    def get_findings(self, query_filter):
        """Retrieves findings from security hub.

        Args:
            query_filter: The query filter to execute on security hub to get the findings.

        Returns:
            findings (list): A list of findings from security hub.

        """
        findings = []
        for region in self.regions:
            self._logger.debug(f'Trying to get findings for region {region}')
            session = boto3.Session(region_name=region)
            security_hub = session.client('securityhub')
            paginator = security_hub.get_paginator('get_findings')
            iterator = paginator.paginate(
                Filters=query_filter
            )
            try:
                for page in iterator:
                    for finding_data in page['Findings']:
                        finding = Finding(finding_data)
                        self._logger.debug(f'Adding finding with id {finding.id}')
                        findings.append(finding)
            except (security_hub.exceptions.InvalidAccessException, security_hub.exceptions.AccessDeniedException):
                self._logger.warning(f'Check your access for Security Hub for region {region}.')
                continue
        return findings

    #  pylint: disable=dangerous-default-value
    @staticmethod
    def calculate_query_filter(default_filter=DEFAULT_SECURITY_HUB_FILTER,
                               allow_list=None,
                               deny_list=None,
                               frameworks=DEFAULT_SECURITY_HUB_FRAMEWORKS):
        """Calculates a Security Hub compatible filter for retrieving findings.

        Depending on arguments provided for allow list, deny list and frameworks to retrieve a query is constructed to
        retrieve only appropriate findings, offloading the filter on the back end.

        Args:
            default_filter: The default filter if no filter is provided.
            allow_list: The allow list of account ids to get the findings for.
            deny_list: The deny list of account ids to filter out findings for.
            frameworks: The default frameworks if no frameworks are provided.


        Returns:
            query_filter (str): The query filter calculated based on the provided arguments.

        """
        default_filter = security_hub_filter_schema.validate(default_filter)
        frameworks = SecurityHub.validate_frameworks(frameworks)
        # extend the filter to only target accounts mentioned in the allow list or not in the deny list and only
        # frameworks requested.
        _ = allow_list
        _ = deny_list
        query_filter = None
        return query_filter
