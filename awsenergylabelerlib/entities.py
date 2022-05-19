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
import tempfile
from collections import Counter
from copy import copy, deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

import boto3
import botocore.errorfactory
import botocore.exceptions
import pandas as pd
from botocore.config import Config
from cachetools import cached, TTLCache
from opnieuw import retry
from pandas.core.frame import DataFrame

from .awsenergylabelerlibexceptions import (InvalidFrameworks,
                                            InvalidOrNoCredentials,
                                            NoAccess,
                                            NoRegion,
                                            AccountsNotPartOfLandingZone,
                                            InvalidPath,
                                            InvalidRegion)
from .configuration import (DEFAULT_SECURITY_HUB_FRAMEWORKS,
                            DEFAULT_SECURITY_HUB_FILTER,
                            LANDING_ZONE_THRESHOLDS,
                            ACCOUNT_THRESHOLDS,
                            FILE_EXPORT_TYPES)
from .labels import AccountEnergyLabel, AggregateAccountsEnergyLabel, LandingZoneEnergyLabel
from .validations import validate_allowed_denied_account_ids, validate_allowed_denied_regions, DestinationPath

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''entities'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class LandingZone:  # pylint: disable=too-many-instance-attributes
    """Models the landing zone and retrieves accounts from it."""

    # pylint: disable=too-many-arguments,dangerous-default-value
    def __init__(self,
                 name,
                 thresholds=LANDING_ZONE_THRESHOLDS,
                 account_thresholds=ACCOUNT_THRESHOLDS,
                 allowed_account_ids=None,
                 denied_account_ids=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.organizations = self._get_client()
        self.name = name
        self.thresholds = thresholds
        self.account_thresholds = account_thresholds
        account_ids = [account.id for account in self.accounts]
        allowed_account_ids, denied_account_ids = validate_allowed_denied_account_ids(allowed_account_ids,
                                                                                      denied_account_ids)
        self.allowed_account_ids = self._validate_landing_zone_account_ids(allowed_account_ids, account_ids)
        self.denied_account_ids = self._validate_landing_zone_account_ids(denied_account_ids, account_ids)
        self._accounts_to_be_labeled = None
        self._targeted_accounts_energy_label = None

    @staticmethod
    def _validate_landing_zone_account_ids(account_ids, landing_zone_account_ids):
        """Validates that a provided list of valid AWS account ids are actually part of the landing zone.

        Args:
            account_ids: A list of valid AWS account ids.
            landing_zone_account_ids: All the landing zone account ids.

        Returns:
            account_ids (list): A list of account ids that are part of the landing zone.

        Raises:
            AccountsNotPartOfLandingZone: If account ids are not part of the current landing zone.

        """
        accounts_not_in_landing_zone = set(account_ids) - set(landing_zone_account_ids)
        if accounts_not_in_landing_zone:
            raise AccountsNotPartOfLandingZone(f'The following account ids provided are not part of the landing zone :'
                                               f' {accounts_not_in_landing_zone}')
        return account_ids

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
        return [account for account in self.accounts if account.id in self.allowed_account_ids]

    def get_not_denied_accounts(self):
        """Retrieves allowed accounts based on an deny list.

        Returns:
            The list of accounts not on the deny list.

        """
        return [account for account in self.accounts if account.id not in self.denied_account_ids]

    @property
    def accounts_to_be_labeled(self):
        """Account to be labeled according to the allow or deny list arguments.

        Returns:
            account (list): A list of accounts to be labeled.

        """
        if self._accounts_to_be_labeled is None:
            if self.allowed_account_ids:
                self._logger.debug(f'Working on allow list {self.allowed_account_ids}')
                self._accounts_to_be_labeled = self.get_allowed_accounts()
            elif self.denied_account_ids:
                self._logger.debug(f'Working on deny list {self.denied_account_ids}')
                self._accounts_to_be_labeled = self.get_not_denied_accounts()
            else:
                self._logger.debug('Working on all landing zone accounts')
                self._accounts_to_be_labeled = self.accounts
        return self._accounts_to_be_labeled

    def get_labeled_targeted_accounts(self, security_hub_findings):
        """Labels the accounts based on the allow and deny list provided.

        Args:
            security_hub_findings: The findings for a landing zone.

        Returns:
            labeled_accounts (list): A list of AwsAccount objects that have their labels calculated.

        """
        labeled_accounts = []
        self._logger.debug('Calculating on security hub findings')
        dataframe_measurements = pd.DataFrame([finding.measurement_data for finding in security_hub_findings])
        for account in self.accounts_to_be_labeled:
            self._logger.debug(f'Calculating energy label for account {account.id}')
            account.calculate_energy_label(dataframe_measurements)
            labeled_accounts.append(account)
        return labeled_accounts

    def get_energy_label_of_targeted_accounts(self, security_hub_findings):
        """Get the energy label of the targeted accounts.

        Args:
            security_hub_findings: The findings from security hub.

        Returns:
            energy_label (str): The energy label of the targeted accounts.

        """
        if self._targeted_accounts_energy_label is None:
            labeled_accounts = self.get_labeled_targeted_accounts(security_hub_findings)
            label_counter = Counter([account.energy_label.label for account in labeled_accounts])
            number_of_accounts = len(labeled_accounts)
            self._logger.debug(f'Number of accounts calculated are {number_of_accounts}')
            account_sums = []
            labels = []
            for threshold in self.thresholds:
                label = threshold.get('label')
                percentage = threshold.get('percentage')
                labels.append(label)
                account_sums.append(label_counter.get(label, 0))
                self._logger.debug(f'Calculating for labels {labels} with threshold {percentage} '
                                   f'and sums of {account_sums}')
                if sum(account_sums) / number_of_accounts * 100 >= percentage:
                    self._logger.debug(f'Found a match with label {label}')
                    self._targeted_accounts_energy_label = AggregateAccountsEnergyLabel(label,
                                                                                        min(label_counter.keys()),
                                                                                        max(label_counter.keys()),
                                                                                        number_of_accounts)
                    break
            else:
                self._logger.debug('Found no match with thresholds, using default worst label F.')
                self._targeted_accounts_energy_label = AggregateAccountsEnergyLabel('F',
                                                                                    min(label_counter.keys()),
                                                                                    max(label_counter.keys()),
                                                                                    number_of_accounts)
        return self._targeted_accounts_energy_label

    def get_energy_label(self, security_hub_findings):
        """Calculates and returns the energy label of the Landing Zone.

        Args:
            security_hub_findings: The measurement data of all the findings for a landing zone.

        Returns:
            energy_label (LandingZoneEnergyLabel): The labeling object of the landing zone.

        """
        aggregate_label = self.get_energy_label_of_targeted_accounts(security_hub_findings)
        coverage_percentage = len(self.accounts_to_be_labeled) / len(self.accounts) * 100
        return LandingZoneEnergyLabel(aggregate_label.label,
                                      best_label=aggregate_label.best_label,
                                      worst_label=aggregate_label.worst_label,
                                      coverage=f'{coverage_percentage:.2f}%')


@dataclass
class AwsAccount:
    """Models the aws account that can label itself."""

    id: str  # pylint: disable=invalid-name
    name: str
    account_thresholds: list
    energy_label: AccountEnergyLabel = AccountEnergyLabel()
    _alias: str = None

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    @property
    def alias(self):
        """Alias."""
        if self._alias is None:
            self._alias = ''
            try:
                self._alias = boto3.client('iam').list_account_aliases()['AccountAliases'][0]
            except IndexError:
                LOGGER.debug(f'Alias for account {self.id} is not set.')
            except botocore.exceptions.ClientError as msg:
                LOGGER.error(f'Alias for account {self.id} could not be retrieved with message {msg}.')
        return self._alias

    def calculate_energy_label(self, findings):
        """Calculates the energy label for the account.

        Args:
            findings: Either a list of security hub findings or a dataframe of security hub findings.

        Returns:
            The energy label of the account based on the provided configuration.

        """
        if not issubclass(DataFrame, type(findings)):
            findings = pd.DataFrame([finding.measurement_data for finding in findings])
        df = findings  # pylint: disable=invalid-name
        try:
            open_findings = df[(df['Account ID'] == self.id) & (df['Workflow State'] != 'RESOLVED')]
        except KeyError:
            self._logger.info(f'No findings for account {self.id}')
            self.energy_label = AccountEnergyLabel('A', 0, 0, 0, 0)
            return self.energy_label
        try:
            number_of_critical_findings = open_findings[open_findings['Severity'] == 'CRITICAL'].shape[0]
            number_of_high_findings = open_findings[open_findings['Severity'] == 'HIGH'].shape[0]
            number_of_critical_high_findings = number_of_critical_findings + number_of_high_findings
            number_of_medium_findings = open_findings[open_findings['Severity'] == 'MEDIUM'].shape[0]
            number_of_low_findings = open_findings[open_findings['Severity'] == 'LOW'].shape[0]
            open_findings_low_or_higher = open_findings[(open_findings['Severity'] == 'LOW') |
                                                        (open_findings['Severity'] == 'MEDIUM') |
                                                        (open_findings['Severity'] == 'HIGH') |
                                                        (open_findings['Severity'] == 'CRITICAL')]
            max_days_open = max(open_findings_low_or_higher['Days Open']) \
                if open_findings_low_or_higher['Days Open'].shape[0] > 0 else 0

            self._logger.debug(f'Calculating for account {self.id} '
                               f'with number of critical+high findings '
                               f'{number_of_critical_high_findings}, '
                               f'number of medium findings {number_of_medium_findings}, '
                               f'number of low findings {number_of_low_findings}, '
                               f'and findings have been open for over '
                               f'{max_days_open} days')
            for threshold in self.account_thresholds:
                if all([number_of_critical_high_findings <= threshold['critical_high'],
                        number_of_medium_findings <= threshold['medium'],
                        number_of_low_findings <= threshold['low'],
                        max_days_open < threshold['days_open_less_than']]):
                    self.energy_label = AccountEnergyLabel(threshold['label'],
                                                           number_of_critical_high_findings,
                                                           number_of_medium_findings,
                                                           number_of_low_findings,
                                                           max_days_open)
                    self._logger.debug(f'Energy Label for account {self.id} '
                                       f'has been calculated: {self.energy_label.label}')
                    break
            else:
                self._logger.debug('No match with thresholds for energy label, using default worst one.')
                self.energy_label = AccountEnergyLabel('F',
                                                       number_of_critical_high_findings,
                                                       number_of_medium_findings,
                                                       number_of_low_findings,
                                                       max_days_open)
        except Exception:  # pylint: disable=broad-except
            self._logger.exception(f'Could not calculate energy label for account {self.id}, using the default "F"')
        return self.energy_label


@dataclass
class Finding:  # pylint: disable=too-many-public-methods
    """Models a finding."""

    _data: dict

    def __post_init__(self):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        """Override the default equals behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) == hash(other)

    def __ne__(self, other):
        """Override the default unequal behavior."""
        if not isinstance(other, Finding):
            raise ValueError('Not a Finding object')
        return hash(self) != hash(other)

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
        """Is this pci dss framework finding."""
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
        self.allowed_regions, self.denied_regions = validate_allowed_denied_regions(allowed_regions, denied_regions)
        self.sts = self._get_sts_client()
        self.ec2 = self._get_ec2_client(region)
        self._aws_regions = None
        self.aws_region = self._validate_region(region) or self._sts_client_config_region

    def _validate_region(self, region):
        if any([not region, region in self.regions]):
            return region
        raise InvalidRegion(region)

    @property
    def _sts_client_config_region(self):
        return self.sts._client_config.region_name  # noqa

    @staticmethod
    def _get_sts_client():
        return boto3.client('sts')

    @staticmethod
    def _get_ec2_client(region):
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

    def _describe_ec2_regions(self):
        return self.ec2.describe_regions().get('Regions')

    @property
    def regions(self):
        """Regions."""
        if self._aws_regions is None:
            self._aws_regions = [region.get('RegionName')
                                 for region in self._describe_ec2_regions()
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
        raise InvalidFrameworks(frameworks)

    def _get_aggregating_region(self):
        aggregating_region = None
        client = boto3.client('securityhub')
        try:
            data = client.list_finding_aggregators()
            aggregating_region = data.get('FindingAggregators')[0].get('FindingAggregatorArn').split(':')[3]
            self._logger.info(f'Found aggregating region {aggregating_region}')
        except (IndexError, botocore.exceptions.ClientError):
            self._logger.debug('Could not get aggregating region, either not set, or a client error')
        return aggregating_region

    @staticmethod
    def filter_findings_by_frameworks(findings, frameworks):
        """Filters provided findings by the provided frameworks.

        Args:
            findings: A list containing security hub findings
            frameworks: The frameworks to filter for

        Returns:
            findings (list(Findings)): A list of findings matching the provided frameworks

        """
        frameworks = SecurityHub.validate_frameworks(frameworks)

        def framework_to_finding_attribute(framework):
            return f'is_{framework.replace("-", "_")}'
        attributes = [framework_to_finding_attribute(framework) for framework in frameworks]
        return [finding for finding in findings
                if any([getattr(finding, attribute) for attribute in attributes])]

    @retry(retry_on_exceptions=botocore.exceptions.ClientError)
    def get_findings(self, query_filter):
        """Retrieves findings from security hub.

        Args:
            query_filter (dict): The query filter to execute on security hub to get the findings.

        Returns:
            findings (list): A list of findings from security hub.

        """
        findings = set()
        aggregating_region = self._get_aggregating_region()
        regions_to_retrieve = [aggregating_region] if aggregating_region else self.regions
        for region in regions_to_retrieve:
            self._logger.debug(f'Trying to get findings for region {region}')
            session = boto3.Session(region_name=region)
            security_hub = session.client('securityhub')
            paginator = security_hub.get_paginator('get_findings')
            iterator = paginator.paginate(Filters=query_filter)
            try:
                for page in iterator:
                    for finding_data in page['Findings']:
                        finding = Finding(finding_data)
                        self._logger.debug(f'Adding finding with id {finding.id}')
                        findings.add(finding)
            except (security_hub.exceptions.InvalidAccessException, security_hub.exceptions.AccessDeniedException):
                self._logger.debug(f'No access for Security Hub for region {region}.')
                continue
        return list(findings)

    @staticmethod
    def _calculate_account_id_filter(allowed_account_ids, denied_account_ids):
        """Calculates the filter targeting allowed or denied account ids.

        Args:
            allowed_account_ids: The account ids if any.
            denied_account_ids: The Denied ids if any.

        Returns:
            allowed_account_ids, denied_account_ids (tuple(list,list)): If any is set and are valid.

        """
        allowed_account_ids, denied_account_ids = validate_allowed_denied_account_ids(allowed_account_ids,
                                                                                      denied_account_ids)
        aws_account_ids = []
        if any([allowed_account_ids, denied_account_ids]):
            comparison = 'EQUALS' if allowed_account_ids else 'NOT_EQUALS'
            iterator = allowed_account_ids if allowed_account_ids else denied_account_ids
            aws_account_ids = [{'Comparison': comparison, 'Value': account} for account in iterator]
        return aws_account_ids

    #  pylint: disable=dangerous-default-value
    @staticmethod
    def calculate_query_filter(query_filter=DEFAULT_SECURITY_HUB_FILTER,
                               allowed_account_ids=None,
                               denied_account_ids=None,
                               frameworks=DEFAULT_SECURITY_HUB_FRAMEWORKS):
        """Calculates a Security Hub compatible filter for retrieving findings.

        Depending on arguments provided for allow list, deny list and frameworks to retrieve a query is constructed to
        retrieve only appropriate findings, offloading the filter on the back end.

        Args:
            query_filter: The default filter if no filter is provided.
            allowed_account_ids: The allow list of account ids to get the findings for.
            denied_account_ids: The deny list of account ids to filter out findings for.
            frameworks: The default frameworks if no frameworks are provided.


        Returns:
            query_filter (dict): The query filter calculated based on the provided arguments.

        """
        query_filter = deepcopy(query_filter)
        _ = SecurityHub.validate_frameworks(frameworks)
        aws_account_ids = SecurityHub._calculate_account_id_filter(allowed_account_ids, denied_account_ids)
        if aws_account_ids:
            query_filter.update({'AwsAccountId': aws_account_ids})
        return query_filter


class DataExporter:  # pylint: disable=too-few-public-methods
    """Export AWS security data."""

    #  pylint: disable=too-many-arguments
    def __init__(self, export_types, name, energy_label, security_hub_findings, labeled_accounts):
        self.name = name
        self.energy_label = energy_label
        self.security_hub_findings = security_hub_findings
        self.labeled_accounts = labeled_accounts
        self.export_types = export_types
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')

    def export(self, path):
        """Exports the data to the provided path."""
        destination = DestinationPath(path)
        if not destination.is_valid():
            raise InvalidPath(path)
        for export_type in self.export_types:
            data_file = DataFileFactory(export_type,
                                        self.name,
                                        self.energy_label,
                                        self.security_hub_findings,
                                        self.labeled_accounts)
            if destination.type == 's3':
                self._export_to_s3(path, data_file.filename, data_file.json)  # pylint: disable=no-member
            else:
                self._export_to_fs(path, data_file.filename, data_file.json)  # pylint: disable=no-member

    def _export_to_fs(self, directory, filename, data):
        """Exports as json to local filesystem."""
        path = Path(directory)
        try:
            path.mkdir()
        except FileExistsError:
            self._logger.debug(f'Directory {directory} already exists.')
        with open(path.joinpath(filename), 'w') as jsonfile:
            jsonfile.write(data)
        self._logger.info(f'File {filename} copied to {directory}')

    def _export_to_s3(self, s3_url, filename, data):
        """Exports as json to S3 object storage."""
        s3 = boto3.client('s3')  # pylint: disable=invalid-name
        parsed_url = urlparse(s3_url)
        bucket_name = parsed_url.netloc
        dst_path = parsed_url.path
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(data.encode('utf-8'))
            temp_file.flush()
            dst_filename = urljoin(dst_path, filename).lstrip("/")
            s3.upload_file(temp_file.name, bucket_name, dst_filename)
            temp_file.close()
        self._logger.info(f'File {filename} copied to {s3_url}')


class DataFileFactory:  # pylint: disable=too-few-public-methods
    """Data export factory to handle the different data types returned."""

    #  pylint: disable=too-many-arguments, unused-argument
    def __new__(cls, export_type, name, energy_label, security_hub_findings, labeled_accounts):
        data_file_configuration = next((datafile for datafile in FILE_EXPORT_TYPES
                                        if datafile.get('type') == export_type.lower()), None)

        if not data_file_configuration:
            LOGGER.error('Unknown data type %s', export_type)
            return None
        obj = data_file_configuration.get('object_type')
        arguments = {'filename': data_file_configuration.get('filename')}
        arguments.update({key: value for key, value in copy(locals()).items()
                          if key in data_file_configuration.get('required_arguments')})
        return obj(**arguments)
