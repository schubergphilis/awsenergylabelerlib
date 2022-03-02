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
from dataclasses import dataclass
from datetime import datetime

import boto3
import botocore.errorfactory
import botocore.exceptions
from botocore.config import Config
from cachetools import cached, TTLCache
from opnieuw import retry

from .awsenergylabelerlibexceptions import (InvalidFrameworks,
                                            InvalidOrNoCredentials,
                                            NoAccess,
                                            NoRegion)

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


class LandingZone:
    """Models the landing zone and retrieves accounts from it."""

    def __init__(self, name, thresholds, account_thresholds):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.organizations = self._get_client()
        self.name = name
        self.thresholds = thresholds
        self.account_thresholds = account_thresholds

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
                    account = AwsAccount(account.get('Id'), account.get('Name'), self, self.account_thresholds)
                    aws_accounts.append(account)
            return aws_accounts
        except self.organizations.exceptions.AccessDeniedException as msg:
            raise NoAccess(msg) from None

    def get_allowed_accounts(self, allow_list):
        """Retrieves allowed accounts based on an allow list.

        Args:
            allow_list: A string of comma delimited accounts numbers or a list or tuple of account numbers.

        Returns:
            The list of accounts based on the allowed list.

        """
        return [account for account in self.accounts if account.id in allow_list]

    def get_not_denied_accounts(self, deny_list):
        """Retrieves allowed accounts based on an deny list.

        Args:
            deny_list: A string of comma delimited accounts numbers or a list or tuple of account numbers.

        Returns:
            The list of accounts not on the deny list.

        """
        return [account for account in self.accounts if account.id not in deny_list]


@dataclass
class AwsAccount:  # pylint: disable=too-many-instance-attributes
    """Models the aws account that can label itself."""

    id: str  # pylint: disable=invalid-name
    name: str
    landing_zone: LandingZone
    account_thresholds: list
    energy_label: str = ""
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
        if not self.energy_label:
            self.energy_label = "F"
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
                    if self.number_of_critical_high_findings <= threshold['critical_high'] \
                            and self.number_of_medium_findings <= threshold['medium'] \
                            and self.number_of_low_findings <= threshold['low'] \
                            and self.max_days_open < threshold['days_open_less_than']:
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


class SecurityHub:  # pylint: disable=too-few-public-methods
    """Singleton for security hub."""

    instance = None

    def __new__(cls, query_filter, region=None, allowed_regions=None, denied_regions=None):
        if not SecurityHub.instance:
            SecurityHub.instance = _SecurityHub(query_filter, region, allowed_regions, denied_regions)
        return SecurityHub.instance


class _SecurityHub:  # pylint: disable=too-many-instance-attributes
    """Models security hub and can retrieve findings."""

    frameworks = {'cis', 'pci-dss', 'aws-foundational-security-best-practices'}

    def __init__(self, query_filter, region=None, allowed_regions=None, denied_regions=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.allowed_regions = allowed_regions
        self.denied_regions = denied_regions
        self.sts = boto3.client('sts')
        self.ec2 = self._get_client(region)
        self.query_filter = query_filter
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

    @property
    @retry(retry_on_exceptions=botocore.exceptions.ClientError)
    @cached(cache=TTLCache(maxsize=150000, ttl=3600))
    def _findings(self):
        findings = []
        for region in self.regions:
            self._logger.debug(f'Trying to get findings for region {region}')
            session = boto3.Session(region_name=region)
            security_hub = session.client('securityhub')
            paginator = security_hub.get_paginator('get_findings')
            iterator = paginator.paginate(
                Filters=self.query_filter
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
        return set(frameworks).issubset(_SecurityHub.frameworks)

    def get_findings_for_frameworks(self, frameworks):
        """Gets findings based on provided frameworks.

        Args:
            frameworks: A list of valid frameworks for filter findings on.

        Returns:
            List of findings matching the provided frameworks.

        """
        if not isinstance(frameworks, (list, tuple)):
            frameworks = [frameworks]
        if not self.validate_frameworks(frameworks):
            raise InvalidFrameworks(f'Only {self.frameworks} are supported, {frameworks} were provided.')
        findings = []
        for framework in frameworks:
            self._logger.debug(f'Getting findings for framework : {framework}')
            attribute = f'is_{framework.replace("-", "_")}'
            findings.extend([finding for finding in self._findings if getattr(finding, attribute)])
        return findings

    def get_findings_measurement_data_for_frameworks(self, frameworks):
        """Gets measurement data from findings based on provided frameworks.

        Args:
            frameworks: A list of valid frameworks for filter measurement finding data on.

        Returns:
            List of measurement data of findings matching the provided frameworks.

        """
        findings = self.get_findings_for_frameworks(frameworks)
        return [finding.measurement_data for finding in findings]
