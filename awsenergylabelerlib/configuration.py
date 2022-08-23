#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
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
configuration package.

Import all parts from configuration here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import json
import logging
import urllib.request
import urllib.error

from .awsenergylabelerlibexceptions import UnableToRetrieveSecurityHubRegions
from .datamodels import (LandingZoneEnergyLabelingData,
                         SecurityHubFindingsData,
                         SecurityHubFindingsResourcesData,
                         SecurityHubFindingsTypesData,
                         LabeledAccountsData,
                         LabeledAccountData)

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

LOGGER_BASENAME = '''configuration'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

ACCOUNT_THRESHOLDS = [{'label': 'A',
                       'critical_high': 0,
                       'medium': 10,
                       'low': 20,
                       'days_open_less_than': 999},
                      {'label': 'B',
                       'critical_high': 10,
                       'medium': 20,
                       'low': 40,
                       'days_open_less_than': 999},
                      {'label': 'C',
                       'critical_high': 15,
                       'medium': 30,
                       'low': 60,
                       'days_open_less_than': 999},
                      {'label': 'D',
                       'critical_high': 20,
                       'medium': 40,
                       'low': 80,
                       'days_open_less_than': 999},
                      {'label': 'E',
                       'critical_high': 25,
                       'medium': 50,
                       'low': 100,
                       'days_open_less_than': 999}]

LANDING_ZONE_THRESHOLDS = [{'label': 'A',
                            'percentage': 90},
                           {'label': 'B',
                            'percentage': 70},
                           {'label': 'C',
                            'percentage': 50},
                           {'label': 'D',
                            'percentage': 30},
                           {'label': 'E',
                            'percentage': 20}]

DEFAULT_SECURITY_HUB_FILTER = {'UpdatedAt': [{'DateRange': {'Value': 7,
                                                            'Unit': 'DAYS'}}],
                               'ComplianceStatus': [{'Value': 'FAILED',
                                                     'Comparison': 'EQUALS'}],
                               'WorkflowStatus': [{'Value': 'SUPPRESSED',
                                                   'Comparison': 'NOT_EQUALS'}],
                               'RecordState': [{'Value': 'ARCHIVED',
                                                'Comparison': 'NOT_EQUALS'}]}

DEFAULT_SECURITY_HUB_FRAMEWORKS = {'cis', 'aws-foundational-security-best-practices'}


def get_available_security_hub_regions():
    """The regions that security hub can be active in.

    Returns:
        regions (list): A list of strings of the regions that security hub can be active in.

    """
    url = 'https://api.regional-table.region-services.aws.a2z.com/index.json'
    try:
        with urllib.request.urlopen(url) as response:
            response_json = json.loads(response.read())
    except (urllib.error.URLError, ValueError):
        raise UnableToRetrieveSecurityHubRegions('Failed to retrieve applicable AWS regions')
    return [entry.get('id', '').split(':')[1]
            for entry in response_json.get('prices')
            if entry.get('id').startswith('securityhub')]


SECURITY_HUB_ACTIVE_REGIONS = ['ap-east-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1',
                               'eu-north-1', 'eu-west-2', 'us-east-2', 'us-gov-west-1', 'us-west-2', 'af-south-1',
                               'ap-northeast-3', 'cn-northwest-1', 'eu-south-1', 'eu-west-1', 'eu-west-3', 'me-south-1',
                               'sa-east-1', 'us-east-1', 'us-west-1', 'ap-northeast-1', 'ap-south-1', 'cn-north-1',
                               'eu-central-1', 'us-gov-east-1']

FILE_EXPORT_TYPES = [
    {'type': 'landing_zone_energy_label',
     'filename': 'landing-zone-energy-label.json',
     'object_type': LandingZoneEnergyLabelingData,
     'required_arguments': ['name', 'energy_label']},
    {'type': 'findings',
     'filename': 'security-hub-findings.json',
     'object_type': SecurityHubFindingsData,
     'required_arguments': ['security_hub_findings']},
    {'type': 'findings_resources',
     'filename': 'security-hub-findings-resources.json',
     'object_type': SecurityHubFindingsResourcesData,
     'required_arguments': ['security_hub_findings']},
    {'type': 'findings_types',
     'filename': 'security-hub-findings-types.json',
     'object_type': SecurityHubFindingsTypesData,
     'required_arguments': ['security_hub_findings']},
    {'type': 'labeled_accounts',
     'filename': 'labeled-accounts.json',
     'object_type': LabeledAccountsData,
     'required_arguments': ['labeled_accounts']},
    {'type': 'account_energy_label',
     'filename': 'account-energy-label.json',
     'object_type': LabeledAccountData,
     'required_arguments': ['labeled_accounts']},
]

LANDING_ZONE_METRIC_EXPORT_TYPES = ['landing_zone_energy_label', 'labeled_accounts']

ACCOUNT_METRIC_EXPORT_TYPES = ['account_energy_label']

DATA_EXPORT_TYPES = ['findings', 'findings_resources', 'findings_types']

ALL_LANDING_ZONE_EXPORT_TYPES = LANDING_ZONE_METRIC_EXPORT_TYPES + DATA_EXPORT_TYPES
ALL_ACCOUNT_EXPORT_TYPES = ACCOUNT_METRIC_EXPORT_TYPES + DATA_EXPORT_TYPES
