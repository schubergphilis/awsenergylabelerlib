#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: datamodels.py
#
# Copyright 2022 Theodoor Scholte, Costas Tyfoxylos, Jenda Brands
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
Main code for datamodels.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import logging
import json

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-04-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos'''
__credits__ = ["Theodoor Scholte", "Costas Tyfoxylos", "Jenda Brands"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''datamodels'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class LandingZoneEnergyLabelingData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, name, energy_label):
        self.filename = filename
        self._name = name
        self._energy_label = energy_label

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Landing Zone Name': self._name,
                            'Landing Zone Energy Label': self._energy_label}],
                          indent=2, default=str)


class SecurityHubFindingsData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, security_hub_findings):
        self.filename = filename
        self._security_hub_findings = security_hub_findings

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Finding ID': finding.id,
                            'Account ID': finding.aws_account_id,
                            'Generator ID': finding.generator_id,
                            'Finding First Observed At': finding.first_observed_at,
                            'Finding Last Observed At': finding.last_observed_at,
                            'Finding Created At': finding.created_at,
                            'Finding Updated At': finding.updated_at,
                            'Severity': finding.severity,
                            'Title': finding.title,
                            'Description': finding.description,
                            'Remediation Text': finding.remediation_recommendation_text,
                            'Remediation Url': finding.remediation_recommendation_url,
                            'Compliance Framework': finding.compliance_framework,
                            'Rule ID': finding.rule_id,
                            'Compliance Status': finding.compliance_status,
                            'Workflow State': finding.workflow_status,
                            'Record State': finding.record_state,
                            'Days Open': finding.days_open
                            }
                           for finding in self._security_hub_findings], indent=2, default=str)


class SecurityHubFindingsResourcesData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, security_hub_findings):
        self.filename = filename
        self._security_hub_findings = security_hub_findings

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Finding ID': finding.id,
                            'Resource ID': resource.get('Id'),
                            'Resource Type': resource.get('Type'),
                            'Resource Partition': resource.get('Partition'),
                            'Resource Region': resource.get('Region')}
                           for finding in self._security_hub_findings for resource in finding.resources],
                          indent=2, default=str)


class SecurityHubFindingsTypesData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, security_hub_findings):
        self.filename = filename
        self._security_hub_findings = security_hub_findings

    @property
    def json(self):
        """Data to json."""
        return json.dumps([{'Finding ID': finding.id,
                            'Finding Type': finding_type}
                           for finding in self._security_hub_findings for finding_type in finding.types],
                          indent=2, default=str)


class LabeledAccountData:
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_accounts):
        self.filename = filename
        self._labeled_account = labeled_accounts

    @property
    def data(self):
        """Data of an account to export."""
        return {'Account ID': self._labeled_account.id,
                'Account Name (or alias if set)': self._labeled_account.alias or self._labeled_account.name,
                'Number of critical & high findings':
                    self._labeled_account.energy_label.number_of_critical_high_findings,
                'Number of medium findings': self._labeled_account.energy_label.number_of_medium_findings,
                'Number of low findings': self._labeled_account.energy_label.number_of_low_findings,
                'Number of maximum days open': self._labeled_account.energy_label.max_days_open,
                'Energy Label': self._labeled_account.energy_label.label}

    @property
    def json(self):
        """Data to json."""
        return json.dumps(self.data, indent=2, default=str)


class LabeledAccountsData:  # pylint: disable=too-few-public-methods
    """Models the data for energy labeling to export."""

    def __init__(self, filename, labeled_accounts):
        self.filename = filename
        self._labeled_accounts = labeled_accounts

    @property
    def json(self):
        """Data to json."""
        return json.dumps([LabeledAccountData(self.filename, account).data
                           for account in self._labeled_accounts], indent=2, default=str)
