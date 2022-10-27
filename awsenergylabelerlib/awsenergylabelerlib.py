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

from cachetools import cached, TTLCache

from .awsenergylabelerlibexceptions import UnsupportedZoneType
from .configuration import (ACCOUNT_THRESHOLDS,
                            ZONE_THRESHOLDS,
                            DEFAULT_SECURITY_HUB_FILTER,
                            DEFAULT_SECURITY_HUB_FRAMEWORKS)
from .entities import SecurityHub, AuditZone, OrganizationsZone
from .schemas import account_thresholds_schema, zone_thresholds_schema

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

SUPPORTED_ZONE_TYPES = {'organizations_zone': OrganizationsZone,
                        'audit_zone': AuditZone}


class EnergyLabeler:  # pylint: disable=too-many-arguments,  too-many-instance-attributes
    """Labeling accounts and zone based on findings and label configurations."""

    # pylint: disable=dangerous-default-value
    def __init__(self,
                 zone_name,
                 region=None,
                 account_thresholds=ACCOUNT_THRESHOLDS,
                 zone_thresholds=ZONE_THRESHOLDS,
                 security_hub_filter=DEFAULT_SECURITY_HUB_FILTER,
                 frameworks=DEFAULT_SECURITY_HUB_FRAMEWORKS,
                 allowed_account_ids=None,
                 denied_account_ids=None,
                 allowed_regions=None,
                 denied_regions=None,
                 zone_type='organizations_zone'):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.account_thresholds = account_thresholds_schema.validate(account_thresholds)
        self.zone_thresholds = zone_thresholds_schema.validate(zone_thresholds)
        zone_type_obj = self._validate_zone_type(zone_type)
        self._security_hub_filter = security_hub_filter
        self._frameworks = SecurityHub.validate_frameworks(frameworks)
        self._security_hub = self._initialize_security_hub(region, allowed_regions, denied_regions)
        self._account_labels_counter = None
        self._query_filter = None
        self._zone_energy_label = None
        self._labeled_accounts_energy_label = None
        self._zone_labeled_accounts = None
        self._zone = zone_type_obj(zone_name, region, allowed_account_ids, denied_account_ids, zone_thresholds,
                                   account_thresholds)

    @staticmethod
    def _validate_zone_type(zone_type):
        zone_type = zone_type.lower()
        if zone_type not in SUPPORTED_ZONE_TYPES:
            raise UnsupportedZoneType(zone_type)
        return SUPPORTED_ZONE_TYPES[zone_type]

    @staticmethod
    def _initialize_security_hub(region, allowed_regions, denied_regions):
        return SecurityHub(region=region,
                           allowed_regions=allowed_regions,
                           denied_regions=denied_regions)

    @property
    def initialized_security_hub_query_filter(self):
        """Calculates and saves the security hub query filter based on the configuration of the zone args.

        Returns:
            query_filter (dict): The query filter constructed and cached.

        """
        if self._query_filter is None:
            self._query_filter = SecurityHub.calculate_query_filter(self._security_hub_filter,
                                                                    self._zone.allowed_account_ids,
                                                                    self._zone.denied_account_ids,
                                                                    self._frameworks)
            self._logger.debug(f'Calculated query {self._query_filter} to execute on security hub.')
        return self._query_filter

    @property
    def matching_frameworks(self):
        """The frameworks provided to match the findings of."""
        return self._frameworks

    @property
    def zone(self):
        """Zone."""
        return self._zone

    @property
    def security_hub(self):
        """Security Hub."""
        return self._security_hub

    @property
    @cached(cache=TTLCache(maxsize=150000, ttl=120))
    def security_hub_findings(self):
        """Security hub findings."""
        findings = self.security_hub.get_findings(self.initialized_security_hub_query_filter)
        return self.security_hub.filter_findings_by_frameworks(findings, self._frameworks)

    @property
    def zone_energy_label(self):
        """Energy label of the zone."""
        if self._zone_energy_label is None:
            self._logger.debug(f'Zone accounts labeled are {len(self._zone.accounts_to_be_labeled)}')
            self._zone_energy_label = self._zone.get_energy_label(self.security_hub_findings)
        return self._zone_energy_label

    @property
    def labeled_accounts_energy_label(self):
        """Energy label of the labeled accounts."""
        if self._labeled_accounts_energy_label is None:
            self._labeled_accounts_energy_label = self._zone.get_energy_label_of_targeted_accounts(
                self.security_hub_findings)
        return self._labeled_accounts_energy_label

    @property
    def zone_labeled_accounts(self):
        """The zone labeled account objects."""
        if self._zone_labeled_accounts is None:
            self._zone_labeled_accounts = self._zone.get_labeled_targeted_accounts(
                self.security_hub_findings)
        return self._zone_labeled_accounts

    def get_zone_energy_label_for_findings_by_query(self, findings_query):
        """Calculates an energy label on an arbitrary security hub findings query."""
        findings = self.security_hub.get_findings(findings_query)
        return self._zone.get_energy_label(findings)

    def get_zone_energy_label_for_findings(self, findings):
        """Calculates an energy label on provided security hub findings."""
        return self._zone.get_energy_label(findings)
