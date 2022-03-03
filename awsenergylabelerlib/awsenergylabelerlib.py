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

from .awsenergylabelerlibexceptions import (MutuallyExclusiveArguments)
from .configuration import (ACCOUNT_THRESHOLDS,
                            LANDING_ZONE_THRESHOLDS,
                            DEFAULT_SECURITY_HUB_FILTER,
                            DEFAULT_SECURITY_HUB_FRAMEWORKS)
from .entities import SecurityHub, LandingZone
from .schemas import account_thresholds_schema, landing_zone_thresholds_schema

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


class EnergyLabeler:  # pylint: disable=too-many-arguments,  too-many-instance-attributes
    """Labeling accounts and landing zone based on findings and label configurations."""

    # pylint: disable=dangerous-default-value
    def __init__(self,
                 landing_zone_name,
                 region=None,
                 frameworks=DEFAULT_SECURITY_HUB_FRAMEWORKS,
                 landing_zone_thresholds=LANDING_ZONE_THRESHOLDS,
                 account_thresholds=ACCOUNT_THRESHOLDS,
                 security_hub_filter=DEFAULT_SECURITY_HUB_FILTER,
                 allow_list=None,
                 deny_list=None,
                 allowed_regions=None,
                 denied_regions=None):
        if all([allow_list, deny_list]):
            raise MutuallyExclusiveArguments('allow_list and deny_list are mutually exclusive.')
        if all([allowed_regions, denied_regions]):
            raise MutuallyExclusiveArguments('allowed_regions and denied_regions are mutually exclusive.')
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._frameworks = SecurityHub.validate_frameworks(frameworks)
        self._security_hub_filter = security_hub_filter
        self._query_filter = None
        self.landing_zone_thresholds = landing_zone_thresholds_schema.validate(landing_zone_thresholds)
        self.account_thresholds = account_thresholds_schema.validate(account_thresholds)
        self._landing_zone = LandingZone(landing_zone_name,
                                         self.landing_zone_thresholds,
                                         self.account_thresholds,
                                         allow_list,
                                         deny_list)
        self._security_hub = SecurityHub(region=region,
                                         allowed_regions=allowed_regions,
                                         denied_regions=denied_regions)
        self._account_labels_counter = None

    @property
    def _security_hub_query_filter(self):
        if self._query_filter is None:
            self._query_filter = SecurityHub.calculate_query_filter(self._security_hub_filter,
                                                                    self._landing_zone.allow_list,
                                                                    self._landing_zone.deny_list,
                                                                    self._frameworks)
            self._logger.debug(f'Calculated query {self._query_filter} to execute on security hub.')
        return self._query_filter

    @property
    def security_hub_findings(self):
        """Security hub findings."""
        return self._security_hub.get_findings(self._security_hub_query_filter)

    @property
    def security_hub_measurement_data(self):
        """Measurement data from security hub findings."""
        return [finding.measurement_data for finding in self.security_hub_findings]

    @property
    def landing_zone_energy_label(self):
        """Energy label of the landing zone."""
        # TODO fix the counting of accounts and energy labels.
        self._logger.debug(f'Landing zone accounts labeled are {len(self._landing_zone.account_ids_to_be_labeled)}')
        return self._landing_zone.get_energy_label()

    @property
    def labeled_accounts_energy_label(self):
        """Energy label of the labeled accounts."""
        # TODO fix the argument passed in the underlying method
        return self._landing_zone.get_labeled_accounts_energy_label()
