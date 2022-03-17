#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: __init__.py
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
awsenergylabelerlib package.

Import all parts from awsenergylabelerlib here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""
from ._version import __version__
from .awsenergylabelerlib import EnergyLabeler, LandingZone, SecurityHub
from .awsenergylabelerlibexceptions import (InvalidFrameworks,
                                            InvalidOrNoCredentials,
                                            InvalidAccountListProvided,
                                            InvalidRegionListProvided,
                                            MutuallyExclusiveArguments,
                                            NoAccess,
                                            NoRegion,
                                            AccountsNotPartOfLandingZone,
                                            UnableToRetrieveSecurityHubRegions,
                                            InvalidRegion)
from .configuration import (ALL_LANDING_ZONE_EXPORT_TYPES,
                            ALL_ACCOUNT_EXPORT_TYPES,
                            DATA_EXPORT_TYPES,
                            ACCOUNT_METRIC_EXPORT_TYPES,
                            LANDING_ZONE_METRIC_EXPORT_TYPES,
                            SECURITY_HUB_ACTIVE_REGIONS,
                            ACCOUNT_THRESHOLDS,
                            LANDING_ZONE_THRESHOLDS,
                            DEFAULT_SECURITY_HUB_FILTER,
                            DEFAULT_SECURITY_HUB_FRAMEWORKS)
from .entities import DataExporter, AwsAccount
from .validations import (is_valid_account_id,
                          are_valid_account_ids,
                          validate_account_ids,
                          validate_allowed_denied_account_ids,
                          is_valid_region,
                          get_invalid_regions,
                          validate_regions,
                          validate_allowed_denied_regions,
                          DestinationPath)


__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''09-11-2021'''
__copyright__ = '''Copyright 2021, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is to 'use' the module(s), so lint doesn't complain
assert __version__
assert EnergyLabeler
assert LandingZone
assert SecurityHub

assert InvalidFrameworks
assert InvalidOrNoCredentials
assert InvalidAccountListProvided
assert InvalidRegionListProvided
assert MutuallyExclusiveArguments
assert NoAccess
assert NoRegion
assert AccountsNotPartOfLandingZone
assert UnableToRetrieveSecurityHubRegions
assert InvalidRegion

assert ALL_LANDING_ZONE_EXPORT_TYPES
assert ALL_ACCOUNT_EXPORT_TYPES
assert DATA_EXPORT_TYPES
assert LANDING_ZONE_METRIC_EXPORT_TYPES
assert ACCOUNT_METRIC_EXPORT_TYPES
assert SECURITY_HUB_ACTIVE_REGIONS
assert ACCOUNT_THRESHOLDS
assert LANDING_ZONE_THRESHOLDS
assert DEFAULT_SECURITY_HUB_FILTER
assert DEFAULT_SECURITY_HUB_FRAMEWORKS

assert DataExporter
assert AwsAccount

assert is_valid_account_id
assert are_valid_account_ids
assert validate_account_ids
assert validate_allowed_denied_account_ids
assert is_valid_region
assert get_invalid_regions
assert validate_regions
assert validate_allowed_denied_regions
assert DestinationPath
