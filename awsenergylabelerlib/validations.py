#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: validations.py
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
schemas package.

Import all parts from schemas here

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html
"""

import re
import logging

from .configuration import SECURITY_HUB_ACTIVE_REGIONS
from .awsenergylabelerlibexceptions import InvalidAccountListProvided, MutuallyExclusiveArguments, \
    InvalidRegionListProvided

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'
__docformat__ = '''google'''
__date__ = '''04-03-2022'''
__copyright__ = '''Copyright 2022, Costas Tyfoxylos, Jenda Brands, Theodoor Scholte'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


LOGGER_BASENAME = '''validations'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


def is_valid_account_id(account_id):
    """Checks whether a provided account id is a valid AWS account id.

    Args:
        account_id (str): An account id string.

    Returns:
        True if the provided value is a valid AWS account id, false otherwise.

    """
    return all([len(account_id) == 12, account_id.isdigit(), not account_id.startswith('0')])


def are_valid_account_ids(account_ids):
    """Checks whether a provided list of account ids contains all valid AWS account ids.

    Args:
        account_ids (list): A list of account id strings.

    Returns:
        True if the provided list contains all valid AWS account ids, false otherwise.

    """
    return all([is_valid_account_id(account) for account in account_ids])


def validate_account_ids(account_ids):
    """Validates a provided string or iterable that it contains valid AWS account ids.

    Args:
        account_ids: A string or iterable of strings with AWS account ids.

    Returns:
        account_ids (list): A list of valid AWS account ids.

    Raises:
        InvalidAccountListProvided: If any of the provided account ids is not a valid AWS account id.

    """
    if account_ids is None:
        return []
    if not isinstance(account_ids, (list, tuple, set, str)):
        raise InvalidAccountListProvided(f'Only list, tuple, set or string of accounts is accepted input, '
                                         f'received: {account_ids}')
    if isinstance(account_ids, str):
        account_ids = [account_ids] if is_valid_account_id(account_ids) else re.split('[^0-9]', account_ids)
    account_ids = list({account_id for account_id in account_ids if account_id})
    return account_ids


def validate_allow_deny_account_ids(allow_list=None, deny_list=None):
    """Validates provided allow and deny account id lists.

    Not both arguments can contain values as they are logically mutually exclusive. The validations process also
    validates that the arguments contain valid account id values if provided.

    Args:
        allow_list (str|iterable): A single or multiple account id to validate, mutually exclusive with the deny list
        deny_list (str|iterable): A single or multiple account id to validate, mutually exclusive with the allow list

    Returns:
        allow_list, deny_list: A tuple of list values with valid account ids

    Raises:
        MutuallyExclusiveArguments: If both arguments contain values.
        InvalidAccountListProvided: If any of the provided account ids is not a valid AWS account id.

    """
    if all([allow_list, deny_list]):
        raise MutuallyExclusiveArguments('allow_list and deny_list are mutually exclusive.')
    return validate_account_ids(allow_list), validate_account_ids(deny_list)


def is_valid_region(region):
    """Checks whether a region provided is a valid Security Hub Region.

    Args:
        region: The region to check

    Returns:
        True if Security Hub is active in that region, False otherwise.

    """
    return region in SECURITY_HUB_ACTIVE_REGIONS


def get_invalid_regions(regions):
    """Calculates if regions are not valid for security hub.

    Args:
        regions: The regions to check

    Returns:
        A set of regions that security hub is not active in

    """
    return set(regions) - set(SECURITY_HUB_ACTIVE_REGIONS)


def validate_regions(regions):
    """Validates provided argument of regions for security hub.

    Args:
        regions: A string or iterable of regions that security hub should be active in.

    Returns:
        A list of valid regions if successful.

    Raises:
        InvalidRegionListProvided: If the regions provided are not valid for security hub.

    """
    if regions is None:
        return regions

    if not isinstance(regions, (list, tuple, set, str)):
        raise InvalidRegionListProvided(f'Only list, tuple, set or string of regions is accepted input, '
                                        f'received: {regions}')
    if isinstance(regions, str):
        regions = [regions] if is_valid_region(regions) else re.split(r'\s', regions)

    invalid_regions = get_invalid_regions(regions)
    if invalid_regions:
        raise InvalidRegionListProvided(f'The following regions provided are not valid for Security Hub. '
                                        f'{invalid_regions}')
    return regions


def validate_allow_deny_regions(allowed_regions=None, denied_regions=None):
    """Validates provided allow and deny regions.

    Not both arguments can contain values as they are logically mutually exclusive. The validations process also
    validates that the arguments contain valid regions if provided.

    Args:
        allowed_regions (str|iterable): A single or multiple region to validate, mutually exclusive with the deny
        denied_regions (str|iterable): A single or multiple region to validate, mutually exclusive with the allow

    Returns:
        allowed_regions, denied_regions: A tuple of list values with valid regions

    Raises:
        MutuallyExclusiveArguments: If both arguments contain values.
        InvalidRegionListProvided: If any of the provided regions is not a valid Security Hub region.

    """
    if all([allowed_regions, denied_regions]):
        raise MutuallyExclusiveArguments('allowed_regions and denied_regions are mutually exclusive.')
    return validate_regions(allowed_regions), validate_regions(denied_regions)
