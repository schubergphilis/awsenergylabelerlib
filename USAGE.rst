=====
Usage
=====


To develop on awsenergylabelerlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scripts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scripts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py


To use awsenergylabelerlib in a project:

.. code-block:: python

    from awsenergylabelerlib import (EnergyLabeler,
                                     AwsAccount,
                                     SecurityHub,
                                     ACCOUNT_THRESHOLDS,
                                     LANDING_ZONE_THRESHOLDS,
                                     DEFAULT_SECURITY_HUB_FILTER,
                                     DEFAULT_SECURITY_HUB_FRAMEWORKS,
                                     ALL_LANDING_ZONE_EXPORT_TYPES,
                                     LANDING_ZONE_METRIC_EXPORT_TYPES,
                                     ALL_ACCOUNT_EXPORT_TYPES,
                                     ACCOUNT_METRIC_EXPORT_TYPES)

    # Label a landing zone
    labeler = EnergyLabeler(landing_zone_name=landing_zone_name,
                            region=region,
                            account_thresholds=ACCOUNT_THRESHOLDS,
                            landing_zone_thresholds=LANDING_ZONE_THRESHOLDS,
                            security_hub_filter=DEFAULT_SECURITY_HUB_FILTER,
                            frameworks=frameworks,
                            allowed_account_ids=allowed_account_ids,
                            denied_account_ids=denied_account_ids,
                            allowed_regions=allowed_regions,
                            denied_regions=denied_regions)
    print(f'Landing Zone Security Score: {labeler.landing_zone_energy_label.label}')
    print(f'Landing Zone Percentage Coverage: {labeler.landing_zone_energy_label.coverage}')
    print(f'Labeled Accounts Measured: {labeler.labeled_accounts_energy_label.accounts_measured}')

    # Label a single account
    account = AwsAccount(ACCOUNT_ID, 'Not Retrieved', ACCOUNT_THRESHOLDS)
    security_hub = SecurityHub(region=region,
                               allowed_regions=allowed_regions,
                               denied_regions=denied_regions)
    query_filter = SecurityHub.calculate_query_filter(DEFAULT_SECURITY_HUB_FILTER,
                                                      allowed_account_ids=[account_id],
                                                      denied_account_ids=None,
                                                      frameworks=frameworks)
    account.calculate_energy_label(security_hub.get_findings(query_filter))
    print(f'Account Security Score: {account.energy_label.label}')
    print(f'Number Of Critical & High Findings: {account.energy_label.number_of_critical_high_findings}')
    print(f'Number Of Medium Findings: {account.energy_label.number_of_medium_findings}')
    print(f'Number Of Low Findings: {account.energy_label.number_of_low_findings}')
    print(f'Max Days Open: {account.energy_label.max_days_open}')
