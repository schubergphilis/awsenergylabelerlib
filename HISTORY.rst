.. :changelog:

History
-------

0.0.1 (09-11-2021)
---------------------

* First code creation


0.1.0 (09-11-2021)
------------------

* Initial pypi release.


0.1.1 (09-11-2021)
------------------

* Exposed main object to the root of the package.


0.2.0 (26-11-2021)
------------------

* Fixed labaling algorithms, added retries to finding retrieval and implemented proper exception handling.


0.2.1 (02-12-2021)
------------------

* Updated number of days open to 999 days
* Account data now includes details on number of findings per severity


0.2.2 (06-12-2021)
------------------

* Improved error handling
* Allow/deny specific regions


0.2.3 (06-12-2021)
------------------

* Added requests dependency


0.2.4 (10-12-2021)
------------------

* A finding exposes now more fields: resources, record_state, description, remediation


0.2.5 (10-12-2021)
------------------

* Compliance fields added to a Security Hub Finding


0.3.0 (14-12-2021)
------------------

* Changed the structure of the measurement data


0.4.0 (28-01-2022)
------------------

* Introduced single account mode which opportunistically gets findings from SecurityHub


0.4.1 (01-02-2022)
------------------

* Edited the filter to only include FAILED findings so NOT_AVAILABLE aren't counted as findings anymore


0.4.2 (02-03-2022)
------------------

* Suppressed findings are no longer counted into the calculation.
* Framework validation works as expected now.


0.4.3 (04-03-2022)
------------------

* Filtered out Archived findings.


0.4.4 (04-03-2022)
------------------

* Filtered out archived findings.


0.4.5 (04-03-2022)
------------------

* No duplicates anymore, unique findings only.


1.0.0 (14-03-2022)
------------------

* Complete redesign of the api and many optimisations of retrieving findings and calculating labels.


1.0.1 (14-03-2022)
------------------

* Cached some calculations to prevent duplications and standardized on default labels with properly retrieved values.
