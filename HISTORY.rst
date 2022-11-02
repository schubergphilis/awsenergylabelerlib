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


1.1.0 (17-03-2022)
------------------

* Implemented client side finding filtering.


1.1.1 (19-05-2022)
------------------

* Fix to strip leading slash in S3 destination path


1.1.2 (23-08-2022)
------------------

* Fix bug related to exporting resources data


1.2.0 (09-09-2022)
------------------

* Removed pandas dependency in favor of native python functionality.


1.2.1 (26-09-2022)
------------------

* Fixed timestamp bug
* Fixed bug where accounts without findings got an F


1.2.2 (26-09-2022)
------------------

* Fixed timestamp bug
* Fixed bug where accounts without findings got an F


2.0.0 (25-10-2022)
------------------

* Removed "CIS" from default frameworks, fixed a bug with required region for security hub service.


2.0.1 (25-10-2022)
------------------

* Set appropriate logging level for unsuccessful retrieval of account alias.


2.0.2 (02-11-2022)
------------------

* Fixes parsing for dates for inspector findings by implementing auto datetime parsing.


3.0.0 (02-11-2022)
------------------

* Implements the concept of a Zone to not require full Organizations access rights.
