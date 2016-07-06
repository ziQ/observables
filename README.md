Overview
========

This repository contains some Python classes for pain-free import of URI, IP or domain observables via CEF Syslog.

Generated Events
================
The following health monitoring and threat intel import events are supported:

| Signature ID  | Category      | Description                   |
|:------------- |:-------------:|:----------------------------- |
| 1000          | Health (good) | Intel Import started          |
| 1001          | Health (good) | Intel Import successful       |
| 4000          | Health (bad)  | Intel Import failed           |
| 2000          | Threat Intel  | IP Observable Import          |
| 2001          | Threat Intel  | IP+Port Observable Import     |
| 2010          | Threat Intel  | Domain Observable Import      |
| 2011          | Threat Intel  | Domain+Port Observable Import |
| 2020          | Threat Intel  | URI Observable Import         |

A successful import would generate the following CEF events:
    CEF:0|Open Source|Observable Importer|0.1|1000|Observable Import started|Low|
    CEF:0|Open Source|Observable Importer|0.1|2000|IP Observable Import|Low|destinationAddress=192.0.2.6
    (...)
    CEF:0|Open Source|Observable Importer|0.1|2000|IP Observable Import|Low|destinationAddress=192.0.2.16
    CEF:0|Open Source|Observable Importer|0.1|1001|Observable Import successful|Low|deviceCustomNumber2Label=Observables imported deviceCustomNumber1=11

A failed import would generate the following CEF events:
    CEF:0|Open Source|Observable Importer|0.1|1000|Observable Import started|Low|
    CEF:0|Open Source|Observable Importer|0.1|4000|Observable Import failed|High|deviceCustomString2Label=Failure Reason deviceCustomString1=list index out of range (list index out of range)

Note that the 'Failure Reason' in the 'Observable Import failed' event is automatically populated with the exception details. This drastically increases troubleshooting capabilities on the consumer side (i.e., ArcSight ESM).

Custom Importers
================
To create a custom importer, a new class needs to be created which inherits from ObservableImporter. In the new class, a method `cust_import_observables` must be created, which contains the relevant application logic.

This is illustrated within ./tests/test_subclassing.py
