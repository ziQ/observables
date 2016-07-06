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
| 4001          | Threat Intel  | Invalid Observable            |

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

This is illustrated within `./test_subclassing.py`

    import observable_importer

    class MyImporter(observable_importer.ObservableImporter):
        def cust_import_observables(self):
            observable_count = 0
            ip_list = ["192.0.2.1", "198.51.100.2", "203.0.113.3"]
            for ip in ip_list:
                self.send_observable("ip", ip)
                observable_count = observable_count + 1
            return observable_count

    my_importer = MyImporter()
    my_importer.import_observables()




[CEF]:   <https://protect724.hp.com/docs/DOC-1072> "CEF Documentation"
[LEEF]:  <https://www.ibm.com/developerworks/community/wikis/form/anonymous/api/wiki/9989d3d7-02c1-444e-92be-576b33d2f2be/page/3dc63f46-4a33-4e0b-98bf-4e55b74e556b/attachment/a19b9122-5940-4c89-ba3e-4b4fc25e2328/media/QRadar_LEEF_Format_Guide.pdf> "LEEF Documentation"
