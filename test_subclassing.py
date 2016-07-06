#!/usr/bin/env python

import observable_importer

class MyImporter(observable_importer.ObservableImporter):
    def cust_import_observables(self):
        """This method is supposed to be overwritten by child classes to provide the actual parsing. For each observable, self.cef_sender.send_cef(...) needs to be called."""

        observable_count = 0

        # to-do: parse something, then loop over contents:
        ip_list = ["192.0.2.{0}".format(i) for i in range(6,17)]

        for ip in ip_list:
            self.send_observable("ip", ip)
            observable_count = observable_count + 1

        return observable_count

my_importer = MyImporter()
my_importer.import_observables()

class FailingImporter(observable_importer.ObservableImporter):
    def cust_import_observables(self):
        """This method is supposed to be overwritten by child classes to provide the actual parsing. For each observable, self.cef_sender.send_cef(...) needs to be called."""

        # doing something that fails:

        ip_list = ["192.0.2.1"]

        print ip_list[3]

failing_importer = FailingImporter()
failing_importer.import_observables()

# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent

