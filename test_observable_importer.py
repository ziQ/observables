#!/usr/bin/env python

import observable_importer

observable_importer = observable_importer.ObservableImporter()

observable_importer.import_observables()

# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent
