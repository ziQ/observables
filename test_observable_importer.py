#!/usr/bin/env python

import observables

observable_importer = observables.ObservableImporter()

observable_importer.import_observables()

# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent
