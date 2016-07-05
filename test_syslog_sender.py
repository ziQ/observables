#!/usr/bin/env python

import observables

ham_sender = observables.CEFSender()
ham_sender.send_cef()
ham_sender.send_cef(name="My Event")


ham_sender = observables.CEFSender(
                 syslog_server="tcp+tls://127.0.0.10:514",
                 device_vendor="ACME",
                 device_product="UDP Spray'n'Pray",
                 device_version="2.1",
                 )
ham_sender.send_cef(name="My Event")
ham_sender.send_cef(ham_sender=1, name="Tasty Ham Event", cef_dict={1:2,3:4})
ham_sender.send_cef(signature_id="0815", severity="Crazy high severity!", cef_dict={"eggs":"tasty"})

# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent
