import string

class SyslogSender:
    """Sends Syslog messages."""

    def __init__(self, **kwargs):
        """Initiate Syslog server settings."""

        kwargs.setdefault("syslog_server","udp://127.0.0.1:514")

        # to-do: extract fields from kwargs["syslog_server"]
        self.syslog_proto  = ""
        self.syslog_server = ""
        self.syslog_port   = ""

    def send_syslog(self, syslog_message):
        """Send a message, as defined by Syslog server settings."""

        # to-do: send syslog event via UDP socket or whatever is
        #        requested through __init_syslog_settings()
        print syslog_message

class CEFSender:
    """Sends standard compliant CEF messages."""

    def __init__(self, **kwargs):
        """Initiate global CEF header fields (i.e., deviceVendor)"""

        self.syslog_sender = SyslogSender(**kwargs)
        self.__init_cef_template(**kwargs)

    def __init_cef_template(self, **kwargs):
        """Create template for CEF messages, which will be used by all CEF messages sent by this CEFSender."""

        kwargs.setdefault("cef_version",0)
        kwargs.setdefault("device_vendor","Tammo")
        kwargs.setdefault("device_product","Observable Importer")
        kwargs.setdefault("device_version","0.1")
        pattern = "CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|$signature_id|$name|$severity|$extension"
        tpl = pattern.format(**kwargs)

        self.cef_template = string.Template(tpl)

    def send_cef(self, **kwargs):
        """Sends a CEF event through the SyslogSender instance."""

        kwargs.setdefault("signature_id", 0x0815)
        kwargs.setdefault("name","Standard Event")
        kwargs.setdefault("severity","Unknown Severity")
        kwargs.setdefault("cef_dict",{})
        kwargs["extension"] = " ".join(["{0}={1}".format(k,v) for k,v in kwargs["cef_dict"].iteritems()])

        syslog_message = self.cef_template.safe_substitute(kwargs)

        self.syslog_sender.send_syslog(syslog_message)


class ObservableImporter:
    """Parse some input file (snort rules, or whichever) for observables, then send all observables in CEF format to a configured Syslog receiver.

    While doing so, generate meaningful health events and send these in CEF format to the same Syslog server. This significantly improves troubleshooting capabilities for Threat Intel imports.

    Health events:
    - import started
    - import successful
    - import failed (including failure reason)

    Import events:
    - ip observable import
    - ip+port observable import
    - domain observable import
    - domain+port observable import
    - uri observable import
    """

    def __init__(self, **kwargs):
        self.cef_sender = CEFSender(**kwargs)

    def import_observables(self):
        cef_dict = {}
        observable_count = 0
        self.cef_sender.send_cef(
                            name="Observable Import started",
                            signature_id=1000,
                            severity="Low",
                            )
        try:
            observable_count = self.cust_import_observables()

        except Exception as e:
            failure_reason = "{0} ({1})".format(e,e)
            cef_dict["deviceCustomString1"]=failure_reason
            cef_dict["deviceCustomString2Label"]="Failure Reason"
            self.cef_sender.send_cef(
                                name="Observable Import failed",
                                signature_id=4000,
                                severity="High",
                                cef_dict=cef_dict,
                                )
        else:
            cef_dict["deviceCustomNumber1"]=observable_count
            cef_dict["deviceCustomNumber2Label"]="Observables imported"
            self.cef_sender.send_cef(
                                name="Observable Import successful",
                                signature_id=1001,
                                severity="Low",
                                cef_dict=cef_dict,
                                )

    def cust_import_observables(self):
        """This method is supposed to be overwritten by child classes to provide the actual parsing. For each observable, self.cef_sender.send_cef(...) needs to be called."""
        self.send_observable("ip", "192.0.2.1")
        self.send_observable("IP", "192.0.2.2", port="1234")
        self.send_observable("domain", "bad.example.com")
        self.send_observable("Domain", "example.com", port="1234")
        self.send_observable("URL", "http://www.example.com/tasty-spam/eggs.php?ham=delicious&bacon=lovely")

    def send_observable(self, observable_type, observable, port=None, **kwargs):
        """Send observables of types IP, domain or URI via configured CEFSender."""

        observable_type = observable_type.lower()
        severity = "Low"
        cef_dict = {}

        if observable_type in ["ip", "ip_addr"]:
            cef_dict["destinationAddress"] = observable
            if not port:
                name = "IP Observable Import"
                signature_id = 2000
            else:
                name = "IP+Port Observable Import"
                signature_id = 2001
                cef_dict["destinationAddress"] = observable
        elif observable_type in ["domain"]:
            cef_dict["destinationHostname"] = observable
            if not port:
                name = "Domain Observable Import"
                signature_id = 2010
            else:
                name = "Domain+Port Observable Import"
                signature_id = 2011
                cef_dict["destinationPort"] = observable
        elif observable_type in ["uri", "url"]:
            name = "URI Observable Import"
            signature_id = 2020
            # to-do: split observable by requestUrlHost, requestUrlPort and requestUrlProtocol
            cef_dict["requestUrlHost"] = observable
        else:
            name = "Invalid Observable"
            signature_id = 4001
            severity = "Medium"

        self.cef_sender.send_cef(
                            name=name,
                            signature_id=signature_id,
                            severity=severity,
                            cef_dict=cef_dict,
                            )

# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent
