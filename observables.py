import string

class SyslogSender:
    """Send out Syslog messages."""

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


# requires ~/.vimrc to contain "set modeline":
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 autoindent
