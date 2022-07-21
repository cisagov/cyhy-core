__all__ = [
    "STATUS",
    "STAGE",
    "TICKET_EVENT",
    "UNKNOWN_OWNER",
    "AGENCY_TYPE",
    "SCAN_TYPE",
    "REPORT_TYPE",
    "REPORT_PERIOD",
    "POC_TYPE",
    "CONTROL_ACTION",
    "CONTROL_TARGET",
    "PortScanNotFoundException",
    "VulnScanNotFoundException",
]

from cyhy.util import Enumerator

STATUS = Enumerator("DONE", "READY", "RUNNING", "WAITING")
STAGE = Enumerator("BASESCAN", "NETSCAN1", "NETSCAN2", "PORTSCAN", "VULNSCAN")
TICKET_EVENT = Enumerator(
    "CHANGED", "CLOSED", "OPENED", "REOPENED", "UNVERIFIED", "VERIFIED"
)
UNKNOWN_OWNER = "UNKNOWN"
AGENCY_TYPE = Enumerator(
    "FEDERAL", "INTERNATIONAL", "LOCAL", "PRIVATE", "STATE", "TERRITORIAL", "TRIBAL"
)
SCAN_TYPE = Enumerator("CYHY", "DNSSEC", "PHISHING")
REPORT_TYPE = Enumerator(
    "BOD", "CYBEX", "CYHY", "CYHY_THIRD_PARTY", "DNSSEC", "PHISHING"
)
REPORT_PERIOD = Enumerator("MONTHLY", "QUARTERLY", "WEEKLY")
POC_TYPE = Enumerator("DISTRO", "TECHNICAL")  # addition for POC types
CONTROL_ACTION = Enumerator("PAUSE", "STOP")
CONTROL_TARGET = Enumerator("COMMANDER")


class PortScanNotFoundException(Exception):
    def __init__(self, ticket_id, port_scan_id, port_scan_time, *args):
        message = "Ticket {}: referenced PortScanDoc {} not found".format(
            ticket_id, port_scan_id, port_scan_time
        )
        self.ticket_id = ticket_id
        self.port_scan_id = port_scan_id
        self.port_scan_time = port_scan_time
        super(PortScanNotFoundException, self).__init__(message)


class VulnScanNotFoundException(Exception):
    def __init__(self, ticket_id, vuln_scan_id, vuln_scan_time, *args):
        message = "Ticket {}: referenced VulnScanDoc {} not found".format(
            ticket_id, vuln_scan_id, vuln_scan_time
        )
        self.ticket_id = ticket_id
        self.vuln_scan_id = vuln_scan_id
        self.vuln_scan_time = vuln_scan_time
        super(VulnScanNotFoundException, self).__init__(message)
