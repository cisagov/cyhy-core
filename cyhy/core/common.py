__all__ = ['STATUS', 'STAGE', 'TICKET_EVENT', 'UNKNOWN_OWNER', 'AGENCY_TYPE',
           'SCAN_TYPE', 'REPORT_TYPE', 'REPORT_PERIOD', 'POC_TYPE',
           'CONTROL_ACTION', 'CONTROL_TARGET', 'VulnScanNotFoundException']

from cyhy.util import Enumerator

STATUS = Enumerator('WAITING','READY', 'RUNNING', 'DONE')
STAGE = Enumerator('NETSCAN1', 'NETSCAN2', 'PORTSCAN', 'VULNSCAN', 'BASESCAN')
TICKET_EVENT = Enumerator('OPENED', 'REOPENED', 'VERIFIED', 'UNVERIFIED', 'CLOSED', 'CHANGED')
UNKNOWN_OWNER = 'UNKNOWN'
AGENCY_TYPE = Enumerator('FEDERAL', 'STATE', 'LOCAL', 'PRIVATE', 'TRIBAL', 'TERRITORIAL')
SCAN_TYPE = Enumerator('CYHY', 'DNSSEC', 'PHISHING')
REPORT_TYPE = Enumerator('CYHY', 'BOD', 'CYBEX', 'DNSSEC', 'PHISHING')
REPORT_PERIOD = Enumerator('WEEKLY', 'MONTHLY', 'QUARTERLY')
POC_TYPE = Enumerator('DISTRO', 'TECHNICAL') # addition for POC types
CONTROL_ACTION = Enumerator('PAUSE', 'STOP')
CONTROL_TARGET = Enumerator('COMMANDER')

class VulnScanNotFoundException(Exception):
    def __init__(self, ticket_id, vuln_scan_id, vuln_scan_time, *args):
        message = 'Ticket {}: referenced VulnScanDoc {} not found'.format(ticket_id, vuln_scan_id, vuln_scan_time)
        self.ticket_id = ticket_id
        self.vuln_scan_id = vuln_scan_id
        self.vuln_scan_time = vuln_scan_time
        super(VulnScanNotFoundException, self).__init__(message)
