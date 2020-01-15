#!/usr/bin/env py.test -v

# built-in python libraries

# third-party libraries (install with pip)
from bson.objectid import ObjectId
from netaddr import IPSet, IPAddress as ip
import pytest

# local libraries
from common_fixtures import database
from cyhy.core.common import TICKET_EVENT, UNKNOWN_OWNER
from cyhy.db import VulnTicketManager, IPPortTicketManager, IPTicketManager
from cyhy.util import util

# IPS = [ip('10.0.0.1'), ip('192.168.1.1'), ip('fe80::8BAD:F00D'), ip('fe80::dead:beef')]
IPS = [ip("10.0.0.1"), ip("192.168.1.1"), ip("172.20.20.20"), ip("10.0.0.2")]
PORTS = [0, 123, 456, 10123]
PORTSCAN_PORTS = [21, 23, 389]
SOURCE_IDS = [1, 2, 3]
SOURCE_NMAP = "nmap"
SOURCE_NESSUS = "nessus"
OWNER = "TEST"
PROTOCOLS = ["tcp"]

PS_1 = {
    "ip": IPS[0],
    "ip_int": long(IPS[0]),
    "port": PORTSCAN_PORTS[1],
    "state": "open",
    "protocol": "tcp",
    "service": "telnet",
    "source": SOURCE_NMAP,
    "source_id": SOURCE_IDS[0],
    "owner": OWNER,
    "severity": 0,
    "cvss_base_score": None,
    "name": "Potentially Risky Service Detected: telnet",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}
PS_2 = {
    "ip": IPS[1],
    "ip_int": long(IPS[1]),
    "port": PORTSCAN_PORTS[2],
    "state": "open",
    "protocol": "tcp",
    "service": "ldap",
    "source": SOURCE_NMAP,
    "source_id": SOURCE_IDS[0],
    "owner": OWNER,
    "severity": 0,
    "cvss_base_score": None,
    "name": "Potentially Risky Service Detected: ldap",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}
PS_3 = {
    "ip": IPS[2],
    "ip_int": long(IPS[2]),
    "port": PORTSCAN_PORTS[0],
    "state": "open",
    "protocol": "tcp",
    "service": "ftp",
    "source": SOURCE_NMAP,
    "source_id": SOURCE_IDS[0],
    "owner": UNKNOWN_OWNER,
    "severity": 0,
    "cvss_base_score": None,
    "name": "Potentially Risky Service Detected: ftp",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}

VULN_1 = {
    "ip": IPS[0],
    "ip_int": long(IPS[0]),
    "port": PORTS[0],
    "protocol": "tcp",
    "service": "ntp",
    "source": SOURCE_NESSUS,
    "plugin_id": SOURCE_IDS[0],
    "owner": OWNER,
    "severity": 2,
    "cvss_base_score": 10.0,
    "plugin_name": "Looks for stuff",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}
VULN_2 = {
    "ip": IPS[1],
    "ip_int": long(IPS[1]),
    "port": PORTS[1],
    "protocol": "tcp",
    "service": "ntp",
    "source": SOURCE_NESSUS,
    "plugin_id": SOURCE_IDS[1],
    "owner": OWNER,
    "severity": 2,
    "cvss_base_score": 10.0,
    "plugin_name": "Looks for stuff",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}
VULN_3 = {
    "ip": IPS[3],
    "ip_int": long(IPS[3]),
    "port": PORTS[2],
    "protocol": "tcp",
    "service": "ntp",
    "source": SOURCE_NESSUS,
    "plugin_id": SOURCE_IDS[1],
    "owner": UNKNOWN_OWNER,
    "severity": 2,
    "cvss_base_score": 10.0,
    "plugin_name": "Looks for stuff",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}
VULN_4 = {
    "ip": IPS[1],
    "ip_int": long(IPS[1]),
    "port": PORTS[2],
    "protocol": "udp",
    "service": "ntp",
    "source": SOURCE_NESSUS,
    "plugin_id": SOURCE_IDS[1],
    "owner": OWNER,
    "severity": 2,
    "cvss_base_score": 10.0,
    "plugin_name": "Looks for stuff",
    "_id": ObjectId(),
    "time": util.utcnow(),
    "latest": True,
}


@pytest.fixture
def vuln_ticket_manager1(database):
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.ips = IPS
    vtm.ports = PORTS
    vtm.source_ids = SOURCE_IDS
    return vtm


@pytest.fixture
def vuln_ticket_manager2(database):
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.ips = IPS[1:]
    vtm.ports = PORTS
    vtm.source_ids = SOURCE_IDS
    return vtm


@pytest.fixture
def vuln_ticket_manager3(database):
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    return vtm


@pytest.fixture
def ip_port_ticket_manager1(database):
    ptm = IPPortTicketManager(database, PROTOCOLS)
    return ptm


@pytest.fixture
def ip_port_ticket_manager2(database):
    database.tickets.remove()
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.open_ticket(VULN_1, "test vuln detected")
    vtm.open_ticket(VULN_2, "test vuln detected")
    ptm = IPPortTicketManager(database, PROTOCOLS)
    return ptm


@pytest.fixture
def ip_port_ticket_manager3(database):
    database.tickets.remove()
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.open_ticket(VULN_1, "test vuln detected")
    vtm.open_ticket(VULN_2, "test vuln detected")
    vtm.open_ticket(VULN_4, "test vuln detected")
    ptm = IPPortTicketManager(database, PROTOCOLS)
    return ptm


@pytest.fixture
def ip_port_ticket_manager4(database):
    ptm = IPPortTicketManager(database, PROTOCOLS)
    ptm.ips = IPS
    ptm.ports = PORTSCAN_PORTS
    return ptm


@pytest.fixture
def ip_ticket_manager1(database):
    ptm = IPTicketManager(database)
    return ptm


@pytest.fixture
def ip_ticket_manager2(database):
    database.tickets.remove()
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.open_ticket(VULN_1, "test vuln detected")
    vtm.open_ticket(VULN_2, "test vuln detected")
    ptm = IPTicketManager(database)
    return ptm


@pytest.fixture
def database_w_vulns(database):
    database.vuln_scans.remove()
    for v in [VULN_1, VULN_2, VULN_3]:
        vuln = database.VulnScanDoc(v)
        vuln.save()
    return database


@pytest.fixture
def database_w_udp_vulns(database):
    database.vuln_scans.remove()
    database.tickets.remove()
    for v in [VULN_1, VULN_2, VULN_4]:
        vuln = database.VulnScanDoc(v)
        vuln.save()
    vtm = VulnTicketManager(database, SOURCE_NESSUS)
    vtm.open_ticket(VULN_1, "test vuln detected")
    vtm.open_ticket(VULN_2, "test vuln detected")
    vtm.open_ticket(VULN_4, "test vuln detected")
    return database


# @pytest.mark.parametrize(('sources'), [SOURCE_NESSUSS_1, SOURCE_NESSUSS_2, SOURCE_NESSUSS_3, SOURCE_NESSUSS_4], scope='class')
class TestVulnTickets:
    def test_clear_tickets(self, database):
        print("number of tickets to remove:", database.tickets.count())
        database.tickets.remove()
        assert database.tickets.count() == 0, "tickets did not clear from database"

    def test_add_one_ticket(self, database, vuln_ticket_manager1):
        assert database.tickets.count() == 0, "collection should be empty"
        vuln_ticket_manager1.open_ticket(VULN_1, "test vuln detected")
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "ticket should be open"
        vuln_ticket_manager1.close_tickets()
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "ticket should still be open"
        ticket = database.TicketDoc.find_one({"open": True})
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.OPENED
        ), "last event of ticket should be opened"

    def test_ticket_closed(self, database, vuln_ticket_manager1):
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "ticket should be open"
        vuln_ticket_manager1.close_tickets()
        assert (
            database.tickets.find({"open": False}).count() == 1
        ), "ticket should be closed"
        ticket = database.TicketDoc.find_one({"open": False})
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.CLOSED
        ), "last event of ticket should be closed"

    def test_reopen_ticket(self, database, vuln_ticket_manager1):
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": False}).count() == 1
        ), "ticket should be closed"
        vuln_ticket_manager1.open_ticket(VULN_1, "test vuln detected")
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"
        ticket = database.TicketDoc.find_one({"open": True})
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.REOPENED
        ), "last event of ticket should be reopened"
        vuln_ticket_manager1.close_tickets()
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"

    def test_close_other_ips(self, database, vuln_ticket_manager2):
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "1 ticket should be closed"
        vuln_ticket_manager2.close_tickets()  # ip is not in list, should not close
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"

    def test_verify_ticket(self, database, vuln_ticket_manager1):
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"
        vuln_ticket_manager1.open_ticket(VULN_1, "test vuln detected")
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"
        vuln_ticket_manager1.close_tickets()  # ip is not in list, should not close
        assert (
            database.tickets.find({"open": True}).count() == 1
        ), "1 ticket should be open"
        assert (
            database.tickets.find({"open": False}).count() == 0
        ), "0 ticket should be closed"
        ticket = database.TicketDoc.find_one({"open": True})
        assert len(ticket["events"]) == 4, "ticket should have 4 events"
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.VERIFIED
        ), "last event of ticket should be verified"

    def test_ready_to_clear_vuln_latest_flags(self, database):
        vtm = VulnTicketManager(database, SOURCE_NESSUS)
        assert (
            vtm.ready_to_clear_vuln_latest_flags() == False
        ), "should not be ready at init"
        vtm.ports = PORTS
        assert (
            vtm.ready_to_clear_vuln_latest_flags() == False
        ), "should not be ready with only ports set"
        vtm.ips = IPS
        assert (
            vtm.ready_to_clear_vuln_latest_flags() == False
        ), "should not be ready without source ids set"
        vtm.source_ids = SOURCE_IDS
        assert (
            vtm.ready_to_clear_vuln_latest_flags() == True
        ), "should be ready as all attributes are set"

    def test_add_unknown_ticket(self, database, vuln_ticket_manager1):
        database.tickets.remove()
        assert database.tickets.count() == 0, "collection should be empty"
        vuln_ticket_manager1.open_ticket(VULN_3, "test vuln detected")
        assert database.tickets.count() == 1, "collection should have 1 document"
        assert (
            database.tickets.find({"open": True}).count() == 0
        ), "ticket should be closed since owner was unknown"

    # TODO test whitelisting


class TestIPPortTickets:
    def test_clear_tickets(self, database):
        print("number of tickets to remove:", database.tickets.count())
        database.tickets.remove()
        assert database.tickets.count() == 0, "tickets did not clear from database"

    def test_add_two_tickets(self, database, vuln_ticket_manager1):
        assert database.tickets.count() == 0, "collection should be empty"
        vuln_ticket_manager1.open_ticket(VULN_1, "test vuln detected")
        vuln_ticket_manager1.open_ticket(VULN_2, "test vuln detected")
        assert database.tickets.count() == 2

    def test_init(self, ip_port_ticket_manager1):
        ptm = ip_port_ticket_manager1
        assert ptm.ips == IPSet(), "ips should be an empty IPSet at init"
        assert ptm.ports == set(), "ports should be an empty set"

    def test_close_none_1(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 2

    def test_close_none_2(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = PORTS
        ip_port_ticket_manager2.ips = IPSet(IPS[2:])
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 2

    def test_close_all(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = PORTS
        ip_port_ticket_manager2.ips = IPSet(IPS)
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 0
        assert database.tickets.find({"open": False}).count() == 2

    def test_close_all_max_ports(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = xrange(1, 65536)
        ip_port_ticket_manager2.ips = IPSet(IPS)
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 0
        assert database.tickets.find({"open": False}).count() == 2

    def test_do_not_close_port_0(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = xrange(1, 1024)
        ip_port_ticket_manager2.ips = IPSet(IPS)
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 1
        assert database.tickets.find({"open": False}).count() == 1

    def test_close_one_unseen(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = PORTS
        ip_port_ticket_manager2.ips = IPSet(IPS)
        ip_port_ticket_manager2.port_open(VULN_1["ip"], VULN_1["port"])
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 1
        assert database.tickets.find({"open": False}).count() == 1

    def test_close_one_uncovered_port(self, database, ip_port_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_port_ticket_manager2.ports = PORTS[1:]
        ip_port_ticket_manager2.ips = IPSet(IPS)
        ip_port_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 1
        assert database.tickets.find({"open": False}).count() == 1


class TestIPTickets:
    def test_clear_tickets(self, database):
        print("number of tickets to remove:", database.tickets.count())
        database.tickets.remove()
        assert database.tickets.count() == 0, "tickets did not clear from database"

    def test_add_two_tickets(self, database, vuln_ticket_manager1):
        assert database.tickets.count() == 0, "collection should be empty"
        vuln_ticket_manager1.open_ticket(VULN_1, "test vuln detected")
        vuln_ticket_manager1.open_ticket(VULN_2, "test vuln detected")
        assert database.tickets.count() == 2

    def test_init(self, ip_ticket_manager1):
        ptm = ip_ticket_manager1
        assert ptm.ips == IPSet(), "ips should be an empty IPSet at init"

    def test_close_none_1(self, database, ip_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 2

    def test_close_none_2(self, database, ip_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_ticket_manager2.ips = IPSet(IPS[2:])
        ip_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 2

    def test_close_all(self, database, ip_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_ticket_manager2.ips = IPSet(IPS)
        ip_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 0
        assert database.tickets.find({"open": False}).count() == 2

    def test_close_one(self, database, ip_ticket_manager2):
        assert database.tickets.find({"open": True}).count() == 2
        ip_ticket_manager2.ips = IPSet([IPS[0]])
        ip_ticket_manager2.close_tickets()
        assert database.tickets.find({"open": True}).count() == 1
        assert database.tickets.find({"open": False}).count() == 1

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>


class TestVulnLatestClear:
    """CYHY-56"""

    def test_database_setup(self, database_w_vulns):
        assert (
            database_w_vulns.vuln_scans.count() == 3
        ), "vuln_scans collection not expected size"

    def test_IPTm_none_up(self, database_w_vulns, ip_ticket_manager1):
        tm = ip_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 0

    def test_IPTm_some_up(self, database_w_vulns, ip_ticket_manager1):
        tm = ip_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.ip_up(IPS[0])
        tm.ip_up(IPS[1])
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 2

    def test_IPTm_all_up(self, database_w_vulns, ip_ticket_manager1):
        tm = ip_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.ip_up(IPS[0])
        tm.ip_up(IPS[1])
        tm.ip_up(IPS[2])
        tm.ip_up(IPS[3])
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 3

    def test_IPPortTm_vuln_none_open(self, database_w_vulns, ip_port_ticket_manager1):
        tm = ip_port_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 0

    def test_IPPortTm_vuln_some_open(self, database_w_vulns, ip_port_ticket_manager1):
        tm = ip_port_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.port_open(VULN_1["ip"], VULN_1["port"])
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 1

    def test_IPPortTm_vuln_more_open(self, database_w_vulns, ip_port_ticket_manager1):
        tm = ip_port_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.port_open(VULN_1["ip"], VULN_1["port"])
        tm.port_open(VULN_2["ip"], VULN_2["port"])
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 2

    def test_IPPortTm_vuln_all_open(self, database_w_vulns, ip_port_ticket_manager1):
        tm = ip_port_ticket_manager1
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.port_open(VULN_1["ip"], VULN_1["port"])
        tm.port_open(VULN_2["ip"], VULN_2["port"])
        tm.port_open(VULN_3["ip"], VULN_3["port"])
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 3

    def test_VulnTm_readiness(self, vuln_ticket_manager3):
        tm = vuln_ticket_manager3
        assert tm.ready_to_clear_vuln_latest_flags() == False
        tm.ips = IPS
        assert tm.ready_to_clear_vuln_latest_flags() == False
        tm.source_ids = SOURCE_IDS
        assert tm.ready_to_clear_vuln_latest_flags() == False
        tm.ports = PORTS
        assert tm.ready_to_clear_vuln_latest_flags() == True

    def test_VulnTm_none_in_scope(self, database_w_vulns, vuln_ticket_manager3):
        tm = vuln_ticket_manager3
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = []
        tm.ports = []
        tm.source_ids = []
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 3

    def test_VulnTm_some_in_scope(self, database_w_vulns, vuln_ticket_manager3):
        tm = vuln_ticket_manager3
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS[:1]
        tm.ports = PORTS[:1]
        tm.source_ids = SOURCE_IDS[:1]
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 2

    def test_VulnTm_all_in_scope(self, database_w_vulns, vuln_ticket_manager3):
        tm = vuln_ticket_manager3
        assert (
            database_w_vulns.vuln_scans.find({"latest": True}).count() == 3
        ), "wrong number of latest vuln_scans"
        tm.ips = IPS
        tm.ports = PORTS
        tm.source_ids = SOURCE_IDS
        tm.clear_vuln_latest_flags()
        assert database_w_vulns.vuln_scans.find({"latest": True}).count() == 0


class TestUDPVulnClose:
    """CYHY-127"""

    def test_database_setup(self, database_w_udp_vulns):
        assert (
            database_w_udp_vulns.vuln_scans.count() == 3
        ), "vuln_scans collection not expected size"
        assert (
            database_w_udp_vulns.tickets.count() == 3
        ), "tickets collection not expected size"

    def test_close_all_max_ports(self, database_w_udp_vulns, ip_port_ticket_manager3):
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 3
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "tcp"}).count()
            == 2
        ), "tcp tickets count not expected"
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp tickets count not expected"
        ip_port_ticket_manager3.ports = xrange(1, 65536)
        ip_port_ticket_manager3.ips = IPSet(IPS)
        ip_port_ticket_manager3.close_tickets()
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 0

    def test_close_all_udp_tickets(self, database_w_udp_vulns, vuln_ticket_manager3):
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 3
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "tcp"}).count()
            == 2
        ), "tcp tickets count not expected"
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp tickets count not expected"
        vuln_ticket_manager3.ports = PORTS[:2]
        vuln_ticket_manager3.ips = IPSet(IPS[:2])
        vuln_ticket_manager3.source_ids = SOURCE_IDS
        vuln_ticket_manager3.close_tickets()
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 0

    def test_seen_udp_vuln_ticket(self, database_w_udp_vulns, vuln_ticket_manager3):
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 3
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "tcp"}).count()
            == 2
        ), "tcp tickets count not expected"
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp tickets count not expected"
        vuln_ticket_manager3.source_ids = SOURCE_IDS
        vuln_ticket_manager3.ports = xrange(1, 65536)
        vuln_ticket_manager3.ips = IPSet(IPS)
        vuln_ticket_manager3.open_ticket(VULN_4, "test vuln detected")
        vuln_ticket_manager3.close_tickets()
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp ticket should not have been closed"

    def test_seen_udp_port_ticket(self, database_w_udp_vulns, ip_port_ticket_manager3):
        assert database_w_udp_vulns.tickets.find({"open": True}).count() == 3
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "tcp"}).count()
            == 2
        ), "tcp tickets count not expected"
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp tickets count not expected"
        ip_port_ticket_manager3.source_ids = SOURCE_IDS
        ip_port_ticket_manager3.ports = xrange(1, 65536)
        ip_port_ticket_manager3.ips = IPSet(IPS[:2])
        ip_port_ticket_manager3.port_open(
            IPS[1], PORTS[2]
        )  # saw PORTS[2] open on IPS[1] (VULN_4)
        ip_port_ticket_manager3.close_tickets()
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "udp"}).count()
            == 1
        ), "udp ticket should not have been closed"
        assert (
            database_w_udp_vulns.tickets.find({"open": True, "protocol": "tcp"}).count()
            == 0
        ), "tcp tickets should have been closed"


class TestIPPortNonVulnScanTickets:
    """CYHYDEV-777"""

    def test_add_two_ps_tickets(self, database, ip_port_ticket_manager4):
        database.tickets.remove()
        assert database.tickets.count() == 0, "collection should be empty"
        ip_port_ticket_manager4.port_open(PS_1["ip"], PS_1["port"])
        ip_port_ticket_manager4.port_open(PS_2["ip"], PS_2["port"])
        ip_port_ticket_manager4.open_ticket(PS_1, "potentially risky service detected")
        ip_port_ticket_manager4.open_ticket(PS_2, "potentially risky service detected")
        assert database.tickets.find({"source": SOURCE_NMAP}).count() == 2

    def test_ps_tickets_closed(self, database, ip_port_ticket_manager4):
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be open"
        # Next lines should close the PS_1 and PS_2 tickets since they were not seen
        ip_port_ticket_manager4.close_tickets()
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be closed"
        ticket = database.tickets.find_one({"open": False, "source": SOURCE_NMAP})
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.CLOSED
        ), "last event of ticket should be closed"

    def test_reopen_ps_tickets(self, database, ip_port_ticket_manager4):
        assert (
            database.tickets.find({"source": SOURCE_NMAP}).count() == 2
        ), "collection should have 2 nmap tickets"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be closed"
        # Next lines should re-open the PS_1 and PS_2 tickets
        ip_port_ticket_manager4.port_open(PS_1["ip"], PS_1["port"])
        ip_port_ticket_manager4.port_open(PS_2["ip"], PS_2["port"])
        ip_port_ticket_manager4.open_ticket(PS_1, "potentially risky service detected")
        ip_port_ticket_manager4.open_ticket(PS_2, "potentially risky service detected")
        assert (
            database.tickets.find({"source": SOURCE_NMAP}).count() == 2
        ), "collection should have 2 nmap tickets"
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap ticket should be open"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 0
        ), "0 nmap tickets should be closed"
        ticket = database.tickets.find_one({"open": True, "source": SOURCE_NMAP})
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.REOPENED
        ), "last event of nmap ticket should be reopened"
        # Next line should should not close either ticket since they were both seen
        ip_port_ticket_manager4.close_tickets()
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be open"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 0
        ), "0 nmap ticket should be closed"

    def test_verify_ps_ticket(self, database, ip_port_ticket_manager4):
        assert (
            database.tickets.find({"source": SOURCE_NMAP}).count() == 2
        ), "collection should have 2 nmap tickets"
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be open"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 0
        ), "0 nmap tickets should be closed"
        # Next lines should verify the already-open PS_1 ticket
        ip_port_ticket_manager4.port_open(PS_1["ip"], PS_1["port"])
        ip_port_ticket_manager4.open_ticket(PS_1, "potentially risky service detected")
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 2
        ), "2 nmap tickets should be open"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 0
        ), "0 nmap tickets should be closed"
        # Next line should:
        #  Close the ticket for PS_2, since ip/port was not seen
        #  Not close the ticket for PS_1, since ip/port was just seen
        ip_port_ticket_manager4.close_tickets()
        assert (
            database.tickets.find({"open": True, "source": SOURCE_NMAP}).count() == 1
        ), "1 nmap ticket should be open"
        assert (
            database.tickets.find({"open": False, "source": SOURCE_NMAP}).count() == 1
        ), "1 nmap ticket should be closed"
        ticket = database.tickets.find_one({"open": True, "source": SOURCE_NMAP})
        assert len(ticket["events"]) == 4, "nmap ticket should have 4 events"
        assert (
            ticket["events"][-1]["action"] == TICKET_EVENT.VERIFIED
        ), "last event of nmap ticket should be verified"

    def test_add_unknown_ps_ticket(self, database, ip_port_ticket_manager4):
        assert (
            database.tickets.find(
                {"owner": UNKNOWN_OWNER, "source": SOURCE_NMAP}
            ).count()
            == 0
        ), "collection should have 0 UNKNOWN_OWNER nmap tickets"
        ip_port_ticket_manager4.open_ticket(PS_3, "potentially risky service detected")
        assert (
            database.tickets.find(
                {"open": False, "owner": UNKNOWN_OWNER, "source": SOURCE_NMAP}
            ).count()
            == 1
        ), "collection should have 1 closed UNKNOWN_OWNER nmap ticket"
