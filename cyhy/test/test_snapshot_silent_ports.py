# third-party libraries (install with pip)
from bson.objectid import ObjectId
from netaddr import IPAddress as ip
import pytest

# local libraries
from common_fixtures import ch_db, database

OWNER = "OWNER"
DESCENDANT = "DESCENDANT"
OTHER_OWNER = "OTHER"

IP_A = ip("10.0.0.1")
IP_B = ip("10.0.0.2")

ALL_COLLECTIONS = (
    "host_scans",
    "hosts",
    "port_scans",
    "requests",
    "snapshots",
    "tickets",
    "vuln_scans",
)


def save_host_scan(database, ip_address, owner, hostname, silent_port_count=None):
    """Create a latest host scan, optionally recording a silent port count."""
    doc = database.HostScanDoc()
    doc["accuracy"] = 100
    doc["hostname"] = hostname
    doc["name"] = "Linux 3.X"
    doc["owner"] = owner
    if silent_port_count is not None:
        doc["silent_port_count"] = silent_port_count
    doc.ip = ip_address
    doc.save()
    return doc


def save_port_scan(database, ip_address, owner, port, state="silent"):
    """Create a latest port scan, by default one recorded as tcpwrapped."""
    doc = database.PortScanDoc()
    doc["hostname"] = None
    doc["owner"] = owner
    doc["port"] = port
    doc["protocol"] = "tcp"
    doc["reason"] = "syn-ack"
    doc["service"] = {"name": "tcpwrapped"} if state == "silent" else {"name": "http"}
    doc["source"] = "nmap"
    doc["state"] = state
    doc.ip = ip_address
    doc.save()
    return doc


def supersede(doc):
    doc["latest"] = False
    doc.save()


def snapshot(ch_db, owner, descendants=()):
    return ch_db.create_snapshot(
        owner, ObjectId(), descendants_included=list(descendants)
    )


@pytest.fixture
def clean_database(database):
    for collection in ALL_COLLECTIONS:
        database[collection].remove()
    return database


class TestSilentPortCount:
    def test_unset_without_silent_ports(self, clean_database, ch_db):
        save_host_scan(clean_database, IP_A, OWNER, None)
        save_port_scan(clean_database, IP_A, OWNER, 80, state="open")
        assert "silent_port_count" not in snapshot(ch_db, OWNER)

    def test_unset_when_host_scans_record_zero(self, clean_database, ch_db):
        save_host_scan(clean_database, IP_A, OWNER, None, silent_port_count=0)
        assert "silent_port_count" not in snapshot(ch_db, OWNER)

    def test_counts_port_scans_from_before_the_change(self, clean_database, ch_db):
        for port in (1, 2, 3):
            save_port_scan(clean_database, IP_A, OWNER, port)
        assert snapshot(ch_db, OWNER)["silent_port_count"] == 3

    def test_counts_each_hostname_on_an_ip(self, clean_database, ch_db):
        """Host scans are written per hostname, giving hostnames x ports."""
        save_host_scan(clean_database, IP_A, OWNER, "a.gov", silent_port_count=5)
        save_host_scan(clean_database, IP_A, OWNER, "b.gov", silent_port_count=5)
        assert snapshot(ch_db, OWNER)["silent_port_count"] == 10

    def test_adds_both_sources(self, clean_database, ch_db):
        """An IP not yet rescanned still has silent port scans."""
        for port in (1, 2):
            save_port_scan(clean_database, IP_A, OWNER, port)
        save_host_scan(clean_database, IP_B, OWNER, None, silent_port_count=5)
        assert snapshot(ch_db, OWNER)["silent_port_count"] == 7

    def test_includes_descendants(self, clean_database, ch_db):
        save_host_scan(clean_database, IP_A, OWNER, "a.gov", silent_port_count=4)
        save_host_scan(clean_database, IP_A, DESCENDANT, "d.gov", silent_port_count=6)
        assert snapshot(ch_db, OWNER, [DESCENDANT])["silent_port_count"] == 10

    def test_ignores_superseded_scans_and_other_owners(self, clean_database, ch_db):
        save_host_scan(clean_database, IP_A, OWNER, None, silent_port_count=4)
        supersede(
            save_host_scan(clean_database, IP_A, OWNER, None, silent_port_count=100)
        )
        supersede(save_port_scan(clean_database, IP_A, OWNER, 1))
        save_host_scan(clean_database, IP_B, OTHER_OWNER, None, silent_port_count=100)
        save_port_scan(clean_database, IP_B, OTHER_OWNER, 1)
        assert snapshot(ch_db, OWNER)["silent_port_count"] == 4
