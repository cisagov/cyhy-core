# third-party libraries (install with pip)
from netaddr import IPAddress as ip, IPSet
import pytest

# local libraries
from common_fixtures import ch_db, database
from cyhy.core.common import TICKET_EVENT

ORIG_OWNER = "ORIG"
NEW_OWNER = "NEW"
OTHER_OWNER = "OTHER"
# An owner recorded on documents that predates the current request document
# owner, which happens because moving a domain has not until now updated host
# documents.
STALE_OWNER = "STALE"
IP_OWNER = "GLOBAL"
REASON = "test owner change"
# In production host_scans and port_scans come from nmap while vuln_scans come
# from nessus.  These tests only care about the owner field, so they use a
# neutral source rather than implying a provenance that is not being exercised.
SOURCE = "test_source"

# change_ownership() moves this network.  change_hostname_ownership() moves a
# hostname that resolves to IP_CARRIED, which sits inside it.
NETWORK = IPSet(["10.0.0.0/24"])
IP_CARRIED = ip("10.0.0.1")
# Also carries HOSTNAME, but its entry and documents still record STALE_OWNER.
IP_STALE = ip("10.0.0.2")
# Outside NETWORK, and its host document does not carry HOSTNAME.
IP_OUTSIDE = ip("10.1.0.1")

HOSTNAME = "moved.gov"
OTHER_HOSTNAME = "unrelated.gov"

SCAN_COLLECTIONS = ("host_scans", "port_scans", "vuln_scans")
ALL_COLLECTIONS = ("hosts",) + SCAN_COLLECTIONS + ("tickets",)

# The fields each scan document class requires beyond the ones shared by all of
# them.  PortScanDoc and VulnScanDoc disagree on the type of "service", so these
# cannot be collapsed into a single set of values.
SCAN_EXTRAS = {
    "host_scans": {"accuracy": 100, "name": "Linux 3.X"},
    "port_scans": {
        "port": 80,
        "protocol": "tcp",
        "reason": "syn-ack",
        "service": {},
        "state": "open",
    },
    "vuln_scans": {
        "cvss_base_score": 0.0,
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "severity": 0,
    },
}
SCAN_DOC_CLASSES = {
    "host_scans": "HostScanDoc",
    "port_scans": "PortScanDoc",
    "vuln_scans": "VulnScanDoc",
}


def save_host(database, ip_address, owner, hostnames):
    """Create a host document, with hostnames as a list of {hostname, owner}."""
    host = database.HostDoc()
    host.init(ip_address, owner, [0.0, 0.0], "NETSCAN1")
    host["hostnames"] = hostnames
    host.save()
    return host


def save_scan(database, collection, ip_address, owner, hostname):
    """Create a scan document in the named collection.

    The hostname field is not declared in the HostScanDoc and PortScanDoc
    structures, but the document classes are schemaless and cyhy-commander
    writes it on all three, so it is set here the same way.
    """
    doc = getattr(database, SCAN_DOC_CLASSES[collection])()
    doc["hostname"] = hostname
    doc["latest"] = True
    doc["owner"] = owner
    doc["source"] = SOURCE
    doc.update(SCAN_EXTRAS[collection])
    doc.ip = ip_address
    doc.save()
    return doc


def save_ticket(database, ip_address, owner, hostname):
    """Create an open ticket document."""
    ticket = database.TicketDoc()
    # mongokit treats an empty dict as a missing required field, so details
    # needs at least one key.
    ticket["details"] = {"name": "test finding"}
    ticket["hostname"] = hostname
    ticket["owner"] = owner
    ticket["port"] = 80
    ticket["protocol"] = "tcp"
    ticket["source"] = SOURCE
    ticket["source_id"] = 1
    ticket.ip = ip_address
    # An empty events list counts as missing too, and a real ticket always has
    # at least the event that opened it.
    ticket.add_event(TICKET_EVENT.OPENED, "test finding detected")
    ticket.save()
    return ticket


def owner_of(database, collection, spec):
    """Return the owner recorded on the single document matching spec."""
    return database[collection].find_one(spec)["owner"]


def count(database, collection, spec):
    """Return how many documents in a collection match spec.

    Checking a single document proves the intended update happened, but only a
    count catches an update that reached further than intended.
    """
    return database[collection].find(spec).count()


def change_events(ticket):
    """Return the owner change events recorded on a ticket."""
    return [e for e in ticket["events"] if e["action"] == TICKET_EVENT.CHANGED]


def assert_change_event(ticket):
    """Assert that a ticket records exactly one owner change event."""
    events = change_events(ticket)
    assert len(events) == 1
    assert events[0]["reason"] == REASON
    assert events[0]["delta"] == [{"from": ORIG_OWNER, "to": NEW_OWNER, "key": "owner"}]


@pytest.fixture
def clean_database(database):
    for collection in ALL_COLLECTIONS:
        database[collection].remove()
    return database


@pytest.fixture
def database_w_network_docs(clean_database):
    """Documents on one IP inside the moved network and one outside it."""
    save_host(clean_database, IP_CARRIED, ORIG_OWNER, [])
    save_host(clean_database, IP_OUTSIDE, ORIG_OWNER, [])
    for collection in SCAN_COLLECTIONS:
        save_scan(clean_database, collection, IP_CARRIED, ORIG_OWNER, None)
        save_scan(clean_database, collection, IP_OUTSIDE, ORIG_OWNER, None)
    save_ticket(clean_database, IP_CARRIED, ORIG_OWNER, None)
    save_ticket(clean_database, IP_OUTSIDE, ORIG_OWNER, None)
    return clean_database


@pytest.fixture
def network_owner_changed(database_w_network_docs, ch_db):
    ch_db.change_ownership(ORIG_OWNER, NEW_OWNER, NETWORK, REASON)
    return database_w_network_docs


@pytest.fixture
def database_w_hostname_docs(clean_database):
    """Documents covering each way a hostname can appear on a scan document.

    IP_CARRIED has HOSTNAME in its host document, so its scan documents were
    stamped with the hostname's owner.  IP_OUTSIDE does not, standing in for an
    nmap-discovered reverse DNS name that happens to match HOSTNAME and was
    therefore stamped with the IP's owner instead.
    """
    save_host(
        clean_database,
        IP_CARRIED,
        IP_OWNER,
        [{"hostname": HOSTNAME, "owner": ORIG_OWNER}],
    )
    save_host(clean_database, IP_OUTSIDE, ORIG_OWNER, [])
    for collection in SCAN_COLLECTIONS:
        save_scan(clean_database, collection, IP_CARRIED, ORIG_OWNER, HOSTNAME)
    save_scan(clean_database, "host_scans", IP_OUTSIDE, ORIG_OWNER, HOSTNAME)
    save_scan(clean_database, "port_scans", IP_CARRIED, OTHER_OWNER, OTHER_HOSTNAME)
    # An IP-only scan document on the carried IP address, owned by ORIG_OWNER so
    # that the hostname predicate is the only thing keeping it out of the update.
    save_scan(clean_database, "port_scans", IP_CARRIED, ORIG_OWNER, None)
    # A second IP address carrying the hostname whose entry and documents still
    # record an owner that predates the request documents.
    save_host(
        clean_database,
        IP_STALE,
        IP_OWNER,
        [{"hostname": HOSTNAME, "owner": STALE_OWNER}],
    )
    for collection in SCAN_COLLECTIONS:
        save_scan(clean_database, collection, IP_STALE, STALE_OWNER, HOSTNAME)
    # Tickets mirroring the scan documents above, so that a ticket update which
    # reaches too far shows up as a count mismatch.  The second one is a ticket
    # left over from when the hostname still resolved to IP_OUTSIDE.
    save_ticket(clean_database, IP_CARRIED, ORIG_OWNER, HOSTNAME)
    save_ticket(clean_database, IP_OUTSIDE, ORIG_OWNER, HOSTNAME)
    save_ticket(clean_database, IP_CARRIED, ORIG_OWNER, None)
    save_ticket(clean_database, IP_CARRIED, OTHER_OWNER, OTHER_HOSTNAME)
    save_ticket(clean_database, IP_STALE, STALE_OWNER, HOSTNAME)
    return clean_database


@pytest.fixture
def hostname_owner_changed(database_w_hostname_docs, ch_db):
    ch_db.change_hostname_ownership(ORIG_OWNER, NEW_OWNER, [HOSTNAME], REASON)
    return database_w_hostname_docs


class TestChangeOwnership:
    def test_hosts_reowned(self, network_owner_changed):
        assert (
            owner_of(network_owner_changed, "hosts", {"_id": long(IP_CARRIED)})
            == NEW_OWNER
        )

    def test_scans_reowned(self, network_owner_changed):
        for collection in SCAN_COLLECTIONS:
            assert (
                owner_of(
                    network_owner_changed, collection, {"ip_int": long(IP_CARRIED)}
                )
                == NEW_OWNER
            )

    def test_tickets_reowned_with_event(self, network_owner_changed):
        ticket = network_owner_changed.tickets.find_one({"ip_int": long(IP_CARRIED)})
        assert ticket["owner"] == NEW_OWNER
        assert_change_event(ticket)

    def test_only_documents_in_network_reowned(self, network_owner_changed):
        # Each collection holds one document inside the moved network and one
        # outside it, so these counts fail if the update reached either too far
        # or not far enough.
        for collection in ALL_COLLECTIONS:
            assert count(network_owner_changed, collection, {"owner": NEW_OWNER}) == 1
            assert count(network_owner_changed, collection, {"owner": ORIG_OWNER}) == 1

    def test_documents_outside_network_untouched(self, network_owner_changed):
        spec = {"ip_int": long(IP_OUTSIDE)}
        assert (
            owner_of(network_owner_changed, "hosts", {"_id": long(IP_OUTSIDE)})
            == ORIG_OWNER
        )
        for collection in SCAN_COLLECTIONS + ("tickets",):
            assert owner_of(network_owner_changed, collection, spec) == ORIG_OWNER
        ticket = network_owner_changed.tickets.find_one(spec)
        assert change_events(ticket) == []


class TestChangeHostnameOwnership:
    def test_hostnames_entry_reowned(self, hostname_owner_changed):
        host = hostname_owner_changed.hosts.find_one({"_id": long(IP_CARRIED)})
        assert host["hostnames"] == [{"hostname": HOSTNAME, "owner": NEW_OWNER}]
        # The owner of the IP address itself is not a hostname owner and is left
        # alone.
        assert host["owner"] == IP_OWNER

    def test_scans_on_carried_ip_reowned(self, hostname_owner_changed):
        for collection in SCAN_COLLECTIONS:
            spec = {"ip_int": long(IP_CARRIED), "hostname": HOSTNAME}
            assert owner_of(hostname_owner_changed, collection, spec) == NEW_OWNER

    def test_scan_on_ip_not_carrying_hostname_untouched(self, hostname_owner_changed):
        # A discovered name that coincidentally matches the moved hostname must
        # not follow it, because it was never customer provided.
        spec = {"ip_int": long(IP_OUTSIDE), "hostname": HOSTNAME}
        assert owner_of(hostname_owner_changed, "host_scans", spec) == ORIG_OWNER

    def test_other_hostname_on_carried_ip_untouched(self, hostname_owner_changed):
        spec = {"ip_int": long(IP_CARRIED), "hostname": OTHER_HOSTNAME}
        assert owner_of(hostname_owner_changed, "port_scans", spec) == OTHER_OWNER

    def test_ip_only_scan_on_carried_ip_untouched(self, hostname_owner_changed):
        # A scan document with no hostname describes the IP address rather than
        # any hostname resolving to it, so moving a hostname must leave it alone
        # even when the original owner also owns the IP-only document.
        spec = {"ip_int": long(IP_CARRIED), "hostname": None}
        assert owner_of(hostname_owner_changed, "port_scans", spec) == ORIG_OWNER

    def test_tickets_reowned_with_event(self, hostname_owner_changed):
        ticket = hostname_owner_changed.tickets.find_one(
            {"ip_int": long(IP_CARRIED), "hostname": HOSTNAME}
        )
        assert ticket["owner"] == NEW_OWNER
        assert_change_event(ticket)

    def test_ticket_on_ip_not_carrying_hostname_also_reowned(
        self, hostname_owner_changed
    ):
        # Unlike the scan documents, tickets are deliberately not restricted to
        # the IP addresses currently carrying the hostname, so a ticket left over
        # from an IP address the hostname no longer resolves to still follows it.
        spec = {"ip_int": long(IP_OUTSIDE), "hostname": HOSTNAME}
        assert owner_of(hostname_owner_changed, "tickets", spec) == NEW_OWNER

    def test_ip_only_ticket_untouched(self, hostname_owner_changed):
        spec = {"ip_int": long(IP_CARRIED), "hostname": None}
        assert owner_of(hostname_owner_changed, "tickets", spec) == ORIG_OWNER

    def test_stale_hostnames_entry_reowned(self, hostname_owner_changed):
        # The move is authoritative, so an entry recording an owner that predates
        # the request documents is reconciled rather than skipped (#177).
        host = hostname_owner_changed.hosts.find_one({"_id": long(IP_STALE)})
        assert host["hostnames"] == [{"hostname": HOSTNAME, "owner": NEW_OWNER}]

    def test_stale_scans_reowned(self, hostname_owner_changed):
        for collection in SCAN_COLLECTIONS:
            spec = {"ip_int": long(IP_STALE), "hostname": HOSTNAME}
            assert owner_of(hostname_owner_changed, collection, spec) == NEW_OWNER

    def test_stale_ticket_not_reowned(self, hostname_owner_changed):
        # Tickets keep the owner predicate, so a stale one is left behind.  It is
        # corrected by the next move from its recorded owner.
        spec = {"ip_int": long(IP_STALE), "hostname": HOSTNAME}
        assert owner_of(hostname_owner_changed, "tickets", spec) == STALE_OWNER

    def test_ownership_counts_after_move(self, hostname_owner_changed):
        # Both IP addresses carrying the hostname move, whatever owner they
        # recorded beforehand.
        for collection in SCAN_COLLECTIONS:
            assert count(hostname_owner_changed, collection, {"owner": NEW_OWNER}) == 2
        # Both tickets carrying the hostname under ORIG_OWNER move, regardless of
        # IP address.  The IP-only, other-owner, and stale tickets stay put.
        assert count(hostname_owner_changed, "tickets", {"owner": NEW_OWNER}) == 2
        assert count(hostname_owner_changed, "tickets", {"owner": ORIG_OWNER}) == 1
        assert count(hostname_owner_changed, "tickets", {"owner": OTHER_OWNER}) == 1
        assert count(hostname_owner_changed, "tickets", {"owner": STALE_OWNER}) == 1

    def test_removal_by_new_owner_finds_the_scans(self, hostname_owner_changed):
        # Guards cisagov/cyhy-core#177: cyhy-domain remove() clears the latest
        # flag with an owner-scoped query, so the moved scan documents have to be
        # reachable under the new owner once the hostname has moved.
        for collection in SCAN_COLLECTIONS:
            assert (
                hostname_owner_changed[collection]
                .find(
                    {
                        "latest": True,
                        "owner": NEW_OWNER,
                        "hostname": {"$in": [HOSTNAME]},
                    }
                )
                .count()
                == 2
            )
