
# built-in python libraries
import imp
import os

# third-party libraries (install with pip)
from netaddr import IPAddress as ip
import pytest

# local libraries
from common_fixtures import database
from cyhy.core.common import TICKET_EVENT
from paths import REPO_ROOT

# cyhy-domain is a script rather than an importable module, so it is loaded by
# path.  This follows the approach proposed in #179.
cyhy_domain = imp.load_source(
    "cyhy_domain_under_test", os.path.join(REPO_ROOT, "bin", "cyhy-domain")
)

OWNER = "OWNER"
STALE_OWNER = "STALE"
OTHER_OWNER = "OTHER"
IP_OWNER = "GLOBAL"

DOMAIN = "removed.gov"
# Removed in the same command as DOMAIN, resolving to a different IP address.
SECOND_DOMAIN = "second.gov"
# Owned by OWNER but not removed.
KEPT_DOMAIN = "kept.gov"

# Carries DOMAIN in its host document.
IP_CARRIED = ip("10.0.0.1")
# Carries SECOND_DOMAIN, not DOMAIN.
IP_SECOND = ip("10.0.0.2")
# Carries neither; stands in for an IP address whose Nessus FQDN happens to
# match DOMAIN.
IP_UNRELATED = ip("10.0.0.3")

SCAN_COLLECTIONS = ("host_scans", "port_scans", "vuln_scans")
ALL_COLLECTIONS = ("hosts", "requests", "tickets") + SCAN_COLLECTIONS


def save_host(database, ip_address, hostnames):
    host = database.HostDoc()
    host.init(ip_address, IP_OWNER, [0.0, 0.0], "NETSCAN1")
    host["hostnames"] = hostnames
    host.save()
    return host


def save_request(database, owner, hostnames):
    request = database.RequestDoc()
    request["_id"] = owner
    request["agency"] = {"acronym": owner, "name": "Test organization"}
    request["hostnames"] = sorted(hostnames)
    request.save()
    return request


def save_ticket(database, ip_address, owner, hostname, is_open=True):
    ticket = database.TicketDoc()
    ticket["details"] = {"name": "test finding"}
    ticket["hostname"] = hostname
    ticket["owner"] = owner
    ticket["port"] = 80
    ticket["protocol"] = "tcp"
    ticket["source"] = "test_source"
    ticket["source_id"] = 1
    ticket.ip = ip_address
    ticket.add_event(TICKET_EVENT.OPENED, "test finding detected")
    if not is_open:
        ticket["open"] = False
    ticket.save()
    return ticket["_id"]


def is_open(database, ticket_id):
    return database.tickets.find_one({"_id": ticket_id})["open"]


def closed_for_scope_change(database, ticket_id):
    """Whether the ticket was closed by the removal rather than beforehand."""
    ticket = database.tickets.find_one({"_id": ticket_id})
    reasons = [
        e["reason"] for e in ticket["events"] if e["action"] == TICKET_EVENT.CLOSED
    ]
    return ticket["open"] is False and reasons == ["hostname moved out of scope"]


@pytest.fixture
def removal(database):
    """Run remove() over a fixture covering every shape of matching ticket.

    Returns the database and a mapping of descriptive names to ticket ids.
    """
    for collection in ALL_COLLECTIONS:
        database[collection].remove()

    save_host(database, IP_CARRIED, [{"hostname": DOMAIN, "owner": OWNER}])
    save_host(database, IP_SECOND, [{"hostname": SECOND_DOMAIN, "owner": OWNER}])
    save_host(database, IP_UNRELATED, [])
    save_request(database, OWNER, [DOMAIN, SECOND_DOMAIN, KEPT_DOMAIN])

    tickets = {
        # On the IP address that carries the domain, owned by the organization
        # the domain is being removed from.
        "carried": save_ticket(database, IP_CARRIED, OWNER, DOMAIN),
        # Same, but recording an owner that predates the request documents.
        "carried_stale": save_ticket(database, IP_CARRIED, STALE_OWNER, DOMAIN),
        # A coincidental FQDN match on an IP address that does not carry the
        # domain, stamped with that IP address's owner.
        "unrelated_same_owner": save_ticket(database, IP_UNRELATED, OWNER, DOMAIN),
        "unrelated_other_owner": save_ticket(
            database, IP_UNRELATED, OTHER_OWNER, DOMAIN
        ),
        # The domain on an IP address carrying a different removed domain.
        "crossed": save_ticket(database, IP_SECOND, OWNER, DOMAIN),
        # The second removed domain, on the IP address that carries it.
        "second": save_ticket(database, IP_SECOND, OWNER, SECOND_DOMAIN),
        # A domain that is not being removed.
        "kept": save_ticket(database, IP_CARRIED, OWNER, KEPT_DOMAIN),
        # Already closed before the removal ran.
        "already_closed": save_ticket(
            database, IP_CARRIED, OWNER, DOMAIN, is_open=False
        ),
    }

    cyhy_domain.remove(database, OWNER, [DOMAIN, SECOND_DOMAIN])
    return database, tickets


class TestRemoveTicketClosure:
    def test_ticket_on_carrying_ip_closed(self, removal):
        database, tickets = removal
        assert closed_for_scope_change(database, tickets["carried"])

    def test_stale_owner_ticket_closed(self, removal):
        # The domain is leaving scope, so a ticket recording an owner that
        # predates the request documents still has to be closed.  Nothing else
        # would ever close it once the domain is in no request document.
        database, tickets = removal
        assert closed_for_scope_change(database, tickets["carried_stale"])

    def test_second_domain_closed(self, removal):
        database, tickets = removal
        assert closed_for_scope_change(database, tickets["second"])

    def test_coincidental_match_on_same_owner_left_open(self, removal):
        # The organization still owns this IP address and it never resolved from
        # the removed domain, so the finding is still in scope.
        database, tickets = removal
        assert is_open(database, tickets["unrelated_same_owner"])

    def test_coincidental_match_on_other_owner_left_open(self, removal):
        database, tickets = removal
        assert is_open(database, tickets["unrelated_other_owner"])

    def test_domain_on_another_removed_domains_ip_left_open(self, removal):
        # Both domains are removed in one command, so the IP addresses must be
        # matched per domain rather than pooled.
        database, tickets = removal
        assert is_open(database, tickets["crossed"])

    def test_unremoved_domain_left_open(self, removal):
        database, tickets = removal
        assert is_open(database, tickets["kept"])

    def test_closure_counts(self, removal):
        database, tickets = removal
        assert database.tickets.find({"open": True}).count() == 4
        assert database.tickets.find({"open": False}).count() == 4

    def test_already_closed_ticket_not_reclosed(self, removal):
        database, tickets = removal
        ticket = database.tickets.find_one({"_id": tickets["already_closed"]})
        assert [
            e for e in ticket["events"] if e["action"] == TICKET_EVENT.CLOSED
        ] == []


class TestRemoveRequestAndHosts:
    def test_domains_removed_from_request(self, removal):
        database, _ = removal
        assert database.requests.find_one({"_id": OWNER})["hostnames"] == [KEPT_DOMAIN]

    def test_hostnames_entries_removed(self, removal):
        database, _ = removal
        for ip_address in (IP_CARRIED, IP_SECOND):
            host = database.hosts.find_one({"_id": long(ip_address)})
            assert host["hostnames"] == []
