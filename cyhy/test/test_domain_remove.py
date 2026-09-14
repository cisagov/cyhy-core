# built-in python libraries
import imp
import os
from StringIO import StringIO
import sys

# third-party libraries (install with pip)
from bson.objectid import ObjectId
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


def save_ticket(database, ip_address, owner, hostname, is_open=True, port=80, id=None):
    ticket = database.TicketDoc()
    if id is not None:
        ticket["_id"] = id
    ticket["details"] = {"name": "test finding"}
    ticket["hostname"] = hostname
    ticket["owner"] = owner
    ticket["port"] = port
    ticket["protocol"] = "tcp"
    ticket["source"] = "test_source"
    ticket["source_id"] = 1
    ticket.ip = ip_address
    ticket.add_event(TICKET_EVENT.OPENED, "test finding detected")
    if not is_open:
        ticket["open"] = False
    ticket.save()
    return ticket["_id"]


class Removal(object):
    """What a remove() run left behind, plus everything it printed."""

    def __init__(self, database, tickets, output):
        self.db = database
        self.tickets = tickets
        self.output = output

    def is_open(self, name):
        return self.db.tickets.find_one({"_id": self.tickets[name]})["open"]

    def closed_events(self, name):
        ticket = self.db.tickets.find_one({"_id": self.tickets[name]})
        return [
            e["reason"] for e in ticket["events"] if e["action"] == TICKET_EVENT.CLOSED
        ]

    def closed_for_scope_change(self, name):
        """Whether the removal closed the ticket, rather than it being closed
        beforehand."""
        return not self.is_open(name) and self.closed_events(name) == [
            "hostname moved out of scope"
        ]

    def report_line(self, hostname, ip_address, owner, name):
        """The line the remaining-ticket report is expected to print."""
        return "\t%s\t%s\t%s\t%s" % (hostname, ip_address, owner, self.tickets[name])


def run_remove(database, owner, domains, tickets):
    """Call remove(), capturing what it prints.

    pytest's capsys does not span another fixture's setup phase, so stdout is
    redirected here instead.
    """
    original = sys.stdout
    sys.stdout = StringIO()
    try:
        cyhy_domain.remove(database, owner, domains)
        return Removal(database, tickets, sys.stdout.getvalue())
    finally:
        sys.stdout = original


def reset(database):
    for collection in ALL_COLLECTIONS:
        database[collection].remove()


@pytest.fixture
def removal(database):
    """Run remove() over every shape of ticket that can carry a removed domain."""
    reset(database)
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
        # Coincidental FQDN matches on an IP address that does not carry the
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
    return run_remove(database, OWNER, [DOMAIN, SECOND_DOMAIN], tickets)


@pytest.fixture
def removal_with_duplicate_shapes(database):
    """Run remove() where remaining tickets share hostname, IP address and owner.

    Tickets are per port, so this is the ordinary case of one host with two open
    findings rather than a contrived one.
    """
    reset(database)
    save_host(database, IP_CARRIED, [{"hostname": DOMAIN, "owner": OWNER}])
    save_request(database, OWNER, [DOMAIN])
    lower_id, higher_id = ObjectId(), ObjectId()
    # Inserted with the higher id first, so the collection's natural order is the
    # reverse of ascending id order.  Without that this test cannot fail.
    tickets = {
        "second": save_ticket(
            database, IP_UNRELATED, OWNER, DOMAIN, port=443, id=higher_id
        ),
        "first": save_ticket(
            database, IP_UNRELATED, OWNER, DOMAIN, port=80, id=lower_id
        ),
    }
    return run_remove(database, OWNER, [DOMAIN], tickets)


@pytest.fixture
def removal_with_nothing_left(database):
    """Run remove() where every matching ticket is closed by the removal."""
    reset(database)
    save_host(database, IP_CARRIED, [{"hostname": DOMAIN, "owner": OWNER}])
    save_request(database, OWNER, [DOMAIN, KEPT_DOMAIN])
    tickets = {
        "carried": save_ticket(database, IP_CARRIED, OWNER, DOMAIN),
        "kept": save_ticket(database, IP_CARRIED, OWNER, KEPT_DOMAIN),
    }
    return run_remove(database, OWNER, [DOMAIN], tickets)


class TestRemoveTicketClosure:
    def test_ticket_on_carrying_ip_closed(self, removal):
        assert removal.closed_for_scope_change("carried")

    def test_stale_owner_ticket_closed(self, removal):
        # The domain is leaving scope, so a ticket recording an owner that
        # predates the request documents still has to be closed.  Nothing else
        # would ever close it once the domain is in no request document.
        assert removal.closed_for_scope_change("carried_stale")

    def test_second_domain_closed(self, removal):
        assert removal.closed_for_scope_change("second")

    def test_coincidental_match_on_same_owner_left_open(self, removal):
        # The organization still owns this IP address and it never resolved from
        # the removed domain, so the finding is still in scope.
        assert removal.is_open("unrelated_same_owner")

    def test_coincidental_match_on_other_owner_left_open(self, removal):
        assert removal.is_open("unrelated_other_owner")

    def test_domain_on_another_removed_domains_ip_left_open(self, removal):
        # Both domains are removed in one command, so the IP addresses must be
        # matched per domain rather than pooled.
        assert removal.is_open("crossed")

    def test_unremoved_domain_left_open(self, removal):
        assert removal.is_open("kept")

    def test_closure_counts(self, removal):
        assert removal.db.tickets.find({"open": True}).count() == 4
        assert removal.db.tickets.find({"open": False}).count() == 4

    def test_already_closed_ticket_not_reclosed(self, removal):
        assert removal.closed_events("already_closed") == []


class TestRemoveRemainingTicketReport:
    def test_reports_how_many_remain(self, removal):
        assert "WARNING - 3 open ticket(s)" in removal.output

    def test_lists_each_remaining_ticket(self, removal):
        # Hostname, IP address, owner and ticket id, so the operator can look
        # them up.
        for name, ip_address, owner in (
            ("unrelated_same_owner", IP_UNRELATED, OWNER),
            ("unrelated_other_owner", IP_UNRELATED, OTHER_OWNER),
            ("crossed", IP_SECOND, OWNER),
        ):
            line = removal.report_line(DOMAIN, ip_address, owner, name)
            assert line in removal.output

    def test_omits_domains_that_were_not_removed(self, removal):
        assert KEPT_DOMAIN not in removal.output

    def test_omits_tickets_it_closed(self, removal):
        for name in ("carried", "carried_stale", "second", "already_closed"):
            assert str(removal.tickets[name]) not in removal.output

    def test_lists_them_in_a_stable_order(self, removal):
        # Sorted by hostname, IP address and owner, so repeated runs and
        # different query orders produce identical output.
        expected = "\n".join(
            removal.report_line(DOMAIN, ip_address, owner, name)
            for ip_address, owner, name in (
                (IP_SECOND, OWNER, "crossed"),
                (IP_UNRELATED, OTHER_OWNER, "unrelated_other_owner"),
                (IP_UNRELATED, OWNER, "unrelated_same_owner"),
            )
        )
        assert expected in removal.output

    def test_orders_tickets_sharing_a_shape_by_id(self, removal_with_duplicate_shapes):
        # Hostname, IP address and owner do not distinguish two findings on
        # different ports, so the ticket id breaks the tie.
        report = removal_with_duplicate_shapes
        expected = "\n".join(
            report.report_line(DOMAIN, IP_UNRELATED, OWNER, name)
            for name in ("first", "second")
        )
        assert expected in report.output

    def test_silent_when_nothing_remains(self, removal_with_nothing_left):
        assert "WARNING" not in removal_with_nothing_left.output


class TestRemoveRequestAndHosts:
    def test_domains_removed_from_request(self, removal):
        assert removal.db.requests.find_one({"_id": OWNER})["hostnames"] == [
            KEPT_DOMAIN
        ]

    def test_hostnames_entries_removed(self, removal):
        for ip_address in (IP_CARRIED, IP_SECOND):
            host = removal.db.hosts.find_one({"_id": long(ip_address)})
            assert host["hostnames"] == []
