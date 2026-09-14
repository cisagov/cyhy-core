# built-in python libraries
import contextlib
import imp
import os
from StringIO import StringIO
import sys

# third-party libraries (install with pip)
from bson.objectid import ObjectId
import mock
from netaddr import IPAddress as ip
import pytest

# local libraries
from common_fixtures import database
from cyhy.core.common import TICKET_EVENT
import cyhy.db.database as db_module
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


def save_ticket(
    database,
    ip_address,
    owner,
    hostname,
    is_open=True,
    port=80,
    protocol="tcp",
    id=None,
):
    ticket = database.TicketDoc()
    if id is not None:
        ticket["_id"] = id
    ticket["details"] = {"name": "test finding"}
    ticket["hostname"] = hostname
    ticket["owner"] = owner
    ticket["port"] = port
    ticket["protocol"] = protocol
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

    def report_line(self, hostname, ip_address, owner, name, port=80, protocol="tcp"):
        """The line the remaining-ticket report is expected to print."""
        return "\t%s\t%s\t%s\t%s\t%s\t%s" % (
            hostname,
            ip_address,
            port,
            protocol,
            owner,
            self.tickets[name],
        )


@contextlib.contextmanager
def captured_stdout():
    """Redirect stdout, since capsys does not span another fixture's setup."""
    original = sys.stdout
    sys.stdout = StringIO()
    try:
        yield sys.stdout
    finally:
        sys.stdout = original


def run_remove(database, owner, domains, tickets):
    """Call remove(), capturing what it prints."""
    with captured_stdout() as out:
        cyhy_domain.remove(database, owner, domains)
    return Removal(database, tickets, out.getvalue())


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

    Tickets are per port and protocol, so this is the ordinary case of one host
    with several open findings rather than a contrived one.

    The ids ascend in an order that disagrees with the expected report order, and
    the tickets are inserted in yet another order, so that dropping either the
    port and protocol or the id from the sort key changes the output.  Without
    that these assertions would pass whatever the sort key was.
    """
    reset(database)
    save_host(database, IP_CARRIED, [{"hostname": DOMAIN, "owner": OWNER}])
    save_request(database, OWNER, [DOMAIN])
    ids = [ObjectId() for _ in range(4)]
    tickets = {}
    # Insertion order, which becomes the collection's natural order.
    for name, port, protocol, id in (
        ("https_udp", 443, "udp", ids[0]),
        ("https_tcp", 443, "tcp", ids[1]),
        ("http_b", 80, "tcp", ids[3]),
        ("http_a", 80, "tcp", ids[2]),
    ):
        tickets[name] = save_ticket(
            database,
            IP_UNRELATED,
            OWNER,
            DOMAIN,
            port=port,
            protocol=protocol,
            id=id,
        )
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

    def test_orders_tickets_sharing_a_shape(self, removal_with_duplicate_shapes):
        # Hostname, IP address and owner do not identify a ticket, so port and
        # protocol order them and the ticket id breaks the remaining tie.
        report = removal_with_duplicate_shapes
        expected = "\n".join(
            report.report_line(
                DOMAIN, IP_UNRELATED, OWNER, name, port=port, protocol=protocol
            )
            for name, port, protocol in (
                ("http_a", 80, "tcp"),
                ("http_b", 80, "tcp"),
                ("https_tcp", 443, "tcp"),
                ("https_udp", 443, "udp"),
            )
        )
        assert expected in report.output

    def test_silent_when_nothing_remains(self, removal_with_nothing_left):
        assert "WARNING" not in removal_with_nothing_left.output


class TestRemoveSurvivesAPartialHostFailure:
    """A save failure while stripping the hostnames entries must be re-runnable.

    Those entries are the only record of which IP addresses a domain resolved to,
    so if the tickets were closed after the stripping, a failure part way through
    would leave the tickets on the already-stripped IP addresses unfindable.
    """

    @pytest.fixture
    def partial_failure(self, database):
        reset(database)
        for ip_address in (IP_CARRIED, IP_SECOND, IP_UNRELATED):
            save_host(database, ip_address, [{"hostname": DOMAIN, "owner": OWNER}])
        save_request(database, OWNER, [DOMAIN, KEPT_DOMAIN])
        tickets = {
            "first": save_ticket(database, IP_CARRIED, OWNER, DOMAIN),
            "second": save_ticket(database, IP_SECOND, OWNER, DOMAIN),
            "third": save_ticket(database, IP_UNRELATED, OWNER, DOMAIN),
        }

        original_save = db_module.HostDoc.save
        calls = []

        def failing_save(self, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("simulated host document write failure")
            return original_save(self, *args, **kwargs)

        with mock.patch.object(db_module.HostDoc, "save", failing_save):
            with captured_stdout():
                with pytest.raises(RuntimeError):
                    cyhy_domain.remove(database, OWNER, [DOMAIN])
        return Removal(database, tickets, "")

    def test_tickets_are_closed_despite_the_failure(self, partial_failure):
        for name in ("first", "second", "third"):
            assert partial_failure.closed_for_scope_change(name)

    def test_request_document_is_untouched(self, partial_failure):
        hostnames = partial_failure.db.requests.find_one({"_id": OWNER})["hostnames"]
        assert DOMAIN in hostnames

    def test_rerun_completes(self, partial_failure):
        # The second attempt finds fewer hostnames entries, which no longer
        # matters because the tickets are already closed.
        rerun = run_remove(partial_failure.db, OWNER, [DOMAIN], partial_failure.tickets)
        assert rerun.db.requests.find_one({"_id": OWNER})["hostnames"] == [KEPT_DOMAIN]
        assert rerun.db.hosts.find({"hostnames.hostname": DOMAIN}).count() == 0
        assert rerun.db.tickets.find({"hostname": DOMAIN, "open": True}).count() == 0


class TestRemoveRequestAndHosts:
    def test_domains_removed_from_request(self, removal):
        assert removal.db.requests.find_one({"_id": OWNER})["hostnames"] == [
            KEPT_DOMAIN
        ]

    def test_hostnames_entries_removed(self, removal):
        for ip_address in (IP_CARRIED, IP_SECOND):
            host = removal.db.hosts.find_one({"_id": long(ip_address)})
            assert host["hostnames"] == []
