"""Regression tests for owner-scoped ticket closure by cyhy-domain."""

import copy
from datetime import datetime
import imp
import os

import mock
import pytest

from common_fixtures import database  # noqa: F401
from paths import REPO_ROOT

cyhy_domain = imp.load_source(
    "cyhy_domain_ticket_owner", os.path.join(REPO_ROOT, "bin", "cyhy-domain")
)


class Document(dict):
    """Record command writes without requiring unrelated document fields."""

    def __init__(self, *args, **kwargs):
        super(Document, self).__init__(*args, **kwargs)
        self.save = mock.Mock()
        self.add_event = mock.Mock()


@pytest.fixture
def removal_data(database):
    """Use real MongoDB selection and isolated command collaborators."""
    collection = database["_test_domain_ticket_owner"]
    collection.drop()
    rows = [
        ("target", "OWNER_A", "shared.example.org", True),
        ("foreign", "OWNER_B", "shared.example.org", True),
        ("second", "OWNER_A", "second.example.org", True),
        ("foreign_second", "OWNER_B", "second.example.org", True),
        ("other_domain", "OWNER_A", "retained.example.org", True),
        ("closed", "OWNER_A", "shared.example.org", False),
    ]
    tickets = {}
    for key, owner, hostname, is_open in rows:
        ticket = Document(
            _id=key,
            owner=owner,
            hostname=hostname,
            open=is_open,
            time_closed=None,
            events=[],
        )
        tickets[key] = ticket
        collection.insert(dict(ticket))

    db = mock.MagicMock()
    request = Document(
        agency={"name": "Example organization"},
        hostnames=["shared.example.org", "second.example.org", "retained.example.org"],
    )
    db.RequestDoc.get_by_owner.return_value = request
    db.HostDoc.get_by_hostname.return_value = []
    db.TicketDoc.find.side_effect = lambda query: [
        tickets[row["_id"]] for row in collection.find(query)
    ]
    for name in ("HostScanDoc", "PortScanDoc", "VulnScanDoc"):
        getattr(db, name).collection.update.return_value = {"nModified": 0}
    yield db, request, tickets
    collection.drop()


@pytest.mark.parametrize(
    "domains,closed_ids",
    [
        (["shared.example.org"], {"target"}),
        (["shared.example.org", "second.example.org"], {"target", "second"}),
    ],
)
def test_remove_closes_only_matching_owner_tickets(removal_data, domains, closed_ids):
    """Leave another owner's matching hostnames and closed tickets unchanged."""
    db, request, tickets = removal_data
    before = {key: copy.deepcopy(dict(ticket)) for key, ticket in tickets.items()}
    original_hostnames = list(request["hostnames"])
    timestamp = datetime(2026, 9, 10, 12, 0)

    with mock.patch.object(cyhy_domain.util, "utcnow", return_value=timestamp):
        cyhy_domain.remove(db, "OWNER_A", domains)

    for key, ticket in tickets.items():
        if key in closed_ids:
            assert ticket["open"] is False
            assert ticket["time_closed"] == timestamp
            ticket.save.assert_called_once_with()
            ticket.add_event.assert_called_once_with(
                cyhy_domain.TICKET_EVENT.CLOSED,
                "hostname moved out of scope",
                time=timestamp,
            )
        else:
            assert dict(ticket) == before[key]
            assert not ticket.save.called
            assert not ticket.add_event.called
    assert request["hostnames"] == [
        hostname for hostname in original_hostnames if hostname not in domains
    ]
    request.save.assert_called_once_with()


def test_remove_rejects_unowned_domain_before_ticket_changes(removal_data):
    """The existing ownership check must still precede all ticket writes."""
    db, request, tickets = removal_data
    with pytest.raises(SystemExit):
        cyhy_domain.remove(db, "OWNER_A", ["unowned.example.org"])
    assert not db.TicketDoc.find.called
    assert not request.save.called
    assert all(not ticket.save.called for ticket in tickets.values())
