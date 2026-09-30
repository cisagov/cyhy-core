"""Regression tests for request contact validation in cyhy-import."""

import copy
import imp
import io
import json
import os

import mock
import pytest

from cyhy.core.common import POC_TYPE
from paths import REPO_ROOT, input_path

cyhy_import = imp.load_source(
    "cyhy_import", os.path.join(REPO_ROOT, "bin", "cyhy-import")
)


@pytest.fixture
def request_data():
    """Return a fresh request document with no network scope."""
    with open(input_path("test-request.json")) as source:
        request = json.load(source)
    request["networks"] = []
    return request


@pytest.fixture
def import_db():
    """Keep imports away from a real database or GeoIP lookup."""
    db = mock.MagicMock()
    db.RequestDoc.get_by_owner.return_value = None
    with mock.patch.object(cyhy_import, "has_intersections", return_value=False):
        with mock.patch.object(cyhy_import, "has_restricted_ips", return_value=False):
            yield db


def contact(kind, index):
    """Build a contact using a reserved example domain."""
    result = {"email": "contact%d@example.org" % index}
    if kind is not None:
        result["type"] = kind
    return result


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("count", [2, 3])
def test_multiple_distribution_contacts_rejected(
    request_data, import_db, capsys, force, count
):
    """Reject multiple distribution contacts even with --force, before any write."""
    request_data["agency"]["contacts"] = [
        contact(POC_TYPE.DISTRO, i) for i in range(count)
    ]
    original = copy.deepcopy(request_data)

    assert not cyhy_import.import_request(
        import_db, request_data, "test.json", force=force
    )

    assert "at most one distribution contact" in capsys.readouterr().out
    assert request_data == original
    assert not import_db.mock_calls


@pytest.mark.parametrize(
    "kinds",
    [
        [],
        [POC_TYPE.DISTRO],
        [POC_TYPE.TECHNICAL, POC_TYPE.TECHNICAL],
        [POC_TYPE.DISTRO, POC_TYPE.TECHNICAL, POC_TYPE.TECHNICAL],
        [None, None, POC_TYPE.DISTRO],
    ],
)
def test_valid_contact_counts_imported(request_data, import_db, kinds):
    """Allow zero or one distribution contact and preserve other contact types."""
    request_data["agency"]["contacts"] = [
        contact(kind, i) for i, kind in enumerate(kinds)
    ]

    assert cyhy_import.import_request(import_db, request_data, "test.json")

    import_db.RequestDoc.return_value.save.assert_called_once_with()


def test_missing_contacts_imported(request_data, import_db):
    """Keep support for request documents without contacts."""
    del request_data["agency"]["contacts"]
    assert cyhy_import.import_request(import_db, request_data, "test.json")
    import_db.RequestDoc.return_value.save.assert_called_once_with()


@pytest.mark.parametrize("source", ["file", "stdin"])
def test_contact_validation_applies_to_both_inputs(
    request_data, import_db, tmpdir, source
):
    """File and stdin imports must both run the shared contact validation."""
    request_data["agency"]["contacts"] = [contact(POC_TYPE.DISTRO, i) for i in range(2)]
    content = json.dumps(request_data)
    if source == "file":
        filename = tmpdir.join("request.json")
        filename.write(content)
        success = cyhy_import.import_file(import_db, str(filename), force=True)
    else:
        with mock.patch.object(cyhy_import.sys, "stdin", io.StringIO(unicode(content))):
            success = cyhy_import.import_stdin(import_db, force=True)
    assert not success
    assert not import_db.mock_calls
