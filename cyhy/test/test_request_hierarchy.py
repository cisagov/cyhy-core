#!/usr/bin/env py.test -v

# third-party libraries (install with pip)
import pytest

# local libraries
from common_fixtures import database
from cyhy.db.database import RequestDoc


def make_org(_id, children=None, stakeholder=False, retired=False):
    """Build a minimal org_info entry like _load_org_info() produces."""
    return {
        "_id": _id,
        "children": children or [],
        "retired": retired,
        "stakeholder": stakeholder,
    }


def make_org_info(*orgs):
    return {o["_id"]: o for o in orgs}


class TestDescendantsTraversal:
    """Unit tests for RequestDoc._descendants().

    These exercise the pure in-memory hierarchy walk and require no database.
    """

    def test_owner_not_included_and_finds_all_levels(self):
        # ROOT -> A -> B ; ROOT -> C
        org_info = make_org_info(
            make_org("ROOT", ["A", "C"]),
            make_org("A", ["B"]),
            make_org("B"),
            make_org("C"),
        )
        result = RequestDoc._descendants(org_info, "ROOT")
        assert sorted(result) == ["A", "B", "C"]
        assert "ROOT" not in result  # owner itself is never a descendant

    def test_leaf_owner_returns_empty(self):
        org_info = make_org_info(make_org("LEAF"))
        assert RequestDoc._descendants(org_info, "LEAF") == []

    def test_unknown_owner_raises(self):
        org_info = make_org_info(make_org("ROOT"))
        with pytest.raises(ValueError):
            RequestDoc._descendants(org_info, "NOPE")

    def test_stakeholders_only_filters_membership_but_still_traverses(self):
        # ROOT -> MID(non-stakeholder) -> LEAF(stakeholder)
        # MID must be excluded from results, but LEAF must still be reached.
        org_info = make_org_info(
            make_org("ROOT", ["MID"], stakeholder=True),
            make_org("MID", ["LEAF"], stakeholder=False),
            make_org("LEAF", stakeholder=True),
        )
        result = RequestDoc._descendants(org_info, "ROOT", stakeholders_only=True)
        assert sorted(result) == ["LEAF"]

    def test_retired_prunes_entire_subtree_by_default(self):
        # ROOT -> RETIRED -> LIVE_GRANDCHILD
        # RETIRED and everything under it should be excluded.
        org_info = make_org_info(
            make_org("ROOT", ["RETIRED"]),
            make_org("RETIRED", ["LIVE_GRANDCHILD"], retired=True),
            make_org("LIVE_GRANDCHILD"),
        )
        assert RequestDoc._descendants(org_info, "ROOT") == []

    def test_include_retired_includes_retired_and_subtree(self):
        org_info = make_org_info(
            make_org("ROOT", ["RETIRED"]),
            make_org("RETIRED", ["GRANDCHILD"], retired=True),
            make_org("GRANDCHILD"),
        )
        result = RequestDoc._descendants(org_info, "ROOT", include_retired=True)
        assert sorted(result) == ["GRANDCHILD", "RETIRED"]

    def test_shared_subtree_returns_no_duplicates(self):
        # Both P1 and P2 are children of ROOT and both point at SHARED.
        org_info = make_org_info(
            make_org("ROOT", ["P1", "P2"]),
            make_org("P1", ["SHARED"]),
            make_org("P2", ["SHARED"]),
            make_org("SHARED"),
        )
        result = RequestDoc._descendants(org_info, "ROOT")
        assert sorted(result) == ["P1", "P2", "SHARED"]
        assert len(result) == len(set(result))  # no dupes

    def test_cycle_terminates_and_excludes_owner(self):
        # A -> B -> A ; must not infinite loop, and the cycle back to the owner
        # must not add the owner to its own descendants.
        org_info = make_org_info(
            make_org("A", ["B"]),
            make_org("B", ["A"]),
        )
        result = RequestDoc._descendants(org_info, "A")
        assert sorted(result) == ["B"]
        assert "A" not in result  # owner is never a descendant, even via a cycle

    def test_self_referential_owner_excluded(self):
        # A lists itself as a child; owner must still be excluded.
        org_info = make_org_info(make_org("A", ["A", "B"]), make_org("B"))
        result = RequestDoc._descendants(org_info, "A")
        assert sorted(result) == ["B"]

    def test_null_children_field_is_handled(self):
        # children stored as None (rather than missing) must not raise.
        org_info = make_org_info(
            {"_id": "A", "children": None, "stakeholder": False, "retired": False}
        )
        assert RequestDoc._descendants(org_info, "A") == []

    def test_dangling_child_reference_is_skipped(self):
        # ROOT references GHOST which has no org document.
        org_info = make_org_info(make_org("ROOT", ["GHOST", "REAL"]), make_org("REAL"))
        result = RequestDoc._descendants(org_info, "ROOT")
        assert sorted(result) == ["REAL"]


# IDs used by the integration fixture below.  Prefixed so cleanup only touches
# these documents and leaves any other request documents untouched.
_HIERARCHY_IDS = [
    "TEST_ROOT",
    "TEST_A",
    "TEST_B",
    "TEST_C",
    "TEST_RETIRED",
    "TEST_UNDER_RETIRED",
]

_HIERARCHY_DOCS = [
    # ROOT -> A, B
    {
        "_id": "TEST_ROOT",
        "children": ["TEST_A", "TEST_B"],
        "stakeholder": True,
        "retired": False,
    },
    # A -> C
    {"_id": "TEST_A", "children": ["TEST_C"], "stakeholder": True, "retired": False},
    # B -> C (shared with A), B -> RETIRED (non-stakeholder parent)
    {
        "_id": "TEST_B",
        "children": ["TEST_C", "TEST_RETIRED"],
        "stakeholder": False,
        "retired": False,
    },
    # C is a shared leaf
    {"_id": "TEST_C", "children": [], "stakeholder": True, "retired": False},
    # RETIRED prunes its subtree unless include_retired=True
    {
        "_id": "TEST_RETIRED",
        "children": ["TEST_UNDER_RETIRED"],
        "stakeholder": True,
        "retired": True,
    },
    {
        "_id": "TEST_UNDER_RETIRED",
        "children": [],
        "stakeholder": True,
        "retired": False,
    },
]


@pytest.fixture
def request_hierarchy(database):
    """Insert a known request hierarchy, then remove it after the test.

    Documents are inserted directly into the collection (bypassing mongokit
    validation) since only the hierarchy fields matter here.
    """
    database.requests.remove({"_id": {"$in": _HIERARCHY_IDS}})
    database.requests.insert(_HIERARCHY_DOCS)
    yield database
    database.requests.remove({"_id": {"$in": _HIERARCHY_IDS}})


class TestGetAllDescendantsIntegration:
    """End-to-end tests that exercise _load_org_info() against MongoDB."""

    def test_default_excludes_retired_subtree_and_dedupes(self, request_hierarchy):
        result = request_hierarchy.RequestDoc.get_all_descendants("TEST_ROOT")
        assert sorted(result) == ["TEST_A", "TEST_B", "TEST_C"]

    def test_include_retired(self, request_hierarchy):
        result = request_hierarchy.RequestDoc.get_all_descendants(
            "TEST_ROOT", include_retired=True
        )
        assert sorted(result) == [
            "TEST_A",
            "TEST_B",
            "TEST_C",
            "TEST_RETIRED",
            "TEST_UNDER_RETIRED",
        ]

    def test_stakeholders_only(self, request_hierarchy):
        # TEST_B is a non-stakeholder: excluded from membership but still
        # traversed, so TEST_C (reached via TEST_B) is still found.
        result = request_hierarchy.RequestDoc.get_all_descendants(
            "TEST_ROOT", stakeholders_only=True
        )
        assert sorted(result) == ["TEST_A", "TEST_C"]

    def test_unknown_owner_raises(self, request_hierarchy):
        with pytest.raises(ValueError):
            request_hierarchy.RequestDoc.get_all_descendants("TEST_DOES_NOT_EXIST")
