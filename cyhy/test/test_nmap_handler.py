#!/usr/bin/env py.test -vs

import os
import sys

me = os.path.realpath(__file__)
myDir = os.path.dirname(me)
sys.path.append(os.path.join(myDir, ".."))

import pytest

import cyhy.util as util
from cyhy.nmap.nmap_handler import NmapContentHander
from xml.sax import parse

TEST_NMAP_FILENAME = "inputs/test-fullscan.xml"


def pytest_runtest_makereport(item, call):
    if "incremental" in item.keywords:
        if call.excinfo is not None:
            parent = item.parent
            parent._previousfailed = item


def pytest_runtest_setup(item):
    if "incremental" in item.keywords:
        previousfailed = getattr(item.parent, "_previousfailed", None)
        if previousfailed is not None:
            pytest.xfail("previous test failed (%s)" % previousfailed.name)


class YourMom(object):
    """You should call back your Mom.  This test does."""

    def __init__(self):
        self.hosts = []
        self.end_callback_call_count = 0

    def netscan_host_callback(self, parsed_host):
        print "X" * 80
        util.pp(parsed_host)
        self.hosts.append(parsed_host)
        # import IPython; IPython.embed() #<<< BREAKPOINT >>>

    def end_callback(self):
        self.end_callback_call_count += 1


@pytest.fixture(scope="session")
def your_mom():
    return YourMom()


@pytest.mark.incremental
class TestNmapHandler:
    def test_parse(self, your_mom):
        # py.test doesn't allow __init__
        handler = NmapContentHander(
            your_mom.netscan_host_callback, your_mom.end_callback
        )
        f = open(TEST_NMAP_FILENAME, "rb")
        parse(f, handler)
        f.close()

    def test_correct_number_of_end_callbacks(self, your_mom):
        assert (
            your_mom.end_callback_call_count == 1
        ), "unexpected number of end callbacks"

    def test_correct_number_of_hosts(self, your_mom):
        assert len(your_mom.hosts) == 2, "unexpected number of hosts parsed"

    def test_os_name(self, your_mom):
        assert (
            your_mom.hosts[0]["os"]["name"] == u"Apple TV (iOS 4.3)"
        ), "unexpected os.name for host 0"
        assert (
            your_mom.hosts[1]["os"]["name"] == u"FreeBSD 6.2-STABLE - 6.4-STABLE"
        ), "unexpected os.name for host 1"

    def test_port_count(self, your_mom):
        assert (
            len(your_mom.hosts[0]["ports"]) == 18
        ), "unexpected number of ports on host 0"
        assert (
            len(your_mom.hosts[1]["ports"]) == 9
        ), "unexpected number of ports on host 1"

    def test_classes(self, your_mom):
        assert (
            len(your_mom.hosts[0]["os"]["classes"]) == 1
        ), "unexpected number of os classes on host 0"
        assert (
            len(your_mom.hosts[1]["os"]["classes"]) == 1
        ), "unexpected number of os classes on host 1"

    def test_cpe(self, your_mom):
        assert (
            len(your_mom.hosts[0]["os"]["classes"][0]["cpe"]) == 1
        ), "unexpected number of cpes on host 0"
        assert (
            len(your_mom.hosts[1]["os"]["classes"][0]["cpe"]) == 1
        ), "unexpected number of cpes on host 1"
