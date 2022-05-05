__all__ = ["db_from_connection", "db_from_config", "id_expand", "ensure_indices"]

from collections import defaultdict, Iterable, OrderedDict
import copy
import datetime
import random
import sys
import time

from bson import ObjectId
from bson.binary import Binary
from mongokit import Document, MongoClient, CustomType
import netaddr
from pymongo.errors import OperationFailure

from cyhy.core.common import *
from cyhy.core.config import Config
from cyhy.core.yaml_config import YamlConfig
from cyhy.util import util

CVE_COLLECTION = "cves"
HOST_COLLECTION = "hosts"
HOST_SCAN_COLLECTION = "host_scans"
KEV_COLLECTION = "kevs"
NEW_HIRE_COLLECTION = "new_hire"
NOTIFICATION_COLLECTION = "notifications"
PLACE_COLLECTION = "places"
PORT_SCAN_COLLECTION = "port_scans"
REPORT_COLLECTION = "reports"
REQUEST_COLLECTION = "requests"
SCORECARD_COLLECTION = "scorecards"
SNAPSHOT_COLLECTION = "snapshots"
SYSTEM_CONTROL_COLLECTION = "control"
TALLY_COLLECTION = "tallies"
TICKET_COLLECTION = "tickets"
VULN_SCAN_COLLECTION = "vuln_scans"

CONTROL_DOC_POLL_INTERVAL = 5  # seconds


def db_from_connection(uri, name):
    con = MongoClient(host=uri, tz_aware=True)
    con.register(
        [
            CVEDoc,
            HireDoc,
            HostDoc,
            HostScanDoc,
            KEVDoc,
            NotificationDoc,
            PlaceDoc,
            PortScanDoc,
            ReportDoc,
            RequestDoc,
            ScorecardDoc,
            SnapshotDoc,
            SystemControlDoc,
            TallyDoc,
            TicketDoc,
            VulnScanDoc,
        ]
    )
    db = con[name]
    return db


def db_from_config(config_section=None, config_filename=None, yaml=False):
    if yaml:
        if config_section is None:
            config_section = YamlConfig.DEFAULT
        config = YamlConfig(config_filename).get_service(
            YamlConfig.MONGO, config_section
        )
        return db_from_connection(config["uri"], config["name"])
    else:
        config = Config(config_section, config_filename)
        return db_from_connection(config.db_uri, config.db_name)


def id_expand(results):
    """Extract items from aggregation grouping _id dictionary and insert into outer results"""
    for result in results:
        if not result.has_key("_id"):
            continue
        _id = result["_id"]
        if type(_id) == dict:
            for (k, v) in _id.items():
                if k == "port":  # map-reduce ints become floats
                    v = int(v)
                result[k] = v
            del result["_id"]


def combine_results(d, results, envelope=None):
    """updates dict with pipeline results"""
    if len(results) == 0:
        return
    results = copy.copy(results)  # don't want to modifiy the results input
    the_goods = results[0]
    del the_goods["_id"]
    if envelope:
        the_goods = {envelope: the_goods}
    d.update(the_goods)


def run_pipeline((pipeline, collection), db):
    """Run an aggregation using a pipeline, collection tuple like those provided
       in the queries module."""
    try:
        results = db[collection].aggregate(pipeline, allowDiskUse=True)
    except OperationFailure, e:
        if e.details["code"] == 16389:
            e.args += (
                "To avoid this error consider calling run_pipeline_cursor instead.",
            )
        raise e
    return results["result"]


def run_pipeline_cursor((pipeline, collection), db):
    """Like run_pipeline but uses a cursor to access results larger than the max
       MongoDB size."""
    cursor = db[collection].aggregate(pipeline, allowDiskUse=True, cursor={})
    results = []
    for doc in cursor:
        results.append(doc)
    return results


def ensure_indices(db, foreground=False):
    background = not foreground
    if background:
        print >> sys.stderr, "Ensuring indices for all collection in background."
    else:
        print >> sys.stderr, "Ensuring indices for all collection in FOREGROUND."

    # possibly delving too greedily and too deep
    for class_name, clazz in db.connection._registered_documents.items():
        print >> sys.stderr, "Ensuring indices for %s:" % class_name
        indices = db[class_name].get_indices()
        if not indices:
            continue
        for name, spec, unique, sparse in indices:
            print >> sys.stderr, "\t%s:\tunique=%s\tsparse=%s\t%s ..." % (
                name,
                unique,
                sparse,
                spec,
            ),
            db[class_name].collection.ensure_index(
                spec, name=name, background=background, unique=unique, sparse=sparse
            )
            print >> sys.stderr, " Done"


class CustomIPAddress(CustomType):
    mongo_type = basestring
    python_type = netaddr.IPAddress
    init_type = None

    def to_bson(self, value):
        return str(value)

    def to_python(self, value):
        return netaddr.IPAddress(value)

    def validate(self, value, path):
        pass


class CustomIPNetwork(CustomType):
    mongo_type = basestring
    python_type = netaddr.IPNetwork
    init_type = None

    def to_bson(self, value):
        return str(value)

    def to_python(self, value):
        return netaddr.IPNetwork(value)

    def validate(self, value, path):
        pass


class RootDoc(Document):
    use_schemaless = True  # raise exceptions only if required fields are missing
    skip_validation = False
    raise_validation_errors = True  # when False errors are stored in validation_errors
    structure = {}

    def save(self, *args, **kwargs):
        # give ourselves a bit more information when a save fails
        try:
            super(RootDoc, self).save(*args, **kwargs)
        except Exception, e:
            print "Exception raised on save:", e
            print "Subject document follows:"
            util.pp(self)
            raise e

    def get_indices(self):
        # allow documents to create their required indices
        # should return a list of triples
        # ((name, spec, unique), ...)
        pass


class ScorecardDoc(RootDoc):
    __collection__ = SCORECARD_COLLECTION
    structure = {
        "scoring_engine": basestring,
        "generated_time": datetime.datetime,
        "last_change": datetime.datetime,
        "scores": [
            {
                "owner": basestring,
                "risk_score": basestring,
                "acronym": basestring,
                "name": basestring,
                "open_tickets": {
                    "critical": {
                        "count": int,
                        "avg_days_open": float,
                        "max_days_open": float,
                    },
                    "high": {
                        "count": int,
                        "avg_days_open": float,
                        "max_days_open": float,
                    },
                    "medium": {
                        "count": int,
                        "avg_days_open": float,
                        "max_days_open": float,
                    },
                    "low": {
                        "count": int,
                        "avg_days_open": float,
                        "max_days_open": float,
                    },
                },
                "closed_tickets": {
                    "critical": {
                        "count": int,
                        "avg_days_to_close": float,
                        "max_days_to_close": float,
                    },
                    "high": {
                        "count": int,
                        "avg_days_to_close": float,
                        "max_days_to_close": float,
                    },
                    "medium": {
                        "count": int,
                        "avg_days_to_close": float,
                        "max_days_to_close": float,
                    },
                    "low": {
                        "count": int,
                        "avg_days_to_close": float,
                        "max_days_to_close": float,
                    },
                },
            }
        ],
    }
    required_fields = ["scoring_engine", "generated_time", "last_change", "scores"]
    default_values = {"last_change": util.utcnow}

    def get_indices(self):
        # TODO Decide which indices are needed
        return None

    def save(self, *args, **kwargs):
        self["last_change"] = util.utcnow()
        # TODO Think about any potential error conditions to be avoided
        super(RootDoc, self).save(*args, **kwargs)


class HireDoc(RootDoc):
    __collection__ = NEW_HIRE_COLLECTION
    structure = {
        "position_number": basestring,
        "iteration": int,
        "position_series_grade": basestring,
        "date_stage_entered": datetime.datetime,
        "current_stage": int,
        "billet_started": datetime.datetime,
        "duty_location": basestring,
        "offer_declined": bool,
        "notes": basestring,
        "active": bool,
        "insert_date": datetime.datetime,
        "eod": datetime.datetime,
    }

    def get_position_number(self):
        return self["position_number"]

    def get_stage(self):
        return self["stage"]

    def get_latest(self):
        return self["latest"]

    def get_notes(self):
        return self["notes"]

    def get_insert_time(self):
        return self["insert_date"]

    def get_billet_started(self):
        return self["billet_started"]

    # This method handles if a billet has not been updated after a week by incrementing the number by the number of weeks since last update
    def update_stage_time(self):
        num2words = {
            1: "one",
            2: "two",
            3: "three",
            4: "four",
            5: "five",
            6: "six",
            7: "seven",
            8: "eight",
            9: "nine",
            10: "ten",
        }
        today = datetime.datetime.now()
        today_years = today.isocalendar()[0]
        today_weeks = today.isocalendar()[1]
        insert_years = self["insert_date"].isocalendar[0]
        insert_weeks = self["insert_date"].isocalendar[1]
        # if the absolute value of the last entry in weeks minus the new entry of weeks is > 0 increment (the years account for subtracting over different years)
        difference_in_weeks = abs(
            insert_weeks - (today_weeks + (52 * (today_years - insert_years)))
        )
        # Convert stagenumber from a int to a string
        current_stage = num2words[self["current_stage"]]
        # If it has been more than one week since last update increment the current stage by that number of weeks
        if difference_in_weeks > 0:
            self["stage"][current_stage] += difference_in_weeks

        return 0


class TicketDoc(RootDoc):
    __collection__ = TICKET_COLLECTION
    structure = {
        "ip_int": long,
        "source": basestring,
        "source_id": int,
        "owner": basestring,
        "ip": CustomIPAddress(),
        "port": int,
        "protocol": basestring,
        "open": bool,
        "false_positive": bool,
        "time_opened": datetime.datetime,
        "last_change": datetime.datetime,
        "time_closed": datetime.datetime,
        "details": dict,
        "events": [
            {
                "time": datetime.datetime,
                "action": basestring,
                "reason": basestring,
                "reference": ObjectId,
            }
        ],
        "loc": (float, float),
    }
    required_fields = [
        "source",
        "owner",
        "ip",
        "ip_int",
        "port",
        "protocol",
        "last_change",
        "time_opened",
        "open",
        "false_positive",
        "source_id",
        "details",
        "events",
    ]
    default_values = {
        "last_change": util.utcnow,
        "time_opened": util.utcnow,
        "open": True,
        "false_positive": False,
        "events": [],
    }

    @property
    def ip(self):
        return self["ip"]

    @property
    def false_positive_dates(self):
        fp_effective_date = fp_expiration_date = None
        if self["false_positive"]:
            for event in reversed(self["events"]):
                if event["action"] == TICKET_EVENT.CHANGED:
                    for delta in event["delta"]:
                        if delta["key"] == "false_positive":
                            fp_effective_date = event["time"]
                            fp_expiration_date = event["expires"]
                            return (fp_effective_date, fp_expiration_date)
        else:
            return None

    @property
    def last_detection_date(self):
        for event in reversed(self["events"]):
            if event["action"] in [
                TICKET_EVENT.OPENED,
                TICKET_EVENT.VERIFIED,
                TICKET_EVENT.REOPENED,
            ]:
                return event["time"]
        # This should never happen, but if we don't find any OPENED/VERIFIED/REOPENED events above, gracefully return time_opened
        return self["time_opened"]

    @ip.setter
    def ip(self, new_ip):
        self["ip"] = new_ip
        self["ip_int"] = long(new_ip)

    def tag_open(self, owners, snapshot_oid):
        self.collection.update(
            {"open": True, "owner": {"$in": owners}},
            {"$push": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )

    def tag_matching(self, existing_snapshot_oids, new_snapshot_oid):
        self.collection.update(
            {"snapshots": {"$in": existing_snapshot_oids}},
            {"$push": {"snapshots": new_snapshot_oid}},
            multi=True,
            safe=True,
        )

    def remove_tag(self, snapshot_oid):
        self.collection.update(
            {"snapshots": snapshot_oid},
            {"$pull": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )

    def get_indices(self):
        return (
            (
                "ip_port_protocol_source_open_false_positive",
                [
                    ("ip_int", 1),
                    ("port", 1),
                    ("protocol", 1),
                    ("source", 1),
                    ("source_id", 1),
                    ("open", 1),
                    ("false_positive", 1),
                ],
                False,
                False,
            ),
            ("ip_open", [("ip_int", 1), ("open", 1)], False, False),
            ("open_owner", [("open", 1), ("owner", 1)], False, False),
            ("time_opened", [("time_opened", 1), ("open", 1)], False, False),
            ("last_change", [("last_change", 1)], False, False),
            ("time_closed", [("time_closed", 1)], False, True),
        )

    def save(self, *args, **kwargs):
        self["last_change"] = util.utcnow()
        if self["false_positive"] and not self["open"]:
            raise Exception("A ticket marked as a false positive cannot be closed.")
        super(RootDoc, self).save(*args, **kwargs)

    def add_event(
        self, action, reason, reference=None, time=None, delta=None, expires=None
    ):
        if action not in TICKET_EVENT:
            raise Exception(
                'Invalid action "' + action + '" cannot be added to ticket events.'
            )

        if not time:
            time = util.utcnow()
        event = {
            "time": time,
            "action": action,
            "reason": reason,
            "reference": reference,
        }
        if delta:
            event["delta"] = delta
        if expires:
            event["expires"] = expires
        self["events"].append(event)

    def set_false_positive(self, new_state, reason, expire_days):
        if self["false_positive"] == new_state:
            return
        delta = [
            {"from": self["false_positive"], "to": new_state, "key": "false_positive"}
        ]
        self["false_positive"] = new_state
        now = util.utcnow()
        expiration_date = None
        if (
            new_state
        ):  # Only include the expiration date when setting false_positive to True
            expiration_date = now + datetime.timedelta(days=expire_days)
            if not self[
                "open"
            ]:  # if ticket is not open, then re-open it; false positive tix should always be open
                self["open"] = True
                self["time_closed"] = None
                self.add_event(
                    TICKET_EVENT.REOPENED, "setting false positive", time=now
                )
        self.add_event(
            TICKET_EVENT.CHANGED, reason, delta=delta, time=now, expires=expiration_date
        )

    def latest_port(self):
        """Returns the last referenced port scan in the event list.
        This should only be used for tickets generated by portscans."""
        for event in self["events"][::-1]:
            reference_id = event.get("reference")
            if reference_id:
                break
        else:
            raise Exception("No references found in ticket events:", self["_id"])
        port = self.db.PortScanDoc.find_one({"_id": reference_id})
        if not port:
            # This can occur when a port_scan has been archived
            # Raise an exception with the info we have for this port_scan from the ticket
            raise PortScanNotFoundException(
                ticket_id=self["_id"],
                port_scan_id=reference_id,
                port_scan_time=event["time"],
            )
        return port

    def latest_vuln(self):
        """Returns the last referenced vulnerability in the event list.
        This should only be used for tickets generated by vulnscans."""
        for event in self["events"][::-1]:
            reference_id = event.get("reference")
            if reference_id:
                break
        else:
            raise Exception("No references found in ticket events:", self["_id"])
        vuln = self.db.VulnScanDoc.find_one({"_id": reference_id})
        if not vuln:
            # This can occur when a vuln_scan has been archived
            # Raise an exception with the info we have for this vuln_scan from the ticket
            raise VulnScanNotFoundException(
                ticket_id=self["_id"],
                vuln_scan_id=reference_id,
                vuln_scan_time=event["time"],
            )
        return vuln


class ScanDoc(RootDoc):
    structure = {
        "source": basestring,
        "owner": basestring,
        "ip": CustomIPAddress(),
        "ip_int": long,
        "time": datetime.datetime,
        "latest": bool,
        "snapshots": [ObjectId],
    }
    required_fields = ["source", "owner", "ip", "ip_int", "time", "latest"]
    default_values = {"latest": True, "time": util.utcnow}

    @property
    def ip(self):
        return self["ip"]

    @ip.setter
    def ip(self, new_ip):
        self["ip"] = new_ip
        self["ip_int"] = long(new_ip)

    def reset_latest_flag_by_owner(self, owner):  # TODO could use an index
        self.collection.update(
            {"latest": True, "owner": owner},
            {"$set": {"latest": False}},
            multi=True,
            safe=True,
        )

    def reset_latest_flag_by_ip(self, ips):
        """ips can be one or more IPAddresses"""
        if isinstance(ips, Iterable):
            ip_ints = [int(x) for x in ips]
        else:
            ip_ints = [int(ips)]
        self.collection.update(
            {"latest": True, "ip_int": {"$in": ip_ints}},
            {"$set": {"latest": False}},
            multi=True,
            safe=True,
        )

    def tag_latest(self, owners, snapshot_oid):
        self.collection.update(
            {"latest": True, "owner": {"$in": owners}},
            {"$push": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )

    def tag_matching(self, existing_snapshot_oids, new_snapshot_oid):
        self.collection.update(
            {"snapshots": {"$in": existing_snapshot_oids}},
            {"$push": {"snapshots": new_snapshot_oid}},
            multi=True,
            safe=True,
        )

    def tag_timespan(self, owner, snapshot_oid, start_time, end_time):
        self.collection.update(
            {"time": {"$gte": start_time, "$lte": end_time}, "owner": owner},
            {"$push": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )

    def remove_tag(self, snapshot_oid):
        self.collection.update(
            {"snapshots": snapshot_oid},
            {"$pull": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )

    def get_indices(self):  # used by all subclasses
        return (
            ("latest_ip", [("latest", 1), ("ip_int", 1)], False, False),
            ("time_owner", [("time", 1), ("owner", 1)], False, False),
            ("ip_int", [("ip_int", 1)], False, False),
            ("snapshots", [("snapshots", 1)], False, True),
        )


class HostScanDoc(ScanDoc):
    __collection__ = HOST_SCAN_COLLECTION
    structure = {
        "name": basestring,
        "accuracy": int,
        "line": int,
        "classes": [dict],
    }
    required_fields = ["accuracy", "name"]
    default_values = {"source": "nmap"}

    def get_indices(self):
        super_indices = super(HostScanDoc, self).get_indices()
        return super_indices + (
            ("latest_owner", [("latest", 1), ("owner", 1)], False, False),
            ("owner", [("owner", 1)], False, False),
        )


class PortScanDoc(ScanDoc):
    __collection__ = PORT_SCAN_COLLECTION
    structure = {
        "protocol": basestring,
        "port": int,
        "service": dict,  # service can be {} for closed nmap ports
        "state": basestring,
        "reason": basestring,
    }
    required_fields = ["state", "reason", "protocol", "port"]
    default_values = {}

    def get_indices(self):
        super_indices = super(PortScanDoc, self).get_indices()
        return super_indices + (
            (
                "latest_owner_state",
                [("latest", 1), ("owner", 1), ("state", 1)],
                False,
                False,
            ),
            ("latest_service_name", [("latest", 1), ("service.name", 1)], False, False),
            ("latest_time", [("latest", 1), ("time", 1)], False, False),
            ("owner", [("owner", 1)], False, False),
        )

    def get_open_ports_for_ip(self, ip):
        ip_int = int(ip)
        rs = self.find(
            spec={"ip_int": ip_int, "state": "open", "latest": True},
            fields={"_id": False, "port": True},
        )
        ports = set()
        for r in rs:
            port = r["port"]
            ports.add(int(port))
        return ports

    def tag_latest_open(self, owners, snapshot_oid):
        self.collection.update(
            {"latest": True, "owner": {"$in": owners}, "state": "open"},
            {"$push": {"snapshots": snapshot_oid}},
            multi=True,
            safe=True,
        )


class VulnScanDoc(ScanDoc):
    __collection__ = VULN_SCAN_COLLECTION
    structure = {
        "protocol": basestring,
        "port": int,
        "service": dict,
        "cvss_base_score": float,
        "cvss_vector": basestring,
        "description": basestring,
        "fname": basestring,
        "plugin_family": basestring,
        "plugin_id": int,
        "plugin_modification_date": datetime.datetime,
        "plugin_name": basestring,
        "plugin_publication_date": datetime.datetime,
        "plugin_type": basestring,
        "risk_factor": basestring,
        "severity": int,
        "solution": basestring,
        "synopsis": basestring,
        "service": basestring,  # overrides
    }
    required_fields = ["cvss_base_score", "severity", "protocol", "port", "service"]
    default_values = {"cvss_base_score": 0.0, "source": "nessus"}

    def get_indices(self):
        super_indices = super(VulnScanDoc, self).get_indices()
        return super_indices + (
            (
                "owner_latest_severity",
                [("owner", 1), ("latest", 1), ("severity", 1)],
                False,
                False,
            ),
        )

    def save(self, *args, **kwargs):
        self["cvss_base_score"] = float(self["cvss_base_score"])
        super(VulnScanDoc, self).save(*args, **kwargs)


class HostDoc(RootDoc):
    __collection__ = HOST_COLLECTION
    structure = {
        "_id": long,  # IP as integer
        "ip": CustomIPAddress(),
        "owner": basestring,
        "last_change": datetime.datetime,
        "next_scan": datetime.datetime,
        "state": dict,  # {'reason':basestring, 'up':bool}, #TODO bug in mongokit api
        "stage": basestring,
        "status": basestring,
        "loc": (float, float),
        "priority": int,
        "r": float,
        "latest_scan": {
            STAGE.NETSCAN1: datetime.datetime,
            STAGE.NETSCAN2: datetime.datetime,
            STAGE.PORTSCAN: datetime.datetime,
            STAGE.VULNSCAN: datetime.datetime,
            STATUS.DONE: datetime.datetime,
        },
    }
    required_fields = [
        "_id",
        "ip",
        "owner",
        "last_change",
        "state",
        "stage",
        "status",
        "priority",
        "r",
    ]
    default_values = {
        "last_change": util.utcnow,
        "priority": 0,
        "r": random.random,
        "stage": STAGE.NETSCAN1,
        "status": STATUS.WAITING,
        "state": {"reason": "new", "up": False},
        "latest_scan": {
            STAGE.NETSCAN1: None,
            STAGE.NETSCAN2: None,
            STAGE.PORTSCAN: None,
            STAGE.VULNSCAN: None,
            STATUS.DONE: None,
        },
    }

    def save(self, *args, **kwargs):
        self["last_change"] = util.utcnow()
        self["_id"] = long(
            self["_id"]
        )  # force long since mongo import/export don't preserve type info
        try:  # TODO handle this more gracefully
            self["loc"] = [
                float(self["loc"][0]),
                float(self["loc"][1]),
            ]  # same as previous
        except TypeError, e:
            print e, self["loc"]
        super(HostDoc, self).save(*args, **kwargs)

    def get_indices(self):
        return (
            (
                "claim",
                [("status", 1), ("stage", 1), ("owner", 1), ("priority", 1), ("r", 1)],
                False,
                False,
            ),
            ("ip", [("ip", 1)], False, False),
            ("up", [("state.up", 1), ("owner", 1)], False, False),
            (
                "next_scan",
                [("next_scan", 1), ("state.up", 1), ("status", 1)],
                False,
                True,
            ),
            ("owner", [("owner", 1)], False, False),
            ("latest_scan_done", [("owner", 1), ("latest_scan.DONE", 1)], False, False),
            (
                "latest_scan_vulnscan",
                [("owner", 1), ("state.up", 1), ("latest_scan.VULNSCAN", 1)],
                False,
                False,
            ),
        )

    @property
    def ip(self):
        return netaddr.IPAddress(self["ip"])

    @ip.setter
    def ip(self, new_ip):
        self["ip"] = new_ip
        self["_id"] = long(new_ip)

    def set_state(self, nmap_says_up, has_open_ports, reason=None):
        """Sets state.up based on different stage
        evidence. nmap has a concept of up which is
        different from our definition. An nmap "up" just
        means it got a reply, not that there are any open
        ports. Note either argument can be None."""

        if has_open_ports == True:  # Only PORTSCAN sends in has_open_ports
            self["state"] = {"up": True, "reason": "open-port"}
        elif has_open_ports == False:
            self["state"] = {"up": False, "reason": "no-open"}
        elif nmap_says_up == False:  # NETSCAN says host is down
            self["state"] = {"up": False, "reason": reason}

    def init(self, ip, owner, location, stage):
        self.ip = ip
        self["owner"] = owner
        self["loc"] = location
        self["stage"] = stage

    def get_count(self, owner, stage, status):
        count = self.find({"stage": stage, "status": status, "owner": owner}).count()
        return count

    def get_by_ip(self, ip):
        int_ip = int(ip)
        host = self.find_one({"_id": int_ip})
        return host

    def get_owner_of_ip(self, ip):
        result = self.find_one({"_id": int(ip)}, {"owner": True})
        if result:
            return result["owner"]
        else:
            return None

    def exists(self, stage, status):
        one = self.find_one({"stage": stage, "status": status})
        return one != None

    def get_some_for_stage(self, stage, count, owner=None, waiting=False):
        if waiting:
            status = {"$in": [STATUS.READY, STATUS.WAITING]}
        else:
            status = STATUS.READY

        if owner != None:
            rs = self.find(
                spec={"status": status, "stage": stage, "owner": owner},
                fields={"ip": True},
                sort=[("priority", 1), ("r", 1)],
                limit=count,
            )
        else:
            rs = self.find(
                spec={"status": status, "stage": stage},
                fields={"ip": True},
                sort=[("priority", 1), ("r", 1)],
                limit=count,
            )
        return rs

    def increase_ready_hosts(self, owner, stage, count):
        hosts = self.find(
            spec={"owner": owner, "stage": stage, "status": STATUS.WAITING},
            sort=[("priority", 1), ("r", 1)],
            limit=count,
        )
        # important to count before using cursor
        changed_count = hosts.count(True)
        for h in hosts:
            h["status"] = STATUS.READY
            h.save()
        return changed_count

    def decrease_ready_hosts(self, owner, stage, count):
        hosts = self.find(
            spec={"owner": owner, "stage": stage, "status": STATUS.READY},
            sort=[("priority", 1), ("r", 1)],
            limit=count,
        )
        # important to count before using cursor
        changed_count = hosts.count(True)
        for h in hosts:
            h["status"] = STATUS.WAITING
            h.save()
        return changed_count

    def reset_state_by_owner(self, owner, init_stage, jump_start=False):
        """Moves hosts back to initial stage and resets status for a single-scan.
           jump_start allows previously up hosts to skip the NETSCANx stages."""
        now = util.utcnow()
        if jump_start:
            self.collection.update(
                spec={"owner": owner, "state.up": True},
                document={
                    "$set": {
                        "stage": STAGE.PORTSCAN,
                        "status": STATUS.WAITING,
                        "last_change": now,
                        "next_scan": None,
                    }
                },
                multi=True,
            )
            self.collection.update(
                spec={"owner": owner, "state.up": False},
                document={
                    "$set": {
                        "stage": init_stage,
                        "status": STATUS.WAITING,
                        "last_change": now,
                        "next_scan": None,
                    }
                },
                multi=True,
            )
        else:
            self.collection.update(
                spec={"owner": owner},
                document={
                    "$set": {
                        "stage": init_stage,
                        "status": STATUS.WAITING,
                        "last_change": now,
                        "next_scan": None,
                    }
                },
                multi=True,
            )

    def get_scheduled_hosts(self, state_up, time=None, limit=2000):
        """Retrieves hosts that have be scheduled to restart scanning.
        Returns a cursor to the hosts list"""
        if time == None:
            time = util.utcnow()
        cursor = self.find(
            spec={
                "next_scan": {"$lte": time},
                "state.up": state_up,
                "status": STATUS.DONE,
            }
        ).limit(limit)
        return cursor

    def purge_all_running(self):
        now = util.utcnow()
        self.collection.update(
            spec={"status": STATUS.RUNNING},
            document={"$set": {"status": STATUS.WAITING, "last_change": now}},
            multi=True,
        )

    def ensure_next_scan_set(self, owner):
        now = util.utcnow()
        self.collection.update(
            spec={"next_scan": None, "owner": owner},
            document={"$set": {"next_scan": now}},
            multi=True,
        )

    def clear_next_scan_date(self, owner):
        self.collection.update(
            spec={"next_scan": {"$exists": True}, "owner": owner},
            document={"$set": {"next_scan": None}},
            multi=True,
        )


class RequestDoc(RootDoc):
    # TODO: enforce _id
    __collection__ = REQUEST_COLLECTION
    structure = {
        "agency": {
            "name": basestring,
            "acronym": basestring,
            "type": basestring,  # TODO: Remove this field now that hierarchy is implemented
            "contacts": [
                {
                    "phone": basestring,
                    "name": basestring,
                    "email": basestring,
                    "type": basestring,  # addition for POC types
                }
            ],
            "location": {
                "gnis_id": long,  # See info about this ID in PlaceDoc below
                "name": basestring,
                "state": basestring,
                "state_fips": basestring,
                "state_name": basestring,
                "county": basestring,
                "county_fips": basestring,
                "country": basestring,
                "country_name": basestring,
            },
        },
        "period_start": datetime.datetime,
        "windows": [{"duration": int, "start": basestring, "day": basestring}],
        "networks": [CustomIPNetwork()],
        "init_stage": basestring,
        "scan_limits": list,  # TODO elaborate
        "key": basestring,  # TODO encrypt?
        "scheduler": basestring,
        "scan_types": list,
        "report_period": basestring,
        "report_types": list,
        "stakeholder": bool,
        "children": list,
        "retired": bool,
    }
    required_fields = [
        "agency.name",
        "agency.acronym",
        "period_start",
        "windows",
        "init_stage",
        "stakeholder",
    ]
    default_values = {
        "period_start": util.utcnow,
        "windows": [{"duration": 168, "start": "00:00:00", "day": "Sunday"}],
        "init_stage": "NETSCAN1",
        "stakeholder": False,
        "retired": False,
    }

    @property
    def start_time(self):
        return self["period_start"]

    @start_time.setter
    def start_time(self, new_start_time):
        self["period_start"] = new_start_time

    @property
    def networks(self):
        return netaddr.IPSet(self["networks"])

    def add_networks(self, additions):
        new_nets = self.networks | additions
        new_nets.compact()
        self["networks"] = new_nets.iter_cidrs()

    def remove_networks(self, subractions):
        new_nets = self.networks - subractions
        new_nets.compact()
        self["networks"] = new_nets.iter_cidrs()

    def get_by_owner(self, owner):
        return self.find_one({"_id": owner})

    def get_all_owners(self):
        rs = self.find(spec={}, sort=[("_id", 1)])
        all_owners = []
        for r in rs:
            all_owners.append(r["_id"])
        return all_owners

    def get_all_parents(self, orgId):
        rs = self.find(filter={"children": {"$in": [orgId]}})
        parents = []
        for r in rs:
            parents.append(r["_id"])

        return parents

    def get_all_intersections(self, cidrs):
        results = OrderedDict()  # {request: IPSet of intersections}
        all_requests = self.collection.aggregate(
            [{"$match": {"networks": {"$ne": []}}}, {"$sort": {"_id": 1}}], cursor={}
        )
        for request in all_requests:
            intersection = netaddr.IPSet(request["networks"]) & cidrs
            if intersection:
                request_doc = self.find_one({"_id": request["_id"]})
                results[request_doc] = intersection
        return results

    def add_children(self, db, child_ids):
        # child_ids must be a list
        for child in child_ids:
            if child == self["_id"]:
                raise ValueError(
                    "Cannot add own id (" + child + ") to list of children"
                )
            if self.get("children") and child in self["children"]:
                raise ValueError(
                    "Child ("
                    + child
                    + ") cannot be added; it is already in list of children of "
                    + self["_id"]
                )
            if not db.requests.find_one({"_id": child}):
                raise ValueError(
                    "Child ("
                    + child
                    + ") was not found in the database and cannot be added"
                )
        if not self.get("children"):
            self["children"] = []
        self["children"] += child_ids
        return True

    def remove_children(self, child_ids):
        if not self.get("children"):
            raise ValueError(self["_id"] + " has no children to remove")
        # child_ids must be a list
        for child in child_ids:
            if child not in self["children"]:
                raise ValueError(
                    "Child ("
                    + child
                    + ") cannot be removed; it is not in list of children of "
                    + self["_id"]
                )
        self["children"] = list(set(self["children"]) - set(child_ids))
        return True

    def get_all_descendants(
        self, owner, stakeholders_only=False, include_retired=False
    ):
        # Build dict of every org and its children (if any)
        org_info = dict()
        for org in self.find():
            org_info[org["_id"]] = {
                "children": org.get("children", []),
                "stakeholder": org.get("stakeholder", False),
                "retired": org.get("retired", False),
            }

        if not org_info.get(owner):
            raise ValueError(owner + " has no request document")

        def get_descendants(org_info, current_org, stakeholders_only, include_retired):
            # Recursive function to get descendants of current_org
            descendants = set()
            for child_org in org_info.get(current_org, {}).get("children", []):
                if include_retired or not org_info[child_org].get("retired"):
                    if not stakeholders_only or org_info[child_org].get("stakeholder"):
                        descendants.add(child_org)
                    descendants = descendants.union(
                        get_descendants(
                            org_info, child_org, stakeholders_only, include_retired
                        )
                    )
            return descendants

        # Build descendants set
        descendants = set()
        descendants = descendants.union(
            get_descendants(org_info, owner, stakeholders_only, include_retired)
        )
        return list(descendants)

    def get_owner_to_type_dict(self, stakeholders_only=False, include_retired=False):
        """returns a dict of owner_id:type. "stakeholders_only" parameter eliminates non-stakeholders from the dict."""
        types = defaultdict(lambda: list())
        for agency_type in AGENCY_TYPE:
            all_agency_type_descendants = self.get_all_descendants(
                agency_type, include_retired=include_retired
            )
            for org in self.find({"_id": {"$in": all_agency_type_descendants}}):
                if not stakeholders_only or org["stakeholder"]:
                    types[org["_id"]].append(agency_type)

        # Check for any orgs that fall into multiple types.  This can occur
        # under normal circumstances when using the CYHY_THIRD_PARTY report
        # type (see CYHYDEV-789).  This can also occur if an organization
        # has erroneously been added as a descendant of more than one
        # AGENCY_TYPE (FEDERAL, STATE, etc.) node.
        for org_id, types_list in types.iteritems():
            if len(types_list) == 1:
                # Everything's cool here- move along.
                types[org_id] = types_list[0]
            else:
                # Attempt to deconflict the multiple types.  The easiest way
                # is to check who the organization is a direct child of.
                org_parents = {
                    org["_id"]
                    for org in self.collection.find({"children": org_id}, {"_id": True})
                }
                # Get intersection of types_list and org_parents
                matching_types = set(types_list) & org_parents

                if len(matching_types) == 1:
                    # Exactly one AGENCY_TYPE is a parent of this org, so
                    # declare that one to be the official type of this org.
                    types[org_id] = matching_types.pop()
                elif len(matching_types) > 1:
                    # This org is a child of multiple AGENCY_TYPEs; this is
                    # bad and should be corrected in the database. Assign this
                    # org a type containing all of the matching types so that
                    # a human can correct this situation.
                    types[org_id] = "_".join(matching_types)
                else:
                    # No matching types - this should not happen.
                    types[org_id] = "UNKNOWN"
        return types

    def get_owner_types(
        self, as_lists=False, stakeholders_only=False, include_retired=False
    ):
        """returns a dict of types to owners.  The owners can be in a set or list depending on "as_lists" parameter.
           "stakeholders_only" parameter eliminates non-stakeholders from the dict."""
        types = defaultdict(lambda: set())

        # No need to reinvent the wheel here- call get_owner_to_type_dict()
        # and then rearrange the data a bit.
        owner_to_type = self.get_owner_to_type_dict(
            stakeholders_only=stakeholders_only, include_retired=include_retired
        )
        for org_id, org_type in owner_to_type.iteritems():
            types[org_type].add(org_id)

        # convert to a dict of lists
        if not as_lists:
            return types
        result = dict()
        for k, v in types.items():
            result[k] = list(v)
        return result

    def save(self, *args, **kwargs):
        if self["agency"].get("location"):
            self["agency"]["location"]["gnis_id"] = long(
                self["agency"]["location"]["gnis_id"]
            )
        super(RequestDoc, self).save(*args, **kwargs)


class TallyDoc(RootDoc):
    __collection__ = TALLY_COLLECTION
    structure = {
        "_id": basestring,  # owner
        "counts": {
            "PORTSCAN": {"READY": int, "WAITING": int, "DONE": int, "RUNNING": int},
            "BASESCAN": {"READY": int, "WAITING": int, "DONE": int, "RUNNING": int},
            "VULNSCAN": {"READY": int, "WAITING": int, "DONE": int, "RUNNING": int},
            "NETSCAN1": {"READY": int, "WAITING": int, "DONE": int, "RUNNING": int},
            "NETSCAN2": {"READY": int, "WAITING": int, "DONE": int, "RUNNING": int},
        },
        "last_change": datetime.datetime,
    }
    required_fields = [
        "_id",
        "last_change",
        "counts.PORTSCAN.READY",
        "counts.PORTSCAN.WAITING",
        "counts.PORTSCAN.DONE",
        "counts.PORTSCAN.RUNNING",
        "counts.BASESCAN.READY",
        "counts.BASESCAN.WAITING",
        "counts.BASESCAN.DONE",
        "counts.BASESCAN.RUNNING",
        "counts.VULNSCAN.READY",
        "counts.VULNSCAN.WAITING",
        "counts.VULNSCAN.DONE",
        "counts.VULNSCAN.RUNNING",
        "counts.NETSCAN1.READY",
        "counts.NETSCAN1.WAITING",
        "counts.NETSCAN1.DONE",
        "counts.NETSCAN1.RUNNING",
        "counts.NETSCAN2.READY",
        "counts.NETSCAN2.WAITING",
        "counts.NETSCAN2.DONE",
        "counts.NETSCAN2.RUNNING",
    ]
    default_values = {
        "last_change": util.utcnow,
        "counts.PORTSCAN.READY": 0,
        "counts.PORTSCAN.WAITING": 0,
        "counts.PORTSCAN.DONE": 0,
        "counts.PORTSCAN.RUNNING": 0,
        "counts.BASESCAN.READY": 0,
        "counts.BASESCAN.WAITING": 0,
        "counts.BASESCAN.DONE": 0,
        "counts.BASESCAN.RUNNING": 0,
        "counts.VULNSCAN.READY": 0,
        "counts.VULNSCAN.WAITING": 0,
        "counts.VULNSCAN.DONE": 0,
        "counts.VULNSCAN.RUNNING": 0,
        "counts.NETSCAN1.READY": 0,
        "counts.NETSCAN1.WAITING": 0,
        "counts.NETSCAN1.DONE": 0,
        "counts.NETSCAN1.RUNNING": 0,
        "counts.NETSCAN2.READY": 0,
        "counts.NETSCAN2.WAITING": 0,
        "counts.NETSCAN2.DONE": 0,
        "counts.NETSCAN2.RUNNING": 0,
    }

    def save(self, *args, **kwargs):
        self["last_change"] = util.utcnow()
        super(TallyDoc, self).save(*args, **kwargs)

    def save_without_timestamp_change(self, *args, **kwargs):
        super(TallyDoc, self).save(*args, **kwargs)

    def active_host_count(self, stage):
        counts = self["counts"]
        return (
            counts[stage][STATUS.WAITING],
            counts[stage][STATUS.READY],
            counts[stage][STATUS.RUNNING],
        )

    def transfer(self, from_stage, from_status, to_stage, to_status, delta):
        self["counts"][from_stage][from_status] -= delta
        self["counts"][to_stage][to_status] += delta

    def get_by_owner(self, owner):
        return self.find_one({"_id": owner})

    def get_all(self, since=None):
        if since == None:
            return self.find()
        return self.find({"last_change": {"$gte": since}})

    def sync(self, db):
        for stage in list(STAGE):
            for status in list(STATUS):
                count = db.HostDoc.get_count(self["_id"], stage, status)
                self["counts"][stage][status] = count
        self.save_without_timestamp_change()


class SnapshotDoc(RootDoc):
    __collection__ = SNAPSHOT_COLLECTION
    structure = {
        "owner": basestring,
        "descendants_included": [basestring],
        "last_change": datetime.datetime,
        "start_time": datetime.datetime,
        "end_time": datetime.datetime,
        "latest": bool,
        "port_count": int,
        "unique_port_count": int,
        "unique_operating_systems": int,
        "host_count": int,
        "vulnerable_host_count": int,
        "vulnerabilities": {
            "critical": int,
            "high": int,
            "medium": int,
            "low": int,
            "total": int,
        },
        "unique_vulnerabilities": {
            "critical": int,
            "high": int,
            "medium": int,
            "low": int,
            "total": int,
        },
        "cvss_average_all": float,
        "cvss_average_vulnerable": float,
        "world": {
            "host_count": int,
            "vulnerable_host_count": int,
            "vulnerabilities": {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "total": int,
            },
            "unique_vulnerabilities": {
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "total": int,
            },
            "cvss_average_all": float,
            "cvss_average_vulnerable": float,
        },
        "networks": [CustomIPNetwork()],
        "addresses_scanned": int,
        "services": dict,
        "tix_msec_open": {
            "tix_open_as_of_date": datetime.datetime,  # Numbers in this section refer to how long open tix were open AT this date/time
            "critical": {"median": long, "max": long},
            "high": {"median": long, "max": long},
            "medium": {"median": long, "max": long},
            "low": {"median": long, "max": long},
        },
        "tix_msec_to_close": {
            "tix_closed_after_date": datetime.datetime,  # Numbers in this section only include tix that closed AT/AFTER this date/time
            "critical": {"median": long, "max": long},
            "high": {"median": long, "max": long},
            "medium": {"median": long, "max": long},
            "low": {"median": long, "max": long},
        },
    }
    required_fields = [
        "owner",
        "last_change",
        "start_time",
        "end_time",
        "latest",
        "port_count",
        "unique_port_count",
        "unique_operating_systems",
        "host_count",
        "vulnerable_host_count",
        "vulnerabilities.critical",
        "vulnerabilities.high",
        "vulnerabilities.medium",
        "vulnerabilities.low",
        "vulnerabilities.total",
        "unique_vulnerabilities.critical",
        "unique_vulnerabilities.high",
        "unique_vulnerabilities.medium",
        "unique_vulnerabilities.low",
        "unique_vulnerabilities.total",
        "cvss_average_all",
        "cvss_average_vulnerable",
        "world.host_count",
        "world.vulnerable_host_count",
        "world.vulnerabilities.critical",
        "world.vulnerabilities.high",
        "world.vulnerabilities.medium",
        "world.vulnerabilities.low",
        "world.vulnerabilities.total",
        "world.unique_vulnerabilities.critical",
        "world.unique_vulnerabilities.high",
        "world.unique_vulnerabilities.medium",
        "world.unique_vulnerabilities.low",
        "world.unique_vulnerabilities.total",
        "addresses_scanned",
    ]
    default_values = {
        "last_change": util.utcnow,
        "latest": True,
        "port_count": 0,
        "unique_port_count": 0,
        "unique_operating_systems": 0,
        "host_count": 0,
        "vulnerable_host_count": 0,
        "vulnerabilities.critical": 0,
        "vulnerabilities.high": 0,
        "vulnerabilities.medium": 0,
        "vulnerabilities.low": 0,
        "vulnerabilities.total": 0,
        "unique_vulnerabilities.critical": 0,
        "unique_vulnerabilities.high": 0,
        "unique_vulnerabilities.medium": 0,
        "unique_vulnerabilities.low": 0,
        "unique_vulnerabilities.total": 0,
        "cvss_average_all": 0.0,
        "cvss_average_vulnerable": 0.0,
        "world.host_count": 0,
        "world.vulnerable_host_count": 0,
        "world.vulnerabilities.critical": 0,
        "world.vulnerabilities.high": 0,
        "world.vulnerabilities.medium": 0,
        "world.vulnerabilities.low": 0,
        "world.vulnerabilities.total": 0,
        "world.unique_vulnerabilities.critical": 0,
        "world.unique_vulnerabilities.high": 0,
        "world.unique_vulnerabilities.medium": 0,
        "world.unique_vulnerabilities.low": 0,
        "world.unique_vulnerabilities.total": 0,
        "addresses_scanned": 0,
    }

    def get_indices(self):
        return (
            (
                "uniques",
                [("owner", 1), ("start_time", 1), ("end_time", 1)],
                True,
                False,
            ),
            ("latest_owner", [("latest", 1), ("owner", 1)], False, False),
        )

    def reset_latest_flag_by_owner(self, owner):
        self.collection.update(
            {"latest": True, "owner": owner},
            {"$set": {"latest": False}},
            multi=True,
            safe=True,
        )

    def will_conflict(self):
        """check to see if a snapshot will conflict when inserted"""
        results = self.collection.find_one(
            {
                "_id": {"$ne": self["_id"]},
                "owner": self["owner"],
                "start_time": self["start_time"],
                "end_time": self["end_time"],
            }
        )
        return results != None

    @property
    def networks(self):
        return netaddr.IPSet(self["networks"])

    @property
    def children(self):
        return list(self.collection.find({"parents": self["_id"]}, {"_id": True}))


class CVEDoc(RootDoc):
    __collection__ = CVE_COLLECTION
    structure = {
        "_id": basestring,  # CVE string
        "cvss_score": float,
        "cvss_version": basestring,
        "severity": int
    }
    required_fields = ["_id", "cvss_score", "cvss_version", "severity"]
    default_values = {}

    def get_indices(self):
        return tuple()

    def save(self, *args, **kwargs):
        # Calculate severity from cvss on save
        # Source: https://nvd.nist.gov/vuln-metrics/cvss
        cvss = self["cvss_score"]
        if self["cvss_version"] == "2.0":
            if cvss == 10:
                self["severity"] = 4
            elif cvss >= 7.0:
                self["severity"] = 3
            elif cvss >= 4.0:
                self["severity"] = 2
            else:
                self["severity"] = 1
        elif self["cvss_version"] in ["3.0", "3.1"]:
            if cvss >= 9.0:
                self["severity"] = 4
            elif cvss >= 7.0:
                self["severity"] = 3
            elif cvss >= 4.0:
                self["severity"] = 2
            else:
                self["severity"] = 1
        super(CVEDoc, self).save(*args, **kwargs)


class ReportDoc(RootDoc):
    __collection__ = REPORT_COLLECTION
    structure = {
        "owner": basestring,
        "generated_time": datetime.datetime,
        "snapshot_oid": list,
        "report_types": list,
    }
    required_fields = ["generated_time", "report_types"]
    default_values = {"generated_time": util.utcnow}

    def get_indices(self):
        return (
            ("owner", [("owner", 1)], False, False),
            ("generated_time", [("generated_time", 1)], False, False),
        )


class SystemControlDoc(RootDoc):
    __collection__ = SYSTEM_CONTROL_COLLECTION
    structure = {
        "action": basestring,  # CONTROL_ACTION
        "sender": basestring,  # Free-form, for UI / Logging
        "target": basestring,  # CONTROL_TARGET
        "reason": basestring,  # Free-form, for UI / Logging
        "time": datetime.datetime,  # creation time
        "completed": bool,  # Set to True when after the action has occurred
    }
    required_fields = ["action", "sender", "target", "reason", "time", "completed"]
    default_values = {
        "time": util.utcnow,
        "target": CONTROL_TARGET.COMMANDER,
        "completed": False,
    }

    def wait(self, timeout=None):
        """Wait for this control action to complete.  If a timeout is set, only
        wait a maximum of timeout seconds.
        Returns True if the document was completed, False otherwise."""
        if timeout:
            timeout_time = util.utcnow() + datetime.timedelta(seconds=timeout)
        while timeout == None or util.utcnow() < timeout_time:
            self.reload()
            if self["completed"]:
                return True
            time.sleep(CONTROL_DOC_POLL_INTERVAL)
        return False


class PlaceDoc(RootDoc):
    __collection__ = PLACE_COLLECTION
    structure = {
        "_id": long,  # _id = GNIS FEATURE_ID (INCITS 446-2008) - https://geonames.usgs.gov/domestic/index.html
        "name": basestring,
        "class": basestring,
        "state": basestring,
        "state_fips": basestring,
        "state_name": basestring,
        "county": basestring,
        "county_fips": basestring,
        "country": basestring,
        "country_name": basestring,
        "latitude_dms": basestring,
        "longitude_dms": basestring,
        "latitude_dec": float,
        "longitude_dec": float,
        "elevation_meters": int,
        "elevation_feet": int,
    }
    required_fields = [
        "_id",
        "name",
        "class",
        "state",
        "state_fips",
        "state_name",
        "country",
        "country_name",
    ]
    default_values = {}

    def get_indices(self):
        return tuple()


class NotificationDoc(RootDoc):
    __collection__ = NOTIFICATION_COLLECTION
    structure = {
        "ticket_id": ObjectId,
        "ticket_owner": basestring,
        "generated_for": list,
    }
    required_fields = ["ticket_id", "ticket_owner"]
    default_values = {"generated_for": []}

    def get_indices(self):
        return tuple()


class KEVDoc(RootDoc):
    __collection__ = KEV_COLLECTION
    structure = {"_id": basestring}
    required_fields = ["_id"]
    default_values = {}

    def get_indices(self):
        return tuple()
