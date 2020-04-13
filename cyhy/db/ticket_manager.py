__all__ = ["VulnTicketManager", "IPPortTicketManager", "IPTicketManager"]

from collections import defaultdict
from dateutil import relativedelta, tz

from cyhy.core.common import TICKET_EVENT, UNKNOWN_OWNER
from cyhy.db.queries import close_tickets_pl, clear_latest_vulns_pl
from cyhy.db import database
from cyhy.util import util

from netaddr import IPSet

MAX_PORTS_COUNT = 65535


class VulnTicketManager(object):
    """Handles the opening and closing of tickets for a vulnerability scan"""

    def __init__(self, db, source, reopen_days=90, manual_scan=False):
        self.__db = db
        self.__ips = IPSet()
        self.__ports = set()
        self.__source_ids = set()
        self.__source = source
        self.__seen_ticket_ids = set()
        self.__closing_time = None
        self.__reopen_delta = relativedelta.relativedelta(days=-reopen_days)
        self.__manual_scan = manual_scan

    @property
    def ips(self):
        return self.__ips

    @ips.setter
    def ips(self, ips):
        self.__ips = IPSet(ips)

    @property
    def ports(self):
        return self.__ports

    @ports.setter
    def ports(self, ports):
        self.__ports = set(ports)
        # General vulns will be on port 0,
        # but nmap will never send 0 as open.
        # we'll add it here so it'll always be considered
        self.__ports.add(0)

    @property
    def source_ids(self):
        return self.__source_ids

    @source_ids.setter
    def source_ids(self, source_ids):
        self.__source_ids = set(source_ids)

    def __mark_seen(self, vuln):
        self.__seen_ticket_ids.add(vuln["_id"])

    def __calculate_delta(self, d1, d2):
        """d1 and d2 are dictionaries.  Returns a list of changes."""
        delta = []
        all_keys = set(d1.keys() + d2.keys())
        for k in all_keys:
            v1 = d1.get(k)
            v2 = d2.get(k)
            if v1 != v2:
                delta.append({"key": k, "from": v1, "to": v2})
        return delta

    def __check_false_positive_expiration(self, ticket, time):
        # if false_positive expiration date has been reached,
        # flip false_positive flag and add CHANGED event
        if ticket["false_positive"] is True:
            fp_effective_date, fp_expiration_date = ticket.false_positive_dates
            if fp_expiration_date < time:
                ticket["false_positive"] = False
                event = {
                    "time": time,
                    "action": TICKET_EVENT.CHANGED,
                    "reason": "False positive expired",
                    "reference": None,
                    "delta": [{"from": True, "to": False, "key": "false_positive"}],
                }
                if self.__manual_scan:
                    event["manual"] = True
                ticket["events"].append(event)

    def __generate_ticket_details(self, vuln, ticket, check_for_changes=True):
        """generates the contents of the ticket's details field using NVD data.
        if check_for_changes is True, it will detect changes in the details,
        and generate a CHANGED event."""
        new_details = {
            "cve": vuln.get("cve"),
            "score_source": vuln["source"],
            "cvss_base_score": vuln["cvss_base_score"],
            "severity": vuln["severity"],
            "name": vuln["plugin_name"],
        }

        if "cve" in vuln:
            cve_doc = self.__db.CVEDoc.find_one({"_id": vuln["cve"]})
            if cve_doc:
                new_details["score_source"] = "nvd"
                new_details["cvss_base_score"] = cve_doc["cvss_score"]
                new_details["severity"] = cve_doc["severity"]

        if check_for_changes:
            delta = self.__calculate_delta(ticket["details"], new_details)
            if delta:
                event = {
                    "time": vuln["time"],
                    "action": TICKET_EVENT.CHANGED,
                    "reason": "details changed",
                    "reference": vuln["_id"],
                    "delta": delta,
                }
                if self.__manual_scan:
                    event["manual"] = True
                ticket["events"].append(event)

        ticket["details"] = new_details

    def __create_notification(self, ticket):
        """Create a notification from a ticket and save it in the database."""
        new_notification = self.__db.NotificationDoc()
        new_notification["ticket_id"] = ticket["_id"]
        new_notification["ticket_owner"] = ticket["owner"]
        # generated_for is initialized as an empty list.  Whenever a
        # notification PDF is generated using this NotificationDoc
        # (by cyhy-reports), the owner _id for that PDF is added to the
        # generated_for list.  It's a list because the same NotificationDoc
        # can get used in both a parent and a descendant PDF.
        new_notification["generated_for"] = list()
        new_notification.save()

    def open_ticket(self, vuln, reason):
        if self.__closing_time is None or self.__closing_time < vuln["time"]:
            self.__closing_time = vuln["time"]

        # search for previous open ticket that matches
        prev_open_ticket = self.__db.TicketDoc.find_one(
            {
                "ip_int": long(vuln["ip"]),
                "port": vuln["port"],
                "protocol": vuln["protocol"],
                "source": vuln["source"],
                "source_id": vuln["plugin_id"],
                "open": True,
            }
        )
        if prev_open_ticket:
            self.__generate_ticket_details(vuln, prev_open_ticket)
            self.__check_false_positive_expiration(
                prev_open_ticket, vuln["time"].replace(tzinfo=tz.tzutc())
            )  # explicitly set to UTC (see CYHY-286)
            # add an entry to the existing open ticket
            event = {
                "time": vuln["time"],
                "action": TICKET_EVENT.VERIFIED,
                "reason": reason,
                "reference": vuln["_id"],
            }
            if self.__manual_scan:
                event["manual"] = True
            prev_open_ticket["events"].append(event)
            prev_open_ticket.save()
            self.__mark_seen(prev_open_ticket)
            return

        # no matching tickets are currently open
        # search for a previously closed ticket that was closed before the cutoff
        cutoff_date = util.utcnow() + self.__reopen_delta
        reopen_ticket = self.__db.TicketDoc.find_one(
            {
                "ip_int": long(vuln["ip"]),
                "port": vuln["port"],
                "protocol": vuln["protocol"],
                "source": vuln["source"],
                "source_id": vuln["plugin_id"],
                "open": False,
                "time_closed": {"$gt": cutoff_date},
            }
        )

        if reopen_ticket:
            self.__generate_ticket_details(vuln, reopen_ticket)
            event = {
                "time": vuln["time"],
                "action": TICKET_EVENT.REOPENED,
                "reason": reason,
                "reference": vuln["_id"],
            }
            if self.__manual_scan:
                event["manual"] = True
            reopen_ticket["events"].append(event)
            reopen_ticket["time_closed"] = None
            reopen_ticket["open"] = True
            reopen_ticket.save()
            self.__mark_seen(reopen_ticket)
            return

        # time to open a new ticket
        new_ticket = self.__db.TicketDoc()
        new_ticket.ip = vuln["ip"]
        new_ticket["port"] = vuln["port"]
        new_ticket["protocol"] = vuln["protocol"]
        new_ticket["source"] = vuln["source"]
        new_ticket["source_id"] = vuln["plugin_id"]
        new_ticket["owner"] = vuln["owner"]
        new_ticket["time_opened"] = vuln["time"]
        self.__generate_ticket_details(vuln, new_ticket, check_for_changes=False)

        host = self.__db.HostDoc.get_by_ip(vuln["ip"])
        if host is not None:
            new_ticket["loc"] = host["loc"]

        event = {
            "time": vuln["time"],
            "action": TICKET_EVENT.OPENED,
            "reason": reason,
            "reference": vuln["_id"],
        }
        if self.__manual_scan:
            event["manual"] = True
        new_ticket["events"].append(event)

        if (
            new_ticket["owner"] == UNKNOWN_OWNER
        ):  # close tickets with no owner immediately
            event = {
                "time": vuln["time"],
                "action": TICKET_EVENT.CLOSED,
                "reason": "No associated owner",
                "reference": None,
            }
            if self.__manual_scan:
                event["manual"] = True
            new_ticket["events"].append(event)
            new_ticket["open"] = False
            new_ticket["time_closed"] = self.__closing_time

        new_ticket.save()
        self.__mark_seen(new_ticket)

        # Create notifications for Highs (3) or Criticals (4)
        if new_ticket["details"]["severity"] > 2:
            self.__create_notification(new_ticket)

    def close_tickets(self):
        if self.__closing_time is None:
            # You don't have to go home but you can't stay here
            self.__closing_time = util.utcnow()
        ip_ints = [int(i) for i in self.__ips]

        # find tickets that are covered by this scan, but weren't just touched
        # TODO: this is the way I wanted to do it, but it blows up mongo
        # tickets = self.__db.TicketDoc.find({'ip_int':{'$in':ip_ints},
        #                                     'port':{'$in':self.__ports},
        #                                     'source_id':{'$in':self.__source_ids},
        #                                     '_id':{'$nin':list(self.__seen_ticket_ids)},
        #                                     'source':self.__source,
        #                                     'open':True})

        # work-around using a pipeline
        tickets = database.run_pipeline_cursor(
            close_tickets_pl(
                ip_ints,
                list(self.__ports),
                list(self.__source_ids),
                list(self.__seen_ticket_ids),
                self.__source,
            ),
            self.__db,
        )

        for raw_ticket in tickets:
            ticket = self.__db.TicketDoc(raw_ticket)  # make it managed
            # don't close tickets that are false_positives, just add event
            reason = "vulnerability not detected"
            self.__check_false_positive_expiration(
                ticket, self.__closing_time.replace(tzinfo=tz.tzutc())
            )  # explicitly set to UTC (see CYHY-286)
            if ticket["false_positive"] is True:
                event = {
                    "time": self.__closing_time,
                    "action": TICKET_EVENT.UNVERIFIED,
                    "reason": reason,
                    "reference": None,
                }
            else:
                ticket["open"] = False
                ticket["time_closed"] = self.__closing_time
                event = {
                    "time": self.__closing_time,
                    "action": TICKET_EVENT.CLOSED,
                    "reason": reason,
                    "reference": None,
                }
            if self.__manual_scan:
                event["manual"] = True
            ticket["events"].append(event)
            ticket.save()

    def ready_to_clear_vuln_latest_flags(self):
        return (
            len(self.__ips) > 0 and len(self.__ports) > 0 and len(self.__source_ids) > 0
        )

    def clear_vuln_latest_flags(self):
        """clear the latest flag for vuln_docs that match the ticket_manager scope"""
        ip_ints = [int(i) for i in self.__ips]
        pipeline = clear_latest_vulns_pl(
            ip_ints, list(self.__ports), list(self.__source_ids), self.__source
        )
        raw_vulns = database.run_pipeline_cursor(pipeline, self.__db)
        for raw_vuln in raw_vulns:
            vuln = self.__db.VulnScanDoc(raw_vuln)
            vuln["latest"] = False
            vuln.save()


class IPPortTicketManager(object):
    """Handles the opening and closing of tickets for a port scan (PORTSCAN)"""

    def __init__(self, db, protocols, reopen_days=90):
        self.__closing_time = None
        self.__db = db
        self.__ips = IPSet()  # ips that were scanned
        self.__ports = set()  # ports that were scanned
        self.__protocols = set(protocols)  # protocols that were scanned
        self.__reopen_delta = relativedelta.relativedelta(days=-reopen_days)
        self.__seen_ip_port = defaultdict(set)  # {ip:set({1,2,3}), ...}

    @property
    def ips(self):
        return self.__ips

    @ips.setter
    def ips(self, ips):
        self.__ips = IPSet(ips)

    @property
    def ports(self):
        return self.__ports

    @ports.setter
    def ports(self, ports):
        self.__ports = list(ports)

    def port_open(self, ip, port):
        self.__seen_ip_port[ip].add(port)

    def __check_false_positive_expiration(self, ticket, closing_time):
        # if false_positive expiration date has been reached,
        # flip false_positive flag and add CHANGED event
        if ticket["false_positive"] is True:
            fp_effective_date, fp_expiration_date = ticket.false_positive_dates
            if fp_expiration_date < closing_time:
                ticket["false_positive"] = False
                event = {
                    "time": closing_time,
                    "action": TICKET_EVENT.CHANGED,
                    "reason": "False positive expired",
                    "reference": None,
                    "delta": [{"from": True, "to": False, "key": "false_positive"}],
                }
                ticket["events"].append(event)

    def __handle_ticket_port_closed(self, ticket, closing_time):
        # don't close tickets that are false_positives, just add event
        reason = "port not open"
        self.__check_false_positive_expiration(
            ticket, closing_time.replace(tzinfo=tz.tzutc())
        )  # explicitly set to UTC (see CYHY-286)
        if ticket["false_positive"] is True:
            event = {
                "time": closing_time,
                "action": TICKET_EVENT.UNVERIFIED,
                "reason": reason,
                "reference": None,
            }
        else:
            ticket["open"] = False
            ticket["time_closed"] = closing_time
            event = {
                "time": closing_time,
                "action": TICKET_EVENT.CLOSED,
                "reason": reason,
                "reference": None,
            }
        ticket["events"].append(event)
        ticket.save()

    def open_ticket(self, portscan, reason):
        if self.__closing_time is None or self.__closing_time < portscan["time"]:
            self.__closing_time = portscan["time"]

        # search for previous open ticket that matches
        prev_open_ticket = self.__db.TicketDoc.find_one(
            {
                "ip_int": portscan["ip_int"],
                "port": portscan["port"],
                "protocol": portscan["protocol"],
                "source": portscan["source"],
                "source_id": portscan["source_id"],
                "open": True,
            }
        )
        if prev_open_ticket:
            self.__check_false_positive_expiration(
                prev_open_ticket, portscan["time"].replace(tzinfo=tz.tzutc())
            )  # explicitly set to UTC (see CYHY-286)
            # add an entry to the existing open ticket
            event = {
                "time": portscan["time"],
                "action": TICKET_EVENT.VERIFIED,
                "reason": reason,
                "reference": portscan["_id"],
            }
            prev_open_ticket["events"].append(event)
            prev_open_ticket.save()
            return

        # no matching tickets are currently open
        # search for a previously closed ticket that was closed before the cutoff
        cutoff_date = util.utcnow() + self.__reopen_delta
        reopen_ticket = self.__db.TicketDoc.find_one(
            {
                "ip_int": portscan["ip_int"],
                "port": portscan["port"],
                "protocol": portscan["protocol"],
                "source": portscan["source"],
                "source_id": portscan["source_id"],
                "open": False,
                "time_closed": {"$gt": cutoff_date},
            }
        )

        if reopen_ticket:
            event = {
                "time": portscan["time"],
                "action": TICKET_EVENT.REOPENED,
                "reason": reason,
                "reference": portscan["_id"],
            }
            reopen_ticket["events"].append(event)
            reopen_ticket["time_closed"] = None
            reopen_ticket["open"] = True
            reopen_ticket.save()
            return

        # time to open a new ticket
        new_ticket = self.__db.TicketDoc()
        new_ticket.ip = portscan["ip"]
        new_ticket["port"] = portscan["port"]
        new_ticket["protocol"] = portscan["protocol"]
        new_ticket["source"] = portscan["source"]
        new_ticket["source_id"] = portscan["source_id"]
        new_ticket["owner"] = portscan["owner"]
        new_ticket["time_opened"] = portscan["time"]
        new_ticket["details"] = {
            "cve": None,
            "score_source": None,
            "cvss_base_score": None,
            "severity": 0,
            "name": portscan["name"],
            "service": portscan["service"],
        }

        host = self.__db.HostDoc.get_by_ip(portscan["ip"])
        if host is not None:
            new_ticket["loc"] = host["loc"]

        event = {
            "time": portscan["time"],
            "action": TICKET_EVENT.OPENED,
            "reason": reason,
            "reference": portscan["_id"],
        }
        new_ticket["events"].append(event)

        if (
            new_ticket["owner"] == UNKNOWN_OWNER
        ):  # close tickets with no owner immediately
            event = {
                "time": portscan["time"],
                "action": TICKET_EVENT.CLOSED,
                "reason": "No associated owner",
                "reference": None,
            }
            new_ticket["events"].append(event)
            new_ticket["open"] = False
            new_ticket["time_closed"] = self.__closing_time

        new_ticket.save()

        # Create a notification for this ticket
        self.__create_notification(new_ticket)

    def close_tickets(self, closing_time=None):
        if closing_time is None:
            closing_time = util.utcnow()
        ip_ints = [int(i) for i in self.__ips]

        all_ports_scanned = len(self.__ports) == MAX_PORTS_COUNT

        if all_ports_scanned:
            # If all the ports were scanned we have an opportunity to close port 0
            # tickets. This can only be done if no ports are open for an IP.
            # Otherwise they can be closed in the VULNSCAN stage.
            ips_with_no_open_ports = self.__ips - IPSet(self.__seen_ip_port.keys())
            ips_with_no_open_ports_ints = [int(i) for i in ips_with_no_open_ports]

            # Close all tickets regardless of protocol for ips_with_no_open_ports
            tickets_to_close = self.__db.TicketDoc.find(
                {"ip_int": {"$in": ips_with_no_open_ports_ints}, "open": True}
            )

            for ticket in tickets_to_close:
                self.__handle_ticket_port_closed(ticket, closing_time)

            # handle ips that had at least one port open
            # next query optimized for all_ports_scanned
            tickets = self.__db.TicketDoc.find(
                {
                    "ip_int": {"$in": ip_ints},
                    "port": {"$ne": 0},
                    "protocol": {"$in": list(self.__protocols)},
                    "open": True,
                }
            )
        else:
            # not all ports scanned
            tickets = self.__db.TicketDoc.find(
                {
                    "ip_int": {"$in": ip_ints},
                    "port": {"$in": list(self.__ports)},
                    "protocol": {"$in": list(self.__protocols)},
                    "open": True,
                }
            )

        for ticket in tickets:
            if ticket["port"] in self.__seen_ip_port[ticket["ip"]]:
                # this ticket's ip:port was open, so we skip closing it
                continue
            self.__handle_ticket_port_closed(ticket, closing_time)

    def clear_vuln_latest_flags(self):
        """clear latest flags of vuln_docs that didn't have an associated open port"""
        ip_ints = [int(i) for i in self.__ips]

        # find vulns that are covered by this scan, but weren't just touched
        vuln_docs = self.__db.VulnScanDoc.find(
            {"ip_int": {"$in": ip_ints}, "latest": True}
        )
        for doc in vuln_docs:
            if doc["port"] not in self.__seen_ip_port[doc["ip"]]:
                # this doc's ip:port was not open, so we clear the latest flag
                doc["latest"] = False
                doc.save()


class IPTicketManager(object):
    """Handles the closing of tickets for a host scan (NETSCAN) """

    def __init__(self, db):
        self.__db = db
        self.__ips = IPSet()  # ips that were scanned
        self.__seen_ips = IPSet()  # ips that were up

    @property
    def ips(self):
        return self.__ips

    @ips.setter
    def ips(self, ips):
        self.__ips = IPSet(ips)

    def ip_up(self, ip):
        self.__seen_ips.add(ip)

    def __check_false_positive_expiration(self, ticket, closing_time):
        # if false_positive expiration date has been reached,
        # flip false_positive flag and add CHANGED event
        if ticket["false_positive"] is True:
            fp_effective_date, fp_expiration_date = ticket.false_positive_dates
            if fp_expiration_date < closing_time:
                ticket["false_positive"] = False
                event = {
                    "time": closing_time,
                    "action": TICKET_EVENT.CHANGED,
                    "reason": "False positive expired",
                    "reference": None,
                    "delta": [{"from": True, "to": False, "key": "false_positive"}],
                }
                ticket["events"].append(event)

    def close_tickets(self, closing_time=None):
        if closing_time is None:
            closing_time = util.utcnow()

        not_up_ips = self.__ips - self.__seen_ips

        ip_ints = [int(i) for i in not_up_ips]

        # find tickets with ips that were not up and are open
        tickets = self.__db.TicketDoc.find({"ip_int": {"$in": ip_ints}, "open": True})

        for ticket in tickets:
            # don't close tickets that are false_positives, just add event
            reason = "host down"
            self.__check_false_positive_expiration(
                ticket, closing_time.replace(tzinfo=tz.tzutc())
            )  # explicitly set to UTC (see CYHY-286)
            if ticket["false_positive"] is True:
                event = {
                    "time": closing_time,
                    "action": TICKET_EVENT.UNVERIFIED,
                    "reason": reason,
                    "reference": None,
                }
            else:
                ticket["open"] = False
                ticket["time_closed"] = closing_time
                event = {
                    "time": closing_time,
                    "action": TICKET_EVENT.CLOSED,
                    "reason": reason,
                    "reference": None,
                }
            ticket["events"].append(event)
            ticket.save()

    def clear_vuln_latest_flags(self):
        """clear latest flags of vuln_docs that had IPs that were not up"""
        not_up_ips = self.__ips - self.__seen_ips
        ip_ints = [int(i) for i in not_up_ips]

        # find vulns that are covered by this scan, but weren't just touched
        vuln_docs = self.__db.VulnScanDoc.find(
            {"ip_int": {"$in": ip_ints}, "latest": True}
        )
        for doc in vuln_docs:
            doc["latest"] = False
            doc.save()
