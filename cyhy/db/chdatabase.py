__all__ = ['CHDatabase']

import sys
import datetime
import copy
import progressbar as pb
import logging

from cyhy.core import Config, STATUS, STAGE
from cyhy.db import database, queries, DefaultHostStateManager, DefaultScheduler

from cyhy.util import util
from cyhy.core.common import *
import time_calc
import time
import netaddr
from bson import ObjectId
import pandas as pd
import numpy as np

class CHDatabase(object):
    #TODO These will eventually come from the request
    TEMP_MAX_CONCURRENCY = {STAGE.NETSCAN1:256, STAGE.NETSCAN2:256, STAGE.PORTSCAN:32, STAGE.VULNSCAN:32, STAGE.BASESCAN:512}
    TEMP_OFF_CONCURRENCY = {STAGE.NETSCAN1:0, STAGE.NETSCAN2:0, STAGE.PORTSCAN:0, STAGE.VULNSCAN:0, STAGE.BASESCAN:0}
    SNAPSHOT_PIPELINES = 13 # number of pipelines run by the create snapshot command
    SNAPSHOT_CLOSED_TICKET_HISTORY_DAYS = 365  # number of days of closed tickets to include in closed tix metrics

    def __init__(self, db, state_manager=None, scheduler=None, next_scan_limit=2000):
        '''db: MongoDB instance
           state_manager: class that implements a HostStateManager
           scheduler: class that implements a Scheduler'''
        self.__db = db
        self.__logger = logging.getLogger(__name__)
        self.__scheduler = scheduler
        self.__next_scan_limit = next_scan_limit
        if state_manager == None:
            self.__state_manager = DefaultHostStateManager()
        else:
            self.__state_manager = state_manager()
        if scheduler == None:
            self.__scheduler = DefaultScheduler(self.__db)
        else:
            self.__scheduler = scheduler(self.__db)

    def __str__(self):
        return '<CHDatabase %s>' % (self.__db)

    def request_limits(self, when=None):
        # returns {owner: {stage:limit, stage:limit, ...}, ...}
        if when == None:
            when = util.utcnow()
        requests = self.__db.RequestDoc.find({'scan_types':SCAN_TYPE.CYHY})
        results = {}
        for request in requests:
            if request['period_start'] < when and time_calc.in_windows(request['windows'], when):
                limits = copy.copy(self.TEMP_MAX_CONCURRENCY)
                for limit in request.get('scan_limits',[]):
                    limits[limit['scanType']] = limit['concurrent']
            else:
                limits = self.TEMP_OFF_CONCURRENCY
            results[request['_id']] = limits
        return results

    def increase_ready_hosts(self, owner, stage, count):
        changed_count = self.__db.HostDoc.increase_ready_hosts(owner, stage, count)
        tally = self.__db.TallyDoc.get_by_owner(owner)
        tally.transfer(stage, STATUS.WAITING, stage, STATUS.READY, changed_count)
        tally.save()
        return changed_count

    def decrease_ready_hosts(self, owner, stage, count):
        changed_count = self.__db.HostDoc.decrease_ready_hosts(owner, stage, count)
        tally = self.__db.TallyDoc.get_by_owner(owner)
        tally.transfer(stage, STATUS.READY, stage, STATUS.WAITING, changed_count)
        tally.save()
        return changed_count

    def balance_ready_hosts(self):
        '''Makes sure the correct number of hosts are in the READY state'''
        limits = self.request_limits()
        for (owner, limit) in limits.items():
            tally = self.__db.TallyDoc.get_by_owner(owner)
            if tally == None:
	            self.__logger.warning('No tally document found for: %s ... skipping.' % owner)
	            continue
            for (stage, target_active_count) in limit.items():
                (waiting_count, ready_count, running_count) = tally.active_host_count(stage)
                active_count = ready_count + running_count
                if active_count != target_active_count:
                    should_be_ready = max(0, target_active_count - running_count)
                    if should_be_ready > ready_count and waiting_count > 0:
                        requested_increase = should_be_ready - ready_count
                        actual_increase = self.increase_ready_hosts(owner, stage, requested_increase)
                        if actual_increase:
                             self.__logger.debug('%s %s target=%d [READY:%d + RUNNING:%d = ACTIVE:%d] + READY:%d = %d' % \
                             (owner, stage, target_active_count, ready_count, running_count, active_count, actual_increase, active_count+actual_increase))
                    elif should_be_ready < ready_count:
                        requested_decrease = ready_count - should_be_ready
                        actual_decrease = self.decrease_ready_hosts(owner, stage, requested_decrease)
                        if actual_decrease:
                            self.__logger.debug('%s %s target=%d [READY:%d + RUNNING:%d = ACTIVE:%d] - READY:%d = %d' % \
                            (owner, stage, target_active_count, ready_count, running_count, active_count, actual_decrease, active_count-actual_decrease))

    def reset_state_by_schedule(self):
        hosts_modified_count = self.__db.HostDoc.reset_state_by_schedule()
        return hosts_modified_count

    def tally_update(self, owner, prev_stage, prev_status, new_stage, new_status):
        tally = self.__db.TallyDoc.get_by_owner(owner)
        if tally == None:
            self.__logger.warning('Tally document not found for: %s ... skipping.' % owner)
            return
        tally.transfer(prev_stage, prev_status, new_stage, new_status, 1)
        tally.save()

    def transition_host(self, ip, up=None, reason=None, has_open_ports=None, was_failure=False):
        '''Attempts to move host from one state to another.
           returns (HostDoc, state_changed)
            - HostDoc: host that was transitioned
            - state_changed: True if the state changed, False otherwise.'''
        host = self.__db.HostDoc.get_by_ip(ip)
        if host == None:
            self.__logger.warning('Could not find %s in database during transition_host call' % ip)
            return (None, False)

        prev_stage = host['stage']
        prev_status = host['status']
        host_transitioned, host_finished_stage = self.__state_manager.transition(host, up, has_open_ports, was_failure)

        # Calculating the state of a HostDoc is non-trivial.
        host.set_state(up, has_open_ports, reason)

        # If host finished a stage, update timestamp for latest_scan.<stage_that_just_finished>
        current_time = util.utcnow()
        if host_finished_stage:
           host['latest_scan'][prev_stage] = current_time

        if host['status'] == STATUS.DONE:
            host['latest_scan'][STATUS.DONE] = current_time  # Update timestamp for reaching DONE status
            # check to see if owner should use a scheduler
            request = self.__db.requests.find_one({'_id':host['owner']},{'scheduler':True})
            if request and request.get('scheduler') != None:
                self.__scheduler.schedule(host)

        # save all changes made to the host by the state manager and the scheduler
        host.save()

        if host_transitioned:
            new_stage = host['stage']
            new_status = host['status']
            owner = host['owner']
            self.tally_update(owner, prev_stage, prev_status, new_stage, new_status)

        return (host, host_transitioned)

    def __update_hosts_next_scans(self, cursor, new_stage, new_status):
        hosts_processed = 0
        for host in cursor:
            self.tally_update(host['owner'], host['stage'], host['status'], new_stage, new_status)
            host['stage'] = new_stage
            host['status'] = new_status
            host['next_scan'] = None
            host.save()
            hosts_processed += 1
        cursor.close()
        return hosts_processed

    def check_host_next_scans(self):
        '''Moves hosts to WAITING status based on their "next_scan" field.
        jump_starts previously "up" hosts, and ignores the owner init_stage (to be deprecated)
        returns the number of modified hosts'''
        now = util.utcnow()
        # move "up" hosts to STAGE.PORTSCAN, STATUS.WAITING
        up_hosts_cursor = self.__db.HostDoc.get_scheduled_hosts(True, now, self.__next_scan_limit)
        self.__logger.debug('Updating previous "up" hosts that are now due to be scanned.')
        hosts_processed = self.__update_hosts_next_scans(up_hosts_cursor, STAGE.PORTSCAN, STATUS.WAITING)
        self.__logger.debug('Updated %d "up" hosts.' % hosts_processed)

        # move "down" hosts to STAGE.NETSCAN1, STATUS.WAITING
        down_hosts_cursor = self.__db.HostDoc.get_scheduled_hosts(False, now, self.__next_scan_limit)
        self.__logger.debug('Updating previous "down" hosts that are now due to be scanned.')
        hosts_processed = self.__update_hosts_next_scans(down_hosts_cursor, STAGE.NETSCAN1, STATUS.WAITING)
        self.__logger.debug('Updated %d "down" hosts.' % hosts_processed)

    def fetch_ready_hosts(self, count, stage, owner=None, waiting_too=False):
        hosts = self.__db.HostDoc.get_some_for_stage(stage, count, owner, waiting_too)
        # NOTE: there is a race condition here, but it won't occur with one commander.
        # And the worst case scenario is that a host is scanned twice
        # Used to be slow multiple find_and_update
        ips = []
        for host in hosts:
            int_ip = host['_id']
            self.transition_host(int_ip)
            ips.append(host['ip'])
        return ips

    def get_open_ports(self, ip_list):
        '''takes a list of IPs and returns a sorted list of open ports'''
        result = set()
        for ip in ip_list:
            ports = self.__db.PortScanDoc.get_open_ports_for_ip(ip)
            result.update(ports)
        result = list(result)
        result.sort()
        return result

    def __process_services(self, results):
        services = {}
        for r in results:
            service_name = r['_id']['service_name']
            service_name = util.clean_mongo_key(service_name)
            count = r['count']
            services[service_name] = count
        return services

    def __process_open_ticket_age(self, results, open_as_of_date):
        open_ticket_age = {}
        open_ticket_age['tix_open_as_of_date'] = open_as_of_date            # Save the date when these calcs were run
        if results:
            df = pd.DataFrame(results)
            for (severity_name,severity_id) in [('critical',4), ('high',3), ('medium',2), ('low',1)]:
                results_for_severity = df.loc[df['severity'] == severity_id]['open_msec']
                if results_for_severity.empty:
                    open_ticket_age[severity_name] = {'median':None, 'max':None}
                else:
                    age_median = long(np.median(results_for_severity))
                    age_max = long(np.max(results_for_severity))
                    open_ticket_age[severity_name] = {'median':age_median, 'max':age_max}
        else:   # No open tix right now
            for severity_name in ['critical', 'high', 'medium', 'low']:
                open_ticket_age[severity_name] = {'median':None, 'max':None}
        return open_ticket_age

    def __process_closed_ticket_age(self, results, closed_after_date):
        closed_ticket_age = {}
        closed_ticket_age['tix_closed_after_date'] = closed_after_date      # Only calculate these metrics for tix that closed on/after this date
        if results:
            df = pd.DataFrame(results)
            for (severity_name,severity_id) in [('critical',4), ('high',3), ('medium',2), ('low',1)]:
                results_for_severity = df.loc[df['severity'] == severity_id]['msec_to_close']
                if results_for_severity.empty:
                    closed_ticket_age[severity_name] = {'median':None, 'max':None}
                else:
                    age_median = long(np.median(results_for_severity))
                    age_max = long(np.max(results_for_severity))
                    closed_ticket_age[severity_name] = {'median':age_median, 'max':age_max}
        else:   # No closed tix that closed in our date range (closed_after_date until now)
            for severity_name in ['critical', 'high', 'medium', 'low']:
                closed_ticket_age[severity_name] = {'median':None, 'max':None}
        return closed_ticket_age

    def __get_tag_timespan(self, oid):
        '''determines the earliest, and latest times of documents'''
        pipeline = queries.time_span(oid)
        r1 = database.run_pipeline((pipeline, database.HOST_SCAN_COLLECTION), self.__db)
        r2 = database.run_pipeline((pipeline, database.PORT_SCAN_COLLECTION), self.__db)
        r3 = database.run_pipeline((pipeline, database.VULN_SCAN_COLLECTION), self.__db)
        database.id_expand(r1)
        database.id_expand(r2)
        database.id_expand(r3)

        spans = []
        if r1:
            spans.append(r1[0])
        if r2:
            spans.append(r2[0])
        if r3:
            spans.append(r3[0])

        if len(spans) == 0:
            return None, None
        else:
            start_time = min([i['start_time'] for i in spans])
            end_time = max([i['end_time'] for i in spans])
            return start_time, end_time

    def __get_host_timespan(self, owners):
        '''determines the earliest and latest last_changed times of hosts'''
        pipeline_collection = queries.host_time_span(owners)
        results = database.run_pipeline(pipeline_collection, self.__db)
        database.id_expand(results)

        if len(results) == 0:
            return None, None   # owner has no host docs
        else:
            start_time = results[0]['start_time']
            end_time = results[0]['end_time']
            return start_time, end_time

    def remove_tag(self, snapshot_oid):
        '''removes a snapshot tag from all documents.
        If a snapshot conflicts this may be needed.'''
        self.__db.HostScanDoc.remove_tag(snapshot_oid)
        self.__db.PortScanDoc.remove_tag(snapshot_oid)
        self.__db.VulnScanDoc.remove_tag(snapshot_oid)
        self.__db.TicketDoc.remove_tag(snapshot_oid)

    def tag_latest(self, owners):
        '''tag latest documents of list of owner with a new oid.  Returns oid.'''
        oid = ObjectId()
        self.__db.HostScanDoc.tag_latest(owners, oid)
        self.__db.PortScanDoc.tag_latest_open(owners, oid)
        self.__db.VulnScanDoc.tag_latest(owners, oid)
        self.__db.TicketDoc.tag_open(owners, oid)
        return oid

    def tag_matching(self, existing_snapshot_oids):
        '''tag documents matching a list of existing_snapshot_oids with a new oid.  Returns oid.'''
        oid = ObjectId()
        self.__db.HostScanDoc.tag_matching(existing_snapshot_oids, oid)
        self.__db.PortScanDoc.tag_matching(existing_snapshot_oids, oid)
        self.__db.VulnScanDoc.tag_matching(existing_snapshot_oids, oid)
        self.__db.TicketDoc.tag_matching(existing_snapshot_oids, oid)
        return oid

    def tag_timespan(self, owner, start_time, end_time):
        '''tag timespan documents of owner with a new oid.
        Used for backfilling.
        Returns oid.'''
        oid = ObjectId()
        self.__db.HostScanDoc.tag_timespan(owner, oid, start_time, end_time)
        self.__db.PortScanDoc.tag_timespan(owner, oid, start_time, end_time)
        self.__db.VulnScanDoc.tag_timespan(owner, oid, start_time, end_time)
        return oid

    def create_snapshot(self, owner, snapshot_oid, parent_oid=None, descendants_included=[], exclude_from_world_stats=False, progress_callback=None):
        '''creates a new snapshot document with the oid returned from one of the tagging methods.
        Returns the snapshot if the snapshot is created successfully.
        Returns None if the snapshot is not unique.  In this case reports should be untagged.'''
        snapshot_doc = self.__db.SnapshotDoc()
        snapshot_doc['_id'] = snapshot_oid
        snapshot_doc['latest'] = True
        snapshot_doc['owner'] = owner
        snapshot_doc['descendants_included'] = descendants_included
        if parent_oid:
            snapshot_doc['parents'] = [parent_oid]
        else:
            snapshot_doc['parents'] = [snapshot_oid]    # If you don't have a parent snapshot, you are your own parent; this prevents deletion of
                                                        # this snap if it ever becomes a child of another snapshot that later gets deleted
        snapshot_doc['networks']  = self.__db.RequestDoc.get_by_owner(owner).networks.iter_cidrs()
        for descendant in descendants_included:
            snapshot_doc['networks'] += self.__db.RequestDoc.get_by_owner(descendant).networks.iter_cidrs()

        if exclude_from_world_stats:
            snapshot_doc['exclude_from_world_stats'] = True

        current_time = util.utcnow()
        snapshot_doc['last_change'] = current_time

        start_time, end_time = self.__get_tag_timespan(snapshot_oid)    # Try to get start/end time from host_scan/port_scan/vuln_scan docs
        if start_time == None:      # If org has no latest=true host_scans, port_scans or vuln_scans, start_time will be None
            start_time, end_time = self.__get_host_timespan([owner] + descendants_included)      # Try to get start/end time from host docs (not ideal, but better than nothing)
            if start_time == None:  # If org(s) have no host docs (or hosts that have not been netscanned yet), start_time will be None
                start_time = end_time = current_time     # All else has failed- just set start/end time to current time

        snapshot_doc['start_time'] = start_time
        snapshot_doc['end_time'] = end_time

        if progress_callback:
            progress_callback()

        if snapshot_doc.will_conflict():
            snapshot_doc['end_time'] = current_time      # Avoid conflicts by setting end_time to current time
                                                         # Not ideal, but will only happen in rare cases and should have minimal impact

        pipeline_collection = queries.addresses_scanned_pl([owner] + descendants_included)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.cvss_sum_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        if results:
            cvss_sum = float(results[0].get('cvss_sum', 0.0))
        else:
            cvss_sum = 0.0

        pipeline_collection = queries.host_count_pl([owner] + descendants_included)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.vulnerable_host_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        snapshot_doc['cvss_average_all'] = util.safe_divide(cvss_sum, snapshot_doc['host_count'])
        snapshot_doc['cvss_average_vulnerable'] = util.safe_divide(cvss_sum, snapshot_doc['vulnerable_host_count'])

        pipeline_collection = queries.unique_operating_system_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.port_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.unique_port_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.silent_port_count_pl([owner] + descendants_included)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results)

        pipeline_collection = queries.severity_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results, 'vulnerabilities')

        pipeline_collection = queries.unique_severity_count_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results, 'unique_vulnerabilities')

        pipeline_collection = queries.false_positives_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results, 'false_positives')

        pipeline_collection = queries.service_counts_simple_pl(snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        services = self.__process_services(results)
        snapshot_doc['services'] = services

        pipeline_collection = queries.open_ticket_age_in_snapshot_pl(current_time, snapshot_oid)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        snapshot_doc['tix_msec_open'] = self.__process_open_ticket_age(results, current_time)

        tix_closed_since_date = current_time - datetime.timedelta(self.SNAPSHOT_CLOSED_TICKET_HISTORY_DAYS)
        pipeline_collection = queries.closed_ticket_age_for_orgs_pl(tix_closed_since_date, [owner] + descendants_included)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        snapshot_doc['tix_msec_to_close'] = self.__process_closed_ticket_age(results, tix_closed_since_date)

        # reset previous latest flag
        self.__db.SnapshotDoc.reset_latest_flag_by_owner(owner)
        snapshot_doc.save()

        # now calculate the world statistics and update the snapshot
        # Since parent snapshots include data for their descendants, we don't want to count descendant snapshots when calculating world stats
        # NOTE: This won't work if a snapshot is created for a descendant org on it's own after the parent org snapshot was created, but
        #       it's good enough for now.  The world statistics process should get updated as part of CYHY-145.
        snaps_to_exclude_from_world_stats = list()
        all_latest_snapshots = list(self.__db.SnapshotDoc.collection.find({'latest':True}, {'_id':1, 'parents':1, 'exclude_from_world_stats':1}))
        for snap in all_latest_snapshots:
            if (snap['_id'] not in snap['parents']) or snap.get('exclude_from_world_stats'):
                # NOTE: A descendant snapshot has a different parent id than itself
                snaps_to_exclude_from_world_stats.append(snap['_id'])

        pipeline_collection = queries.world_pl(snaps_to_exclude_from_world_stats)
        results = database.run_pipeline(pipeline_collection, self.__db)
        if progress_callback:
            progress_callback()
        database.combine_results(snapshot_doc, results, 'world')

        snapshot_doc.save()
        return snapshot_doc

    def ignore_ticket(self, ip, port, source, source_id, reason):
        ticket = self.__db.TicketDoc.find_one({'ip_int':long(ip),
                                                'port':port,
                                                'source':source,
                                                'source_id':source_id,
                                                'open':True,
                                                'false_positive':False})
        if not ticket:
            return False

        ticket['false_positive'] = True
        ticket.add_event(TICKET_EVENT.CHANGED, reason, delta={'from':False, 'to':True, 'key':'false_positive'})
        ticket.save()
        return True

    def done_scanning(self, tally_time_after=None):
        '''Gets a list of all the owners who are done scanning but need a snapshot.
        Owners that are using persistent schedulers are omitted.
        This works for organizations that complete a full run between snapshots.
        tally_time_after allows a tallies that are too old to be filtered out.'''

        # return list of owners (and times) who have all hosts with status.done at all stages
        query = {}
        # build the query from the stage and status enumerations
        for stage in STAGE:
            for status in list(STATUS)[:-1]: # every status but DONE
                query['counts' + '.' + stage + '.' + status] = 0
        tallies = self.__db.TallyDoc.find(query, {'_id':True, 'last_change':True})

        owners_that_need_snapshot = []

        for t in tallies:
            owner = t['_id']
            tally_time = t['last_change']
            # skip tallies that are too old
            if tally_time_after and tally_time < tally_time_after:
                continue
            latest_snapshot = self.__db.SnapshotDoc.find_one({'owner':owner, 'latest':True})
            request = self.__db.RequestDoc.get_by_owner(owner)
            owner_has_scheduler = request.get('scheduler') != None
            if owner_has_scheduler == False and (latest_snapshot == None or tally_time > latest_snapshot['last_change']):
                owners_that_need_snapshot.append(owner)

        owners_that_need_snapshot.sort()

        return owners_that_need_snapshot

    def change_ownership(self, orig_owner, new_owner, networks, reason):
        # Change owner on all relevant documents for a given list of networks.
        # Special case for tickets collection; add a CHANGED event to the events list of each ticket
        change_event = {'time':util.utcnow(), 'action':TICKET_EVENT.CHANGED, 'reason':reason, 'reference':None, 'delta':[{'from':orig_owner, 'to':new_owner, 'key':'owner'}]}
        for net in networks.iter_cidrs():
            print 'Changing owner of network %s to %s' % (net, new_owner)
            for collection,ip_key,update_cmd in ((self.__db.hosts,'_id',{'$set':{'owner':new_owner}}),
                                             (self.__db.host_scans,'ip_int',{'$set':{'owner':new_owner}}),
                                             (self.__db.port_scans,'ip_int',{'$set':{'owner':new_owner}}),
                                             (self.__db.vuln_scans,'ip_int',{'$set':{'owner':new_owner}}),
                                             (self.__db.tickets,'ip_int',{'$set':{'owner':new_owner}, '$push':{'events':change_event}})):
                result = collection.update({ip_key:{'$gte':net.first, '$lte':net.last}},update_cmd, upsert=False, multi=True, safe=True)
                result['collection'] = collection.name
                print '  {nModified} {collection} documents modified'.format(**result)

    def pause_commander(self, sender, reason):
        '''Request that the commander pause processing.
        Returns a document that will contain the status of the request.  This
        document can be polled to wait for processing to complete.
        To cancel the action, delete the document.'''
        control_doc = self.__db.SystemControlDoc()
        control_doc['action'] = CONTROL_ACTION.PAUSE
        control_doc['target'] = CONTROL_TARGET.COMMANDER
        control_doc['sender'] = sender
        control_doc['reason'] = reason
        control_doc.save()
        return control_doc

    def should_commander_pause(self, apply_actions=True):
        docs = self.__db.SystemControlDoc.find({'action':CONTROL_ACTION.PAUSE, 'target':CONTROL_TARGET.COMMANDER})
        if docs.count() == 0:
            return False
        if apply_actions:
            for doc in docs:
                doc['completed'] = True
                doc.save()
        return True
