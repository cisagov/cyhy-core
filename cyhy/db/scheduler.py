__all__ = ['DefaultScheduler']

from collections import defaultdict
from datetime import datetime

from cyhy.core.common import *
from cyhy.db.queries import max_severity_for_host
from cyhy.db import database
from cyhy.util import util

from dateutil.relativedelta import relativedelta as delta
import pandas as pd
import numpy as np

class BaseScheduler(object):
    '''Base class for all schedulers'''
    def __init__(self, db):
        self._db = db

    def schedule(self, host):
        '''modifies host using schedule but does NOT save it'''
        pass


class DefaultScheduler(BaseScheduler):
    # The priority can be adjusted over a range of -20 (the highest) to 20 (the lowest).
    # Priority is based on the Unix scheduler and the nice/renice tools

    # the priority of a host that was down
    RESTING_DOWN_PRIORITY = 1

    # the priority of a host that was up
    RESTING_UP_PRIORITY = -1

    # mapping of vuln severities to priorities
    SEVERITY_PRIORITY = {1 : -2,
                         2 : -4,
                         3 : -8,
                         4 : -16}

    # create a series with all our priorites as the index
    PRIORITY_TIMES = pd.Series(np.nan, index=range(1,-17,-1))

    # set the time in hours for specific priorities
    PRIORITY_TIMES[1] = 90 * 24
    PRIORITY_TIMES[0] = 14 * 24
    PRIORITY_TIMES[-1] = 7 * 24
    PRIORITY_TIMES[-4] = 4 * 24
    PRIORITY_TIMES[-8] = 1 * 24
    PRIORITY_TIMES[-16] = 12

    # interpolate the time for all other priorities
    PRIORITY_TIMES.interpolate(inplace=True)

    # convert the time in hours to time deltas
    PRIORITY_TIMES = PRIORITY_TIMES.apply(lambda x:delta(hours=x))

    def __priority_for_severity(self, severity):
        if severity < 1:
            severity = 1
        elif severity > 4:
            severity = 4
        return self.SEVERITY_PRIORITY[severity]

    def __timedelta_for_priority(self, priority):
        if priority < self.PRIORITY_TIMES.index.min():
            priority = self.PRIORITY_TIMES.index.min()
        elif priority > self.PRIORITY_TIMES.index.max():
            priority = self.PRIORITY_TIMES.index.max()
        return self.PRIORITY_TIMES[priority]

    def __process_down_host(self, host):
        if host['priority'] < self.RESTING_DOWN_PRIORITY:
            host['priority'] += 1

    def __process_vuln_host(self, host, max_severity):
        priority_from_severity = self.__priority_for_severity(max_severity)

        if priority_from_severity == host['priority']:
            # noop, host is where it should be
            return

        if priority_from_severity < host['priority']:
            # host is worthy of a higher priority (lower number)
            host['priority'] = priority_from_severity
            return

        # host is recovering from a previous more severe vuln, decay
        host['priority'] += 1

    def __process_vuln_free_host(self, host):
        if host['priority'] < self.RESTING_UP_PRIORITY:
            # decay host back to "resting up"
            host['priority'] += 1
        elif host['priority'] > self.RESTING_UP_PRIORITY:
            # host was previously down (or worse)
            host['priority'] = self.RESTING_UP_PRIORITY

    def __host_max_severity(self, host):
        ip_int = host['_id']
        q = max_severity_for_host(ip_int)
        r = database.run_pipeline_cursor(q, self._db)
        database.id_expand(r)
        if len(r) > 0:
            # found tickets
            return r[0]['severity_max']
        else:
            # no tickets
            return 0

    def schedule(self, host):
        super(DefaultScheduler, self).schedule(host)

        # determine the new priority for the host
        if host['state']['up'] == False:
            self.__process_down_host(host)
        else:
            # host was up
            max_severity = self.__host_max_severity(host)
            if max_severity > 0:
                self.__process_vuln_host(host, max_severity)
            else:
                self.__process_vuln_free_host(host)

        # determine the next scan time based on the priority
        d = self.__timedelta_for_priority(host['priority'])
        host['next_scan'] = util.utcnow() + d
