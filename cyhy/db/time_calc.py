#!/usr/bin/env python

import dateutil
from dateutil.relativedelta import *
from dateutil import parser
from datetime import *
from cyhy.util import util

# windows look like this:
# window =  {"duration" : 10, "start" : "22:00:00", "day" : "Saturday"}


def in_windows(windows, time=None):
    if time == None:
        time = util.utcnow()

    for w in windows:
        parse_me = "%s %s" % (w["day"], w["start"])
        dt = parser.parse(parse_me)
        dow = dt.weekday()
        relative_weekday = dateutil.relativedelta.weekday(dow)
        duration = int(w["duration"])
        delta = relativedelta(
            weekday=relative_weekday(-1),
            hour=dt.hour,
            minute=dt.minute,
            second=dt.second,
            microsecond=dt.microsecond,
        )
        window_start = time + delta
        window_duration = relativedelta(hours=+duration)
        window_close = window_start + window_duration
        if time > window_start and time < window_close:
            return True
    return False
