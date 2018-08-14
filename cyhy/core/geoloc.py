#!/usr/bin/env python

__all__ = ['GeoLocDB']

import sys
import os 
import geoip2.database 

GEODB_CITY_PATHS = ['/usr/share/GeoIP/GeoLite2-City.mmdb', '/usr/local/share/GeoIP/GeoLite2-City.mmdb']

class GeoLocDB(object):
    def __init__(self, database_path=None):
        if not database_path:
            for path in GEODB_CITY_PATHS:
                if os.path.exists(path):
                    database_path = path
                    break
            else:
                raise Exception('No GeoIP databases found.  Search in:', GEODB_CITY_PATHS)
        self.__reader = geoip2.database.Reader(database_path)

    def lookup(self, ip):
        # ip is expected to be a netaddr.IPAddress
        response = self.__reader.city(str(ip))
        if response == None:
            return (None, None)
        return (response.location.longitude, response.location.latitude)