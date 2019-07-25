#!/usr/bin/env python

__all__ = ["GeoLocDB"]

import os
import sys

import geoip2.database

GEODB_FILES = ["GeoIP2-City.mmdb", "GeoLite2-City.mmdb"]
GEODB_CITY_PATHS = ["/usr/share/GeoIP/", "/usr/local/share/GeoIP/"]
GEODB_FILE_PATHS = []
# Ensure that the order in GEODB_FILES is used for searching
for file in GEODB_FILES:
    for path in GEODB_CITY_PATHS:
        GEODB_FILE_PATHS.append(path + file)


class GeoLocDB(object):
    def __init__(self, database_path=None):
        if not database_path:
            for file in GEODB_FILE_PATHS:
                if os.path.exists(file):
                    database_path = file
                    break
            else:
                raise Exception(
                    "No GeoIP databases found.  Search in:", GEODB_CITY_PATHS
                )
        self.__reader = geoip2.database.Reader(database_path)

    def lookup(self, ip):
        # ip is expected to be a netaddr.IPAddress
        response = self.__reader.city(str(ip))
        if response == None:
            return (None, None)
        return (response.location.longitude, response.location.latitude)
