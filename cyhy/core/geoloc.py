#!/usr/bin/env python

__all__ = ["GeoLocDB"]

import os
import sys

import geoip2.database
from geoip2.errors import AddressNotFoundError

GEODB_FILES = ["GeoIP2-City.mmdb", "GeoLite2-City.mmdb"]
GEODB_CITY_PATHS = ["/usr/share/GeoIP/", "/usr/local/share/GeoIP/"]
GEODB_FILE_PATHS = []
RESTRICTED_COUNTRIES = ["China", "Iran", "North Korea", "Russia"]
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
        try:
            # ip is expected to be a netaddr.IPAddress
            response = self.__reader.city(str(ip))
            if response == None:
                return (None, None)
            return (response.location.longitude, response.location.latitude)
        except AddressNotFoundError:
            return (None, None)

    def check_restricted_ip(self, ip):
        try:
            response = self.__reader.city(str(ip))
            if response.country.name in RESTRICTED_COUNTRIES:
                return True,response.country.name
            return False,None
        except AddressNotFoundError:
            print >> sys.stderr, "CIDR %s not found in geolocation database" % cidr
