__all__ = ["GeoLocDB"]

import os
import sys

import geoip2.database
from geoip2.errors import AddressNotFoundError

GEODB_FILES = ["GeoIP2-City.mmdb", "GeoLite2-City.mmdb"]
GEODB_CITY_PATHS = ["/usr/share/GeoIP/", "/usr/local/share/GeoIP/"]
GEODB_FILE_PATHS = []

# The list of restricted countries was provided by CISA International Affairs
# in March 2024.
# The MaxMind GeoLite2 and GeoIP2 databases that we support use 
# https://www.geonames.org/countries/ as the data source for country names.
# For more info, see: 
# https://support.maxmind.com/hc/en-us/articles/4414877149467-IP-Geolocation-Data#h_01FRRNFD5Z5EWNCAXM6SZZ5H2C
RESTRICTED_COUNTRIES = [
    "Afghanistan",
    "Belarus",
    "Cambodia",
    "Central African Republic",
    "China",
    "Cuba",
    "Cyprus",
    "DR Congo",
    "Eritrea",
    "Ethiopia",
    "Haiti",
    "Iran",
    "Iraq",
    "Lebanon",
    "Libya",
    "Myanmar",
    "North Korea",
    "Russia",
    "Somalia",
    "South Sudan",
    "Sudan",
    "Syria",
    "Venezuela",
    "Zimbabwe",
]

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
                return response.country.name
        except AddressNotFoundError:
            print >> sys.stderr, "IP %s not found in geolocation database" % ip

        return ""
