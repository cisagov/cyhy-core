__all__ = ["Config"]

import os
from ConfigParser import SafeConfigParser

DEFAULT_CONFIG_FILENAME = os.path.expanduser("/etc/cyhy/cyhy.conf")
DEFAULT = "DEFAULT"
PRODUCTION_SECTION = "production"
TESTING_SECTION = "testing"
DATABASE_NAME = "database-name"
DATABASE_URI = "database-uri"
REPORT_KEY = "report-key"
DEFAULT_SECTION = "default-section"
TESTING_DATABASE_NAME = "test_cyhy"
PRODUCTION_DATABASE_NAME = "cyhy"
DEFAULT_DATABASE_URI = "mongodb://localhost:27017/"


class Config(object):
    def __init__(self, config_section=None, config_filename=None):
        if config_filename:
            self.config_filename = config_filename
        else:
            self.config_filename = DEFAULT_CONFIG_FILENAME
        if not os.path.exists(self.config_filename):
            self.__write_config()
            self.config_created = self.config_filename
        else:
            self.config_created = None
        config = self.__read_config()
        if config_section == None:
            config_section = config.get(DEFAULT, DEFAULT_SECTION)
        self.active_section = config_section
        self.db_name = config.get(config_section, DATABASE_NAME)
        self.db_uri = config.get(config_section, DATABASE_URI)
        self.report_key = config.get(config_section, REPORT_KEY)

    def __read_config(self):
        config = SafeConfigParser()
        config.read([self.config_filename])
        return config

    def __write_config(self):
        config = SafeConfigParser()
        config.add_section(PRODUCTION_SECTION)
        config.add_section(TESTING_SECTION)
        # config section None goes to [DEFAULT]
        config.set(None, DEFAULT_SECTION, TESTING_SECTION)
        config.set(PRODUCTION_SECTION, DATABASE_NAME, PRODUCTION_DATABASE_NAME)
        config.set(TESTING_SECTION, DATABASE_NAME, TESTING_DATABASE_NAME)
        config.set(None, DATABASE_URI, DEFAULT_DATABASE_URI)
        config.set(None, REPORT_KEY, "")
        with open(self.config_filename, "wb") as config_file:
            config.write(config_file)
