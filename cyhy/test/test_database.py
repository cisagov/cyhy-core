#!/usr/bin/env py.test -v

import pytest
import cyhy.db.database as db
from cyhy.core.config import DEFAULT_CONFIG_FILENAME
from cyhy.core.yaml_config import YamlConfig
from paths import input_path
import mock

# Contents of the fake default configuration file used by
# test_from_config_etc().  Creating this file in a fake filesystem keeps the
# test independent of whatever configuration happens to exist on the machine
# running the test suite.
DEFAULT_CONFIG_CONTENTS = """[DEFAULT]
default-section = testing
report-key = test-report-key

[testing]
database-uri = mongodb://test:test@localhost:27017/test-cyhy
database-name = test-cyhy
"""


class TestDatabase:
    @mock.patch("cyhy.db.database.db_from_connection")
    def test_from_config_etc(self, mock_db_from_connection, fs):
        # The fs fixture is provided by pyfakefs and replaces the filesystem for
        # the duration of this test, so the configuration file created below
        # shadows the real /etc/cyhy/cyhy.conf.
        fs.create_file(DEFAULT_CONFIG_FILENAME, contents=DEFAULT_CONFIG_CONTENTS)

        db.db_from_config()  # default section set to testing
        mock_db_from_connection.assert_called_with(
            "mongodb://test:test@localhost:27017/test-cyhy", "test-cyhy"
        )

        db.db_from_config("testing")
        mock_db_from_connection.assert_called_with(
            "mongodb://test:test@localhost:27017/test-cyhy", "test-cyhy"
        )

    @mock.patch("cyhy.db.database.db_from_connection")
    def test_from_config_conf(self, mock_db_from_connection):
        db.db_from_config("testconf", input_path("test-conf.conf"))
        mock_db_from_connection.assert_called_with(
            "mongodb://test:test@localhost:27017/test-conf", "test-name"
        )

        db.db_from_config(config_filename=input_path("test-conf.conf"))
        mock_db_from_connection.assert_called_with(
            "mongodb://test:test@localhost:27017/test-conf", "test-name"
        )

    @mock.patch("cyhy.db.database.db_from_connection")
    def test_from_config_yml(self, mock_db_from_connection):
        db.db_from_config("default", input_path("test_all.yml"), True)
        mock_db_from_connection.assert_called_with(
            "mongodb://dbuser:dbpass@localhost:27017/local", "localuser"
        )

        db.db_from_config(config_filename=input_path("test_all.yml"), yaml=True)
        mock_db_from_connection.assert_called_with(
            "mongodb://dbuser:dbpass@localhost:27017/local", "localuser"
        )
