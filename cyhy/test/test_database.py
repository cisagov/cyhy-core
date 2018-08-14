#!/usr/bin/env py.test -v

import pytest
import cyhy.db.database as db
from cyhy.core.yaml_config import YamlConfig
import mock

class TestDatabase:

    @mock.patch('cyhy.db.database.db_from_connection')
    def test_from_config_etc(self, mock_db_from_connection):
        db.db_from_config() # default section set to testing
        mock_db_from_connection.assert_called_with(
            'mongodb://test:test@localhost:27017/test-cyhy', 'test-cyhy')

        db.db_from_config('testing')
        mock_db_from_connection.assert_called_with(
            'mongodb://test:test@localhost:27017/test-cyhy', 'test-cyhy')

    @mock.patch('cyhy.db.database.db_from_connection')
    def test_from_config_conf(self, mock_db_from_connection):
        db.db_from_config('testconf', 'inputs/test-conf.conf')
        mock_db_from_connection.assert_called_with(
            'mongodb://test:test@localhost:27017/test-conf', 'test-name')

        db.db_from_config(config_filename='inputs/test-conf.conf')
        mock_db_from_connection.assert_called_with(
            'mongodb://test:test@localhost:27017/test-conf', 'test-name')

    @mock.patch('cyhy.db.database.db_from_connection')
    def test_from_config_yml(self, mock_db_from_connection):
        db.db_from_config('default', 'inputs/test_all.yml', True)
        mock_db_from_connection.assert_called_with(
            'mongodb://dbuser:dbpass@localhost:27017/local', 'localuser')

        db.db_from_config(config_filename='inputs/test_all.yml', yaml=True)
        mock_db_from_connection.assert_called_with(
            'mongodb://dbuser:dbpass@localhost:27017/local', 'localuser')
