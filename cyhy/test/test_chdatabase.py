#!/usr/bin/env py.test -v

import pytest
import cyhy.db.chdatabase as chdb
import cyhy.db.database as db
from cyhy.core.yaml_config import YamlConfig
import mock


class TestCHDatabase:
    @mock.patch("cyhy.db.database.db_from_connection")
    def test_stub(self, mock_db_from_connection):
        pass
