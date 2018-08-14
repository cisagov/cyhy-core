#!/usr/bin/env py.test -v

import pytest
from yaml import YAMLError
from cyhy.core.yaml_config import YamlConfig

class TestYamlConfig:

    @pytest.fixture
    def yc(self):
        return YamlConfig('inputs/test_all.yml')

    @pytest.fixture
    def sample_config(self):
        return {
            'version': '1',
            'redis': {
                'local': {
                    'uri': 'redis://localhost:6379/'
                },
                'example-section-name': {
                    'uri': 'redis://:password@localhost:6379/'
                },
                'default': {
                    'uri': 'redis://localhost:6379/'
                }
            },
            'mongo': {
                'local': {
                    'name': 'localuser',
                    'uri': 'mongodb://dbuser:dbpass@localhost:27017/local'
                },
                'example-mongo': {
                    'name': 'example',
                    'uri': 'mongodb://localhost:27017/all'
                },
                'default': {
                    'name': 'localuser',
                    'uri': 'mongodb://dbuser:dbpass@localhost:27017/local'
                }
            },
            'core': {
                'setting': 'ABCdef123'
            }
        }

    def test_no_filename_given(self):
        with pytest.raises(ValueError):
            yc = YamlConfig()

    def test_filename_wrong_type(self):
        with pytest.raises(ValueError):
            yc = YamlConfig(15)

    def test_load_config_non_existent_file(self):
        with pytest.raises(IOError):
            yc = YamlConfig('i_dont_exist.yml')

    def test_load_config_non_yaml_file(self):
        with pytest.raises(YAMLError):
            yc = YamlConfig('inputs/test-fullscan.xml')

    def test_load_config_corrupt_yaml_file(self):
        with pytest.raises(YAMLError):
            yc = YamlConfig('inputs/corrupt_yaml.yml')

    def test_load_config_no_cyhy_version(self):
        with pytest.raises(KeyError):
            yc = YamlConfig('inputs/no_version.yml')

    def test_load_config_wrong_cyhy_version(self):
        with pytest.raises(ValueError):
            yc = YamlConfig('inputs/bad_version.yml')

    def test_load_proper_config(self, sample_config):
        yc = YamlConfig('inputs/test_all.yml')
        assert isinstance(yc, YamlConfig)
        assert yc.config == sample_config

    def test_get_no_parameter(self, yc):
        with pytest.raises(ValueError):
            yc.get()

    def test_get_non_string(self, yc):
        with pytest.raises(ValueError):
            yc.get(15)

    def test_get_non_existent_key(self, yc):
        with pytest.raises(KeyError):
            yc.get_service('not_exist')

    def test_get_value(self, yc, sample_config):
        assert yc.get(YamlConfig.VERSION) == sample_config[YamlConfig.VERSION]

    def test_get_object(self, yc, sample_config):
        assert yc.get(YamlConfig.REDIS) == sample_config[YamlConfig.REDIS]

    def test_get_service_no_parameters(self, yc):
        with pytest.raises(ValueError):
            yc.get_service()

    def test_get_service_non_string(self, yc):
        with pytest.raises(ValueError):
            yc.get_service(4)

    def test_get_service_non_existent(self, yc):
        with pytest.raises(KeyError):
            yc.get_service('bad-service')

    def test_get_service_no_section(self, yc, sample_config):
        assert (yc.get_service(YamlConfig.REDIS)
                == sample_config[YamlConfig.REDIS]['default'])

    def test_get_service_section_non_string(self, yc):
        with pytest.raises(ValueError):
            yc.get_service(YamlConfig.REDIS, 4)

    def test_get_service_section_non_existent(self, yc):
        with pytest.raises(KeyError):
            yc.get_service(YamlConfig.REDIS, 'bad-section')

    def test_get_section_value(self, yc, sample_config):
        assert (yc.get_service(YamlConfig.CORE, 'setting')
               == sample_config[YamlConfig.CORE]['setting'])

    def test_get_section_object(self, yc, sample_config):
        assert (yc.get_service(YamlConfig.MONGO, 'example-mongo')
               == sample_config[YamlConfig.MONGO]['example-mongo'])
