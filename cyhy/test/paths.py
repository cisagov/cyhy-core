"""Helpers for locating test input files.

Test input files are referenced relative to this directory rather than the
current working directory so that the test suite can be run from anywhere,
e.g. both `pytest` at the repository root and `pytest .` in this directory.
"""

import os

# Absolute path to the directory holding this module.
TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# Absolute path to the directory holding the test input files.
INPUTS_DIR = os.path.join(TEST_DIR, "inputs")

# Absolute path to the root of the repository.
REPO_ROOT = os.path.dirname(os.path.dirname(TEST_DIR))

# Absolute path to the Docker composition that provides MongoDB for the tests.
COMPOSE_FILE = os.path.join(REPO_ROOT, "docker-compose.yml")


def input_path(*parts):
    """Return the absolute path to a test input file.

    For example, input_path("test_all.yml") returns the absolute path to
    cyhy/test/inputs/test_all.yml.
    """
    return os.path.join(INPUTS_DIR, *parts)
