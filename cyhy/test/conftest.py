"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Standard Python Libraries
import os
import subprocess

# Third-Party Libraries
import pytest

# cisagov Libraries
from paths import COMPOSE_FILE, REPO_ROOT
from testenv import DB_URI_VAR, SKIP_COMPOSE_VAR


def compose(*args):
    """Run a docker compose command against our composition.

    Returns the output of the command.  The project directory is specified
    explicitly rather than left to Docker Compose to infer, so that the project
    name is derived from the root of the repository no matter which directory
    pytest was invoked from.  That keeps this in agreement with the project name
    used when the composition is brought up by hand from the repository root, so
    the two cannot end up managing separate sets of containers.
    """
    command = [
        "docker",
        "compose",
        "--project-directory",
        REPO_ROOT,
        "--file",
        COMPOSE_FILE,
    ] + list(args)
    try:
        return subprocess.check_output(command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        raise RuntimeError(
            '"%s" failed with exit status %d:\n%s'
            % (" ".join(command), err.returncode, err.output)
        )
    except OSError as err:
        raise RuntimeError(
            'Unable to run "%s": %s.\n\nDocker, including the Docker Compose '
            "plugin, is required to run the tests that use MongoDB. "
            "Alternatively, set %s to point at an existing MongoDB instance and "
            "set %s to keep the test suite from managing the composition itself."
            % (" ".join(command), err, DB_URI_VAR, SKIP_COMPOSE_VAR)
        )


@pytest.fixture(scope="session")
def dockerc():
    """Start up the Docker composition, and shut it down when finished.

    This spares developers from having to remember to start MongoDB before
    running the tests.  "--wait" blocks until the MongoDB container reports
    healthy, so the tests cannot race its startup.

    The composition is brought up once per test session rather than once per
    test, since the tests that use it already reset the collections they touch.
    No volumes are configured for the composition, so bringing it down discards
    its data.

    Set the environment variable named by SKIP_COMPOSE_VAR to bypass this
    entirely and use a MongoDB instance managed elsewhere.  Note that when this
    fixture is in charge, it shuts the composition down at the end of the
    session even if the composition was already running beforehand.

    This mirrors the approach used in cisagov/guacscanner, which drives its
    composition with python-on-whales.  That library requires Python 3.8 or
    newer, so it cannot be used here until this project leaves Python 2.7
    behind; docker compose is invoked directly in the meantime.
    """
    if os.environ.get(SKIP_COMPOSE_VAR):
        yield None
        return

    compose("up", "--detach", "--wait")
    yield None
    compose("down")
