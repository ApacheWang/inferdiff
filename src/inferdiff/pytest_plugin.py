"""Opt-in pytest fixtures for the inferdiff assertions.

Set ``pytest_plugins = ["inferdiff.pytest_plugin"]`` in your conftest.py to
use the ``assert_sse_honest`` and ``assert_endpoint_honest`` fixtures.
"""

from .testing import assert_endpoint_honest, assert_sse_honest


def pytest_configure(config):
    import pytest

    class Assertions:
        @pytest.fixture
        def assert_sse_honest(self):
            return assert_sse_honest

        @pytest.fixture
        def assert_endpoint_honest(self):
            return assert_endpoint_honest

    config.pluginmanager.register(Assertions(), "inferdiff-assertions")
