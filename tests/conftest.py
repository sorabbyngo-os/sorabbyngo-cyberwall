"""
Pytest configuration for Sorabbyngo Cyberwall tests.
"""
import asyncio
import pytest


@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


# pytest-asyncio >= 0.23 uses asyncio_mode = auto in pytest.ini
# No manual event_loop fixture needed — handled by pytest-asyncio
