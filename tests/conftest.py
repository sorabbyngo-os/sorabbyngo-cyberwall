"""
Pytest configuration for Sorabbyngo Cyberwall tests.
"""
import asyncio
import pytest


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
