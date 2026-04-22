"""
Tests — EventBus + ThreatEvent
"""
import asyncio
import pytest
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel


@pytest.fixture
def bus():
    return EventBus()


def test_threat_event_to_dict():
    evt = ThreatEvent(
        source="test",
        threat_type="port_scan",
        level=ThreatLevel.HIGH,
        score=7.0,
        description="Test event",
        data={"src_ip": "1.2.3.4"},
    )
    d = evt.to_dict()
    assert d["source"]      == "test"
    assert d["threat_type"] == "port_scan"
    assert d["level"]       == "HIGH"
    assert d["score"]       == 7.0
    assert d["data"]["src_ip"] == "1.2.3.4"
    assert "timestamp" in d


def test_threat_levels_ordered():
    assert ThreatLevel.INFO     < ThreatLevel.LOW
    assert ThreatLevel.LOW      < ThreatLevel.MEDIUM
    assert ThreatLevel.MEDIUM   < ThreatLevel.HIGH
    assert ThreatLevel.HIGH     < ThreatLevel.CRITICAL


@pytest.mark.asyncio
async def test_event_bus_subscribe_and_receive():
    bus    = EventBus()
    received = []

    async def handler(event: ThreatEvent):
        received.append(event)

    bus.subscribe("port_scan", handler)

    evt = ThreatEvent(
        source="firewall", threat_type="port_scan",
        level=ThreatLevel.HIGH, score=7.0,
        description="Test port scan",
    )
    await bus.publish(evt)

    # Run bus briefly
    task = asyncio.create_task(bus.run())
    await asyncio.sleep(0.1)
    bus.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len(received) == 1
    assert received[0].threat_type == "port_scan"


@pytest.mark.asyncio
async def test_event_bus_wildcard_subscriber():
    bus      = EventBus()
    received = []

    async def catch_all(event: ThreatEvent):
        received.append(event)

    bus.subscribe("*", catch_all)

    for threat_type in ["port_scan", "malware_detected", "syn_flood"]:
        await bus.publish(ThreatEvent(
            source="test", threat_type=threat_type,
            level=ThreatLevel.MEDIUM, score=5.0,
            description=f"Test {threat_type}",
        ))

    task = asyncio.create_task(bus.run())
    await asyncio.sleep(0.1)
    bus.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len(received) == 3


@pytest.mark.asyncio
async def test_event_bus_multiple_handlers():
    bus   = EventBus()
    log_a = []
    log_b = []

    async def handler_a(e): log_a.append(e)
    async def handler_b(e): log_b.append(e)

    bus.subscribe("port_scan", handler_a)
    bus.subscribe("port_scan", handler_b)

    await bus.publish(ThreatEvent(
        source="test", threat_type="port_scan",
        level=ThreatLevel.HIGH, score=7.0,
        description="Multi-handler test",
    ))

    task = asyncio.create_task(bus.run())
    await asyncio.sleep(0.1)
    bus.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len(log_a) == 1
    assert len(log_b) == 1
