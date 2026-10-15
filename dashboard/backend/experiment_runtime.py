"""Backend-owned Twin worker; updates are applied on the FastAPI event loop."""
import asyncio
import json
import logging
import os
from typing import Any, TYPE_CHECKING

from dashboard.backend.state import state
from dashboard.backend.websocket_manager import manager
from dashboard.backend.mqtt_bridge import mqtt_client

LOG = logging.getLogger(__name__)
if TYPE_CHECKING:
    from digital_twin.experiment_service import TwinExperimentService
service: "TwinExperimentService | None" = None


def start_runtime(loop: asyncio.AbstractEventLoop) -> None:
    global service
    if os.getenv("AERO_PROBE_MODE") == "esp32":
        return
    from digital_twin.experiment_service import TwinExperimentService
    def apply(payload: dict[str, Any]) -> None:
        state.experiment_status = payload
        asyncio.create_task(manager.broadcast({"type": "EXPERIMENT_STATUS_UPDATE", "experiment_status": payload}))
        result = mqtt_client.publish("edge/experiments/status", json.dumps(payload), qos=1, retain=True)
        if result.rc != 0:
            LOG.warning("Twin status MQTT publish unavailable; local API/UI still receive status")
    def notify(payload: dict[str, Any]) -> None:
        if not loop.is_closed():
            loop.call_soon_threadsafe(apply, payload)
    service = TwinExperimentService(notify)


async def stop_runtime() -> None:
    global service
    if service:
        await asyncio.to_thread(service.close)
        service = None
