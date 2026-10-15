"""Read sanitized counters from the local dashboard, without sending commands."""
import asyncio
import json
import urllib.request
import websockets

FIELDS = ["record_kind", "packet_rate", "byte_rate", "captured_packets", "published", "dropped", "failed", "timestamp"]

async def inspect() -> None:
    with urllib.request.urlopen("http://127.0.0.1:8000/api/history?limit=2", timeout=3) as response:
        print("history", [{key: row.get(key) for key in FIELDS} for row in json.load(response)])
    async with websockets.connect("ws://127.0.0.1:8000/ws/telemetry", open_timeout=3) as socket:
        for _ in range(5):
            data = json.loads(await asyncio.wait_for(socket.recv(), 3))
            window = data.get("latest_traffic_window") or (data.get("data") if data.get("type") == "TRAFFIC_WINDOW_UPDATE" else None)
            if window:
                print("window", {key: window.get(key) for key in FIELDS})

if __name__ == "__main__":
    asyncio.run(inspect())
