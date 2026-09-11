#!/usr/bin/env python3
"""
Edge AI Network Security Dashboard - Backend Server
====================================================
FastAPI + WebSocket + MQTT Bridge
- Khởi tạo ứng dụng FastAPI kết nối MQTT Broker và phát sóng qua WebSocket.
- Cung cấp REST APIs điều khiển simulator và điều chỉnh cấu hình ngưỡng.
- Phục vụ giao diện Web Dashboard tĩnh từ dashboard/frontend/.
"""

import os
import sys
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dashboard.backend.config import WEB_PORT, FRONTEND_DIR
from dashboard.backend.mqtt_bridge import start_mqtt_bridge, stop_mqtt_bridge
from dashboard.backend.routers.api import router as api_router
from dashboard.backend.routers.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Khởi động MQTT Bridge trong event loop
    loop = asyncio.get_running_loop()
    start_mqtt_bridge(loop)
    yield
    stop_mqtt_bridge()


app = FastAPI(
    title="Edge AI Network Anomaly Detection Dashboard",
    description="Real-time telemetry and cybersecurity monitoring on edge",
    version="2.5.0",
    lifespan=lifespan
)

# Gắn kết các Routers
app.include_router(api_router)
app.include_router(ws_router)

# Phục vụ Static Files cho Frontend
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Frontend index.html not found"}


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    main()
