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
from typing import Awaitable, Callable
from pathlib import Path
import re

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response, HTMLResponse

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dashboard.backend.config import WEB_PORT, FRONTEND_DIR
from dashboard.backend.assets import DashboardAssets
from dashboard.backend.mqtt_bridge import start_mqtt_bridge, stop_mqtt_bridge
from dashboard.backend.routers.api import router as api_router
from dashboard.backend.routers.ws import router as ws_router
from dashboard.backend.experiment_runtime import start_runtime, stop_runtime


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Khởi động MQTT Bridge trong event loop
    loop = asyncio.get_running_loop()
    start_mqtt_bridge(loop)
    start_runtime(loop)
    try:
        yield
    finally:
        await stop_runtime()
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


@app.middleware("http")
async def revalidate_dashboard_assets(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Revalidate mutable dashboard modules after local source updates."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        if "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-cache"
    return response

# Phục vụ Static Files cho Frontend
if os.path.exists(FRONTEND_DIR):
    dashboard_assets = DashboardAssets(directory=FRONTEND_DIR)
    app.mount("/static", dashboard_assets, name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    fav_svg = os.path.join(FRONTEND_DIR, "favicon.svg")
    if os.path.exists(fav_svg):
        return FileResponse(fav_svg, media_type="image/svg+xml")
    fav_ico = os.path.join(FRONTEND_DIR, "favicon.ico")
    if os.path.exists(fav_ico):
        return FileResponse(fav_ico, media_type="image/x-icon")
    return Response(status_code=204)


@app.get("/favicon.svg", include_in_schema=False)
async def serve_favicon_svg():
    fav_svg = os.path.join(FRONTEND_DIR, "favicon.svg")
    if os.path.exists(fav_svg):
        return FileResponse(fav_svg, media_type="image/svg+xml")
    return Response(status_code=204)


@app.get("/")
async def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        source = await asyncio.to_thread(Path(index_file).read_text, encoding="utf-8")
        source = re.sub(r'/static/js/main\.js(?:\?v=[^"\s]*)?',
                        f'/static/js/main.js?v={dashboard_assets.revision}', source)
        return HTMLResponse(source, headers={"Cache-Control": "no-store"})
    return {"message": "Frontend index.html not found"}


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    main()
