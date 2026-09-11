"""
Dashboard WebSocket Connection Manager
======================================
Quản lý các kết nối WebSocket đang hoạt động và phát sóng dữ liệu đa nhiệm.
"""

import json
from typing import List
from fastapi import WebSocket

from dashboard.backend.state import state


class ConnectionManager:
    """Quản lý danh sách kết nối WebSocket và broadcast dữ liệu thời gian thực."""

    def __init__(self):
        self.active_websockets: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.append(websocket)
        # Gửi payload khởi tạo ngay khi client kết nối
        await websocket.send_text(json.dumps(state.get_initial_payload()))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_websockets:
            self.active_websockets.remove(websocket)

    async def broadcast(self, message: dict):
        msg_str = json.dumps(message)
        disconnected = []
        for ws in self.active_websockets:
            try:
                await ws.send_text(msg_str)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)


# Singleton connection manager instance
manager = ConnectionManager()
