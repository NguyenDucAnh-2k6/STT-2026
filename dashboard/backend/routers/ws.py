"""
Dashboard WebSocket Router
==========================
Cung cấp kênh truyền phát sóng thời gian thực /ws/telemetry.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from dashboard.backend.websocket_manager import manager

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    """Kênh WebSocket phát sóng telemetry thời gian thực tới frontend."""
    await manager.connect(websocket)
    try:
        while True:
            # Lắng nghe các tin nhắn cấu hình gửi lên từ client (nếu có)
            data_text = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
