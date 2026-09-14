from typing import List, Dict, Any
from fastapi import WebSocket
from datetime import datetime, timezone
from app.core.logger import logger

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active: {len(self.active_connections)}")
        
        # Send welcome heartbeat
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to SENTINEL-X Real-Time Security Telemetry Stream"
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error sending message to websocket: {e}")
                dead_connections.append(connection)
        
        for dead in dead_connections:
            self.disconnect(dead)

    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        await self.broadcast({
            "type": "NEW_ALERT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": alert_data
        })

    async def broadcast_scan_update(self, progress: int, status: str, details: Dict[str, Any]):
        await self.broadcast({
            "type": "SCAN_PROGRESS",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "progress": progress,
            "status": status,
            "details": details
        })

    async def broadcast_asset_update(self, asset_data: Dict[str, Any]):
        await self.broadcast({
            "type": "ASSET_UPDATED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": asset_data
        })

ws_manager = WebSocketManager()
