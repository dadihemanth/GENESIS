from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str) -> None:
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)
        logger.info("WebSocket connected for session %s", session_id)

    async def disconnect(self, websocket: WebSocket, session_id: str) -> None:
        connections = self.active_connections.get(session_id, [])
        if websocket in connections:
            connections.remove(websocket)
        if not connections:
            self.active_connections.pop(session_id, None)
        logger.info("WebSocket disconnected for session %s", session_id)

    async def broadcast(self, session_id: str, message: Dict[str, Any]) -> None:
        connections = self.active_connections.get(session_id, [])
        dead: List[WebSocket] = []
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws, session_id)

    async def listen_redis(self, websocket: WebSocket, session_id: str) -> None:
        from app.database.redis_client import create_session_subscriber

        pubsub = await create_session_subscriber(session_id)
        try:
            async for raw_message in pubsub.listen():
                if raw_message is None:
                    continue
                if raw_message.get("type") != "message":
                    continue
                data = raw_message.get("data", "")
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                try:
                    parsed = json.loads(data)
                except (json.JSONDecodeError, TypeError):
                    parsed = {"raw": str(data)}
                try:
                    await websocket.send_json(parsed)
                except Exception:
                    # Client disconnected
                    break
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Redis listener error for session %s: %s", session_id, exc)
        finally:
            try:
                await pubsub.unsubscribe(f"session:{session_id}")
                await pubsub.close()
            except Exception:
                pass


manager = WebSocketManager()
