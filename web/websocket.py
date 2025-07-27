"""
WebSocket Manager for DriftBuddy Web Interface
Provides real-time updates for scan progress, notifications, and chat
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from .database import get_db
from .models import Finding, Scan, User


class ConnectionManager:
    """Manages WebSocket connections and broadcasts"""

    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}  # user_id -> connections
        self.scan_connections: Dict[int, List[WebSocket]] = {}  # scan_id -> connections
        self.broadcast_connections: List[WebSocket] = []  # broadcast connections

    async def connect(self, websocket: WebSocket, user_id: Optional[int] = None):
        """Connect a new WebSocket"""
        await websocket.accept()

        if user_id:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
        else:
            self.broadcast_connections.append(websocket)

    def disconnect(self, websocket: WebSocket, user_id: Optional[int] = None):
        """Disconnect a WebSocket"""
        if user_id and user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
        else:
            if websocket in self.broadcast_connections:
                self.broadcast_connections.remove(websocket)

    async def send_personal_message(self, message: str, user_id: int):
        """Send message to specific user"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_text(message)
                except:
                    # Remove broken connection
                    self.active_connections[user_id].remove(connection)

    async def send_scan_update(self, scan_id: int, message: str):
        """Send scan update to all connections monitoring this scan"""
        if scan_id in self.scan_connections:
            for connection in self.scan_connections[scan_id]:
                try:
                    await connection.send_text(message)
                except:
                    # Remove broken connection
                    self.scan_connections[scan_id].remove(connection)

    async def broadcast(self, message: str):
        """Broadcast message to all connections"""
        for connection in self.broadcast_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove broken connection
                self.broadcast_connections.remove(connection)

    def subscribe_to_scan(self, websocket: WebSocket, scan_id: int):
        """Subscribe to scan updates"""
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = []
        self.scan_connections[scan_id].append(websocket)

    def unsubscribe_from_scan(self, websocket: WebSocket, scan_id: int):
        """Unsubscribe from scan updates"""
        if scan_id in self.scan_connections:
            if websocket in self.scan_connections[scan_id]:
                self.scan_connections[scan_id].remove(websocket)
                if not self.scan_connections[scan_id]:
                    del self.scan_connections[scan_id]


class WebSocketService:
    """WebSocket service for real-time features"""

    def __init__(self):
        self.manager = ConnectionManager()

    async def handle_websocket(self, websocket: WebSocket, user_id: Optional[int] = None, scan_id: Optional[int] = None):
        """Handle WebSocket connection"""
        await self.manager.connect(websocket, user_id)

        if scan_id:
            self.manager.subscribe_to_scan(websocket, scan_id)

        try:
            while True:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)

                # Handle different message types
                await self._handle_message(message, websocket, user_id)

        except WebSocketDisconnect:
            self.manager.disconnect(websocket, user_id)
            if scan_id:
                self.manager.unsubscribe_from_scan(websocket, scan_id)

    async def _handle_message(self, message: Dict[str, Any], websocket: WebSocket, user_id: Optional[int]):
        """Handle incoming WebSocket message"""
        message_type = message.get("type")

        if message_type == "ping":
            await websocket.send_text(json.dumps({"type": "pong", "timestamp": datetime.utcnow().isoformat()}))

        elif message_type == "subscribe_scan":
            scan_id = message.get("scan_id")
            if scan_id:
                self.manager.subscribe_to_scan(websocket, scan_id)
                await websocket.send_text(json.dumps({"type": "subscribed", "scan_id": scan_id, "message": f"Subscribed to scan {scan_id} updates"}))

        elif message_type == "unsubscribe_scan":
            scan_id = message.get("scan_id")
            if scan_id:
                self.manager.unsubscribe_from_scan(websocket, scan_id)
                await websocket.send_text(json.dumps({"type": "unsubscribed", "scan_id": scan_id, "message": f"Unsubscribed from scan {scan_id} updates"}))

        elif message_type == "chat_message":
            # Handle chat messages
            await self._handle_chat_message(message, websocket, user_id)

    async def _handle_chat_message(self, message: Dict[str, Any], websocket: WebSocket, user_id: Optional[int]):
        """Handle chat message"""
        from .ai_chat import AIChatService

        chat_service = AIChatService()
        db = next(get_db())

        try:
            # Process chat message
            result = await chat_service.process_chat_message(
                db=db, user_id=user_id, message=message.get("content", ""), scan_id=message.get("scan_id"), context=message.get("context")
            )

            # Send response back to client
            response = {
                "type": "chat_response",
                "success": result.get("success", False),
                "content": result.get("response", "Sorry, I couldn't process your message."),
                "metadata": result.get("metadata", {}),
                "timestamp": datetime.utcnow().isoformat(),
            }

            await websocket.send_text(json.dumps(response))

        except Exception as e:
            error_response = {"type": "chat_error", "error": str(e), "timestamp": datetime.utcnow().isoformat()}
            await websocket.send_text(json.dumps(error_response))

        finally:
            db.close()

    async def send_scan_progress(self, scan_id: int, status: str, progress: int = 0, message: str = ""):
        """Send scan progress update"""
        update_message = {
            "type": "scan_progress",
            "scan_id": scan_id,
            "status": status,
            "progress": progress,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.manager.send_scan_update(scan_id, json.dumps(update_message))

    async def send_scan_complete(self, scan_id: int, findings_count: int, results: Dict[str, Any]):
        """Send scan completion notification"""
        complete_message = {
            "type": "scan_complete",
            "scan_id": scan_id,
            "findings_count": findings_count,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.manager.send_scan_update(scan_id, json.dumps(complete_message))

    async def send_notification(self, user_id: int, notification_type: str, title: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Send notification to specific user"""
        notification = {
            "type": "notification",
            "notification_type": notification_type,
            "title": title,
            "message": message,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.manager.send_personal_message(json.dumps(notification), user_id)

    async def broadcast_announcement(self, title: str, message: str, announcement_type: str = "info"):
        """Broadcast announcement to all users"""
        announcement = {
            "type": "announcement",
            "title": title,
            "message": message,
            "announcement_type": announcement_type,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.manager.broadcast(json.dumps(announcement))

    async def send_finding_update(self, scan_id: int, finding: Finding):
        """Send finding update"""
        finding_message = {
            "type": "finding_update",
            "scan_id": scan_id,
            "finding": {
                "id": finding.id,
                "query_name": finding.query_name,
                "severity": finding.severity,
                "description": finding.description,
                "risk_score": finding.risk_score,
                "created_at": finding.created_at.isoformat(),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.manager.send_scan_update(scan_id, json.dumps(finding_message))


# Global WebSocket service instance
websocket_service = WebSocketService()
