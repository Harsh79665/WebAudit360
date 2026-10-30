"""WebAudit 360 — Real-Time WebSocket Progress Gateway
Author: Harsh Patel
"""

import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.core.logging import logger
from backend.app.services.audit_service import AUDIT_EVENT_SUBSCRIBERS

router = APIRouter(tags=["WebSockets"])


@router.websocket("/ws/audits/{audit_id}")
async def audit_progress_websocket(websocket: WebSocket, audit_id: int):
    """
    Subscribes a connected client to live progress events for the specified audit job.
    Streams genuine worker events without artificial delays or timer-based percentages.
    """
    await websocket.accept()
    queue = asyncio.Queue()

    if audit_id not in AUDIT_EVENT_SUBSCRIBERS:
        AUDIT_EVENT_SUBSCRIBERS[audit_id] = []
    AUDIT_EVENT_SUBSCRIBERS[audit_id].append(queue)

    logger.info(f"WebSocket client connected to audit #{audit_id} stream.")

    try:
        # Send initial confirmation event
        await websocket.send_json({
            "type": "connection_established",
            "audit_id": audit_id,
            "message": "Connected to WebAudit 360 live diagnostic event stream."
        })

        while True:
            # Wait for event from worker pipeline or client message
            event = await queue.get()
            await websocket.send_json(event)

            # If audit completed or failed, close gracefully
            if event.get("type") in ("audit_completed", "audit_failed", "audit_cancelled"):
                await asyncio.sleep(0.5)
                break

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from audit #{audit_id}.")
    except Exception as e:
        logger.error(f"WebSocket error on audit #{audit_id}: {e}")
    finally:
        if audit_id in AUDIT_EVENT_SUBSCRIBERS:
            try:
                AUDIT_EVENT_SUBSCRIBERS[audit_id].remove(queue)
                if not AUDIT_EVENT_SUBSCRIBERS[audit_id]:
                    del AUDIT_EVENT_SUBSCRIBERS[audit_id]
            except ValueError:
                pass
        try:
            await websocket.close()
        except Exception:
            pass

