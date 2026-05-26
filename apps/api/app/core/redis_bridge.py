"""Redis pub/sub → WebSocket bridge.

Celery workers publish agent events to Redis on:
  ``engagement:{engagement_id}:events``

This background task subscribes to that pattern and forwards every
message to the matching WebSocket clients via ``ws_manager.broadcast()``.

Runs as a background ``asyncio.Task`` — restarts automatically if the
Redis connection is lost.
"""

from __future__ import annotations

import asyncio
import json
import os

import redis.asyncio as aioredis

from app.ws.manager import ws_manager


async def start_redis_bridge() -> None:
    """Entry point — call once at API startup via ``asyncio.create_task()``.

    Loops forever with auto-reconnect on Redis failure.
    Exits cleanly when the task is cancelled (shutdown).
    """
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

    while True:
        r: aioredis.Redis | None = None
        try:
            r = aioredis.from_url(redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.psubscribe("engagement:*:events")

            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue

                # channel format: "engagement:{engagement_id}:events"
                channel: str = message["channel"]
                parts = channel.split(":")
                if len(parts) < 3:
                    continue
                engagement_id = parts[1]

                try:
                    event = json.loads(message["data"])
                    await ws_manager.broadcast(engagement_id, event)
                except (json.JSONDecodeError, Exception):
                    pass

        except asyncio.CancelledError:
            # Shutdown requested — exit cleanly
            break
        except Exception:
            # Redis disconnected — wait 3 s then reconnect
            await asyncio.sleep(3)
        finally:
            if r is not None:
                try:
                    await r.aclose()
                except Exception:
                    pass
