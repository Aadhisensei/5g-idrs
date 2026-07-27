"""
Thin Redis Streams helper shared by every parser and the NWDAF service.

All parsers write to the same stream: ids:events
The NAS parser additionally reads from: nas:raw (fed by the NGAP parser,
since NAS-5GS messages are transported *inside* NGAP PDUs and have no
IP-layer existence of their own).
"""
import os
import redis

from .events import IDRSEvent

EVENTS_STREAM = "ids:events"
NAS_RAW_STREAM = "nas:raw"


def get_redis() -> redis.Redis:
    host = os.environ.get("REDIS_HOST", "127.0.0.1")
    port = int(os.environ.get("REDIS_PORT", 6379))
    return redis.Redis(host=host, port=port, decode_responses=True)


def publish_event(r: redis.Redis, event: IDRSEvent, stream: str = EVENTS_STREAM) -> None:
    r.xadd(stream, {"data": event.to_json()})


def read_stream(r: redis.Redis, stream: str, last_id: str = "$", block_ms: int = 5000, count: int = 50):
    """Blocking read helper. Pass last_id='0' to read from the beginning."""
    resp = r.xread({stream: last_id}, block=block_ms, count=count)
    return resp
