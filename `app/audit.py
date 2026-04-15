import json
import os
from datetime import datetime, timezone

from app.config import settings


def write_audit_event(event_type: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(settings.AUDIT_LOG_PATH), exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "payload": payload,
    }
    with open(settings.AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
