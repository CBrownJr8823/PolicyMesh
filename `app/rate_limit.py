import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.config import settings

RATE_BUCKETS: dict[str, deque] = defaultdict(deque)


def check_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60
    bucket = RATE_BUCKETS[client_ip]

    while bucket and bucket[0] < window_start:
        bucket.popleft()

    if len(bucket) >= settings.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

    bucket.append(now)
