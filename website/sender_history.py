"""Privacy-preserving sender observation history for optional Upstash storage."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import time
from typing import Callable
from urllib.request import HTTPRedirectHandler, Request, build_opener

from config import Settings


HISTORY_SCOPE = "this_service_history"
MAX_RETAINED_SEEN_COUNT = 1_000_000
_ALIAS_TAG_RE = re.compile(r"[a-z0-9._%+\-]+", re.IGNORECASE)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Keep the bearer token on the validated Upstash origin."""

    def redirect_request(self, *_args, **_kwargs):
        return None

_OBSERVE_SCRIPT = """
local created = 0
local now = tonumber(ARGV[1])
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1], 'first_seen', now, 'last_seen', now, 'seen_count', 1)
  created = 1
else
  local first_seen = tonumber(redis.call('HGET', KEYS[1], 'first_seen')) or now
  local last_seen = tonumber(redis.call('HGET', KEYS[1], 'last_seen')) or now
  redis.call('HSET', KEYS[1],
    'first_seen', math.min(first_seen, now),
    'last_seen', math.max(last_seen, now))
  redis.call('HINCRBY', KEYS[1], 'seen_count', 1)
end
redis.call('EXPIRE', KEYS[1], ARGV[2])
local values = redis.call('HMGET', KEYS[1], 'first_seen', 'last_seen', 'seen_count')
return {created, values[1], values[2], values[3]}
""".strip()

_RATE_LIMIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
""".strip()


@dataclass(frozen=True)
class SenderHistoryResult:
    status: str
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    seen_count: int | None = None
    scope: str = HISTORY_SCOPE
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "sender_history_status": self.status,
            "sender_history_scope": self.scope,
        }


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after: int = 0


def canonicalize_sender_address(address: str) -> str:
    """Apply the sender detector's alias rules without retaining the original."""
    normalized = (address or "").strip().lower()
    if normalized.count("@") != 1:
        return normalized
    local, domain = normalized.rsplit("@", 1)
    base, separator, tag = local.partition("+")
    if separator and base and tag and _ALIAS_TAG_RE.fullmatch(tag):
        local = base
    if domain == "gmail.com":
        local = local.replace(".", "")
    return f"{local}@{domain}"


def sender_history_key(address: str, secret: str) -> str:
    canonical = canonicalize_sender_address(address)
    digest = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return f"sender-history:v1:{digest}"


def _rate_limit_key(identity: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), identity.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return f"rate-limit:v1:{digest}"


def _iso_timestamp(value: object) -> str:
    timestamp = int(value)
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _available_result(status: str, values: list[object]) -> SenderHistoryResult:
    first_seen, last_seen, count = values
    first_timestamp = int(first_seen)
    last_timestamp = int(last_seen)
    raw_count = int(count)
    if first_timestamp > last_timestamp or raw_count < 1:
        raise ValueError("Invalid sender-history record")
    bounded_count = min(raw_count, MAX_RETAINED_SEEN_COUNT)
    return SenderHistoryResult(
        status=status,
        first_seen_at=_iso_timestamp(first_timestamp),
        last_seen_at=_iso_timestamp(last_timestamp),
        seen_count=bounded_count,
    )


class DisabledSenderHistoryStore:
    def __init__(self, status: str = "disabled") -> None:
        self._status = status

    async def lookup(self, _address: str) -> SenderHistoryResult:
        return SenderHistoryResult(status=self._status)

    async def observe(self, _address: str) -> SenderHistoryResult:
        return SenderHistoryResult(status=self._status)

    async def check_rate_limit(
        self, _identity: str, *, limit: int, window_seconds: int,
    ) -> RateLimitDecision | None:
        return None


class UpstashSenderHistoryStore:
    def __init__(
        self,
        settings: Settings,
        *,
        opener: Callable | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not settings.sender_history_ready:
            raise ValueError("Sender history is not configured")
        self._url = f"{settings.sender_history_rest_url}/pipeline"
        self._token = settings.sender_history_rest_token or ""
        self._secret = settings.sender_history_hmac_key or ""
        self._ttl_seconds = settings.sender_history_retention_days * 86400
        self._timeout = settings.sender_history_timeout_seconds
        self._opener = opener or build_opener(_NoRedirectHandler()).open
        self._clock = clock

    def _execute(self, commands: list[list[object]]) -> object:
        request = Request(
            self._url,
            data=json.dumps(commands, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self._opener(request, timeout=self._timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if (
            not isinstance(payload, list)
            or len(payload) != 1
            or not isinstance(payload[0], dict)
            or "error" in payload[0]
            or "result" not in payload[0]
        ):
            raise ValueError("Invalid sender-history response")
        return payload[0]["result"]

    async def lookup(self, address: str) -> SenderHistoryResult:
        key = sender_history_key(address, self._secret)
        try:
            values = await asyncio.to_thread(
                self._execute,
                [["HMGET", key, "first_seen", "last_seen", "seen_count"]],
            )
            if values == [None, None, None]:
                return SenderHistoryResult(status="not_seen")
            if not isinstance(values, list) or len(values) != 3:
                raise ValueError("Invalid sender-history values")
            return _available_result("previously_seen", values)
        except Exception:
            return SenderHistoryResult(
                status="unavailable",
                error="Sender history is temporarily unavailable.",
            )

    async def observe(self, address: str) -> SenderHistoryResult:
        key = sender_history_key(address, self._secret)
        now = int(self._clock())
        try:
            values = await asyncio.to_thread(
                self._execute,
                [["EVAL", _OBSERVE_SCRIPT, "1", key, now, self._ttl_seconds]],
            )
            if not isinstance(values, list) or len(values) != 4:
                raise ValueError("Invalid sender-history values")
            created, first_seen, last_seen, count = values
            return _available_result(
                "first_seen" if int(created) == 1 else "previously_seen",
                [first_seen, last_seen, count],
            )
        except Exception:
            return SenderHistoryResult(
                status="unavailable",
                error="Sender history is temporarily unavailable.",
            )

    async def check_rate_limit(
        self, identity: str, *, limit: int, window_seconds: int,
    ) -> RateLimitDecision | None:
        key = _rate_limit_key(identity, self._secret)
        try:
            values = await asyncio.to_thread(
                self._execute,
                [[
                    "EVAL", _RATE_LIMIT_SCRIPT, "1", key,
                    str(limit), str(window_seconds),
                ]],
            )
            if not isinstance(values, list) or len(values) != 2:
                raise ValueError("Invalid distributed rate-limit response")
            count, ttl = (int(value) for value in values)
            if count < 1 or ttl < 0:
                raise ValueError("Invalid distributed rate-limit values")
            if count <= limit:
                return RateLimitDecision(allowed=True)
            return RateLimitDecision(allowed=False, retry_after=max(1, ttl))
        except Exception:
            return None


def build_sender_history_store(settings: Settings):
    if not settings.sender_history_ready:
        status = "unavailable" if settings.sender_history_config_error else "disabled"
        return DisabledSenderHistoryStore(status=status)
    return UpstashSenderHistoryStore(settings)
