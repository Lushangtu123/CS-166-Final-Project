"""Authenticated case APIs. All analysts belong to one shared workspace."""
from dataclasses import dataclass, field
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from case_store import CaseStore, CaseConflict, CaseInvalid, CaseNotFound, RISKS, STATUSES
from case_cloud import UpstashCaseStore, CaseUnavailable
from visual_evidence import VisualRequest


@dataclass
class CaseService:
    store: object
    analysts: dict = field(repr=False)


def build_case_service(env):
    enabled = env.get('CASE_MANAGEMENT_ENABLED', 'false').lower()
    if enabled not in {'true', 'false'}:
        raise ValueError('CASE_MANAGEMENT_ENABLED must be true or false')
    if enabled == 'false':
        return None
    try:
        analysts = json.loads(env.get('CASE_ANALYST_TOKEN_HASHES', '{}'))
        if not isinstance(analysts, dict) or not 1 <= len(analysts) <= 50:
            raise ValueError()
        if any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', actor)
               or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
               for actor, digest in analysts.items()):
            raise ValueError()
        if len(set(analysts.values())) != len(analysts):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Configure 1–50 unique analyst IDs with distinct SHA-256 token hashes') from None
    backend = env.get('CASE_STORE', 'sqlite')
    if backend == 'upstash':
        store = UpstashCaseStore(env.get('CASE_REDIS_REST_URL') or env.get('UPSTASH_REDIS_REST_URL', ''),
                                 env.get('CASE_REDIS_REST_TOKEN') or env.get('UPSTASH_REDIS_REST_TOKEN', ''),
                                 env.get('CASE_WORKSPACE', ''))
    elif backend == 'sqlite':
        path = Path(env.get('CASE_DB_PATH', ''))
        if env.get('VERCEL') or not path.is_absolute() or (Path(__file__).parent / 'static') in path.resolve().parents:
            raise ValueError('SQLite cases require an absolute private path on a persistent host; Vercel requires Upstash')
        store = CaseStore(path)
    else:
        raise ValueError('CASE_STORE must be sqlite or upstash')
    return CaseService(store, analysts)


class CaseInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject: str = Field(default='', max_length=500)
    body: str = Field(default='', max_length=50000)
    raw_email: str = Field(default='', max_length=60000)


class CaseReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_version: int = Field(ge=1, strict=True)
    status: str
    verdict: str | None = None
    note: str = Field(default='', max_length=4000)


def make_case_router(analyze):
    router = APIRouter(prefix='/api/cases')

    def identity(request: Request):
        if getattr(request.app.state, 'case_configuration_error', False):
            raise HTTPException(503, 'Case configuration is invalid; contact the administrator')
        service = getattr(request.app.state, 'case_service', None)
        if service is None:
            raise HTTPException(404, 'Case management is not configured')
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer ') or not 32 <= len(auth[7:]) <= 256:
            raise HTTPException(401, 'A valid analyst access token is required', headers={'WWW-Authenticate': 'Bearer'})
        digest = hashlib.sha256(auth[7:].encode()).hexdigest()
        actor = None
        for candidate, expected in service.analysts.items():
            if hmac.compare_digest(digest, expected):
                actor = candidate
        if actor is None:
            raise HTTPException(401, 'A valid analyst access token is required')
        return service.store, actor

    async def call(fn, *args, **kwargs):
        try:
            return await run_in_threadpool(fn, *args, **kwargs)
        except CaseNotFound as exc:
            raise HTTPException(404, str(exc)) from None
        except CaseConflict as exc:
            raise HTTPException(409, str(exc)) from None
        except CaseInvalid as exc:
            raise HTTPException(422, str(exc)) from None
        except (CaseUnavailable, sqlite3.Error, OSError):
            raise HTTPException(503, 'Case storage is unavailable. Reload to check whether your last operation completed.') from None

    @router.get('/me')
    async def me(access=Depends(identity)):
        return {'actor': access[1]}

    @router.get('')
    async def listing(status: str | None = None, risk: str | None = None,
                      created_from: date | None = None, created_to: date | None = None,
                      limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
                      access=Depends(identity)):
        if status is not None and status not in STATUSES or risk is not None and risk not in RISKS:
            raise HTTPException(422, 'Invalid status or risk filter')
        if created_from and created_to and created_from > created_to:
            raise HTTPException(422, 'Start date must not be after end date')
        return await call(access[0].list, status=status, risk=risk, limit=limit, offset=offset,
                          created_from=created_from.isoformat() if created_from else None,
                          created_to=created_to.isoformat() if created_to else None)

    async def create(request, access, payload, raw):
        key = request.headers.get('idempotency-key', '')
        try:
            key = str(UUID(key))
        except ValueError:
            raise HTTPException(422, 'A UUID Idempotency-Key header is required') from None
        content = b'eml\0' + raw if raw is not None else b'json\0' + json.dumps(payload.model_dump(), sort_keys=True).encode()
        digest = hashlib.sha256(content).hexdigest()
        store, actor = access
        prior = await call(store.existing, actor, key, digest)
        if prior is not None:
            return prior
        source, analysis, provenance = await analyze(payload, raw)
        return await call(store.create, actor=actor, request_key=key, input_sha256=digest,
                          source=source, analysis=analysis, provenance=provenance)

    @router.post('', status_code=201)
    async def create_json(request: Request, payload: CaseInput, access=Depends(identity)):
        return await create(request, access, payload, None)

    @router.post('/eml', status_code=201)
    async def create_eml(request: Request, access=Depends(identity)):
        if request.headers.get('content-type', '').split(';', 1)[0].lower() not in {'message/rfc822', 'application/octet-stream'}:
            raise HTTPException(415, 'Upload original .eml bytes as message/rfc822')
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > 60000:
                raise HTTPException(413, 'Email file exceeds the 60,000-byte limit')
            raw.extend(chunk)
        if not raw.strip():
            raise HTTPException(400, 'Email file is empty')
        return await create(request, access, CaseInput(), bytes(raw))

    @router.post('/visual', status_code=201)
    async def create_visual(request: Request, payload: VisualRequest, access=Depends(identity)):
        return await create(request, access, payload, None)

    @router.get('/{case_id}')
    async def get(case_id: str, access=Depends(identity)):
        return await call(access[0].get, case_id)

    @router.patch('/{case_id}')
    async def update(case_id: str, payload: CaseReview, access=Depends(identity)):
        return await call(access[0].update, case_id, actor=access[1], **payload.model_dump())

    return router
