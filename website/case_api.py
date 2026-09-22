"""Authenticated case APIs. All analysts belong to one shared workspace."""
from dataclasses import dataclass, field
from datetime import date
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from case_store import CaseStore, CaseConflict, CaseInvalid, CaseNotFound, RISKS, STATUSES
from case_cloud import UpstashCaseStore, CaseUnavailable, feedback_workspace_name
from visual_evidence import VisualRequest
from jev import JevClient, prepare_case_input, configuration as jev_configuration
from jev_control import JevControl, request_identity


@dataclass
class CaseService:
    store: object
    analysts: dict = field(repr=False)
    feedback_store: object | None = field(default=None, repr=False)
    deployment_environment: str = 'local'
    jev_control: object | None = field(default=None, repr=False)


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
        url = env.get('CASE_REDIS_REST_URL') or env.get('UPSTASH_REDIS_REST_URL', '')
        token = env.get('CASE_REDIS_REST_TOKEN') or env.get('UPSTASH_REDIS_REST_TOKEN', '')
        workspace = env.get('CASE_WORKSPACE', '')
        store = UpstashCaseStore(url, token, workspace)
        feedback_workspace = env.get('CASE_FEEDBACK_WORKSPACE') or feedback_workspace_name(workspace)
        feedback_store = UpstashCaseStore(url, token, feedback_workspace)
        if feedback_store.key == store.key:
            raise ValueError('CASE_FEEDBACK_WORKSPACE must differ from CASE_WORKSPACE')
    elif backend == 'sqlite':
        path = Path(env.get('CASE_DB_PATH', ''))
        if env.get('VERCEL') or not path.is_absolute() or (Path(__file__).parent / 'static') in path.resolve().parents:
            raise ValueError('SQLite cases require an absolute private path on a persistent host; Vercel requires Upstash')
        store = CaseStore(path)
        feedback_store = CaseStore(path.with_name(path.stem + '.feedback' + path.suffix))
    else:
        raise ValueError('CASE_STORE must be sqlite or upstash')
    deployment_environment = env.get('VERCEL_ENV', 'local').strip().lower()
    if deployment_environment not in {'production', 'preview', 'development', 'local'}:
        deployment_environment = 'deployment'
    return CaseService(store, analysts, feedback_store, deployment_environment)


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
    feedback_reason: str | None = None
    evidence_basis: str | None = None


class AuxiliaryConsent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    allow_external_processing: bool = Field(strict=True)


def jev_client(request):
    # Web requests must reserve the shared budget before evaluate(). CLI keeps its cap.
    return JevClient.from_env(os.environ, max_calls=None)


def jev_control(service):
    if service.jev_control is None:
        service.jev_control = JevControl(service.store, service.deployment_environment)
    return service.jev_control


def public_jev_status(app):
    config = jev_configuration(os.environ)
    return {'jev_enabled': os.environ.get('PHISHGUARD_JEV_ENABLED') == 'true',
            'jev_configured': (config['status'] == 'available'
                               and getattr(app.state, 'case_service', None) is not None
                               and not getattr(app.state, 'case_configuration_error', False))}


def make_case_router(analyze, *, visible_text, mask_inline_data):
    router = APIRouter(prefix='/api/cases')

    def identity(request: Request):
        if getattr(request.app.state, 'case_configuration_error', False):
            raise HTTPException(503, 'Case configuration is invalid; contact the administrator')
        service = getattr(request.app.state, 'case_service', None)
        if service is None:
            raise HTTPException(404, 'Case management is not configured')
        scope = service.deployment_environment
        detail = f'A valid analyst access token is required for this {scope} deployment.'
        if scope in {'production', 'preview'}:
            detail += ' Production and Preview credentials are separate.'
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer ') or not 32 <= len(auth[7:]) <= 256:
            raise HTTPException(401, detail, headers={'WWW-Authenticate': 'Bearer'})
        digest = hashlib.sha256(auth[7:].encode()).hexdigest()
        actor = None
        for candidate, expected in service.analysts.items():
            if hmac.compare_digest(digest, expected):
                actor = candidate
        if actor is None:
            raise HTTPException(401, detail)
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

    def with_kind(record, kind):
        record['kind'] = kind
        return record

    async def find_record(service, case_id):
        for store, kind in ((service.store, 'case'), (service.feedback_store, 'feedback')):
            if store is None:
                continue
            try:
                return store, with_kind(await call(store.get, case_id), kind)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
        raise HTTPException(404, 'Case not found')

    @router.get('/me')
    async def me(request: Request, access=Depends(identity)):
        config = jev_configuration(os.environ)
        if config['status'] == 'available':
            try:
                control = await run_in_threadpool(jev_control, request.app.state.case_service)
                config.update(await run_in_threadpool(control.snapshot, config['daily_limit']))
                if config['used'] >= config['daily_limit']:
                    config['status'] = 'quota_exhausted'
            except (CaseUnavailable, sqlite3.Error, OSError):
                config['status'] = 'control_unavailable'
        # Quota-exhausted analysts may still retrieve a previously saved receipt.
        return {'actor': access[1], 'jev_available': config['status'] in {'available', 'quota_exhausted'},
                'jev': config}

    @router.get('')
    async def listing(request: Request, status: str | None = None, risk: str | None = None,
                      kind: str = 'all',
                      created_from: date | None = None, created_to: date | None = None,
                      limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
                      access=Depends(identity)):
        if status is not None and status not in STATUSES or risk is not None and risk not in RISKS or kind not in {'all', 'case', 'feedback'}:
            raise HTTPException(422, 'Invalid status, risk, or kind filter')
        if created_from and created_to and created_from > created_to:
            raise HTTPException(422, 'Start date must not be after end date')
        service = request.app.state.case_service
        stores = [('case', service.store), ('feedback', service.feedback_store)]
        items = []
        total = 0
        needed = offset + limit
        for record_kind, store in stores:
            if store is None or kind not in {'all', record_kind}:
                continue
            store_offset = 0
            while True:
                page = await call(store.list, status=status, risk=risk,
                                  limit=min(100, needed - store_offset), offset=store_offset,
                                  created_from=created_from.isoformat() if created_from else None,
                                  created_to=created_to.isoformat() if created_to else None)
                items.extend(with_kind(item, record_kind) for item in page['items'])
                store_offset += len(page['items'])
                if store_offset >= needed or store_offset >= page['total'] or not page['items']:
                    total += page['total']
                    break
        items.sort(key=lambda item: (item['created_at'], item['id']), reverse=True)
        return {'items': items[offset:offset + limit], 'total': total}

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
        return with_kind(await call(store.create, actor=actor, request_key=key, input_sha256=digest,
                          source=source, analysis=analysis, provenance=provenance), 'case')

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
    async def get(case_id: str, request: Request, access=Depends(identity)):
        _, record = await find_record(request.app.state.case_service, case_id)
        return record

    @router.post('/{case_id}/auxiliary')
    async def auxiliary(case_id: str, payload: AuxiliaryConsent, request: Request, access=Depends(identity)):
        if payload.allow_external_processing is not True:
            raise HTTPException(422, 'Explicit permission to send this message to TypeSafe is required')
        _, case = await find_record(request.app.state.case_service, case_id)
        if case['kind'] == 'feedback':
            raise HTTPException(422, 'Auxiliary analysis is unavailable for user feedback')
        client = jev_client(request)
        if not client.enabled:
            raise HTTPException(503, 'Auxiliary analysis is not configured')
        try:
            prepared = prepare_case_input(case['source'], case['analysis'],
                                          visible_text=visible_text, mask_inline_data=mask_inline_data)
        except ValueError:
            return {'case_id': case_id, 'case_version': case['version'], 'status': 'skipped',
                    'reason': 'legacy_source_format', 'affects_risk': False}
        base = {'case_id': case_id, 'case_version': case['version'], 'affects_risk': False}
        try:
            request_id = request_identity(access[1], case_id, prepared)
        except ValueError as error:
            return {**base, 'status': 'skipped', 'reason': str(error)}
        limit = jev_configuration(os.environ)['daily_limit']
        if limit is None:
            raise HTTPException(503, 'Auxiliary daily limit configuration is invalid')
        control = await call(jev_control, request.app.state.case_service)
        reservation = await call(control.reserve, request_id, limit)
        quota = {key: reservation[key] for key in ('used', 'daily_limit', 'reset_at')}
        receipt = {'quota': quota, 'receipt_expires_at': reservation.get('expires_at')}
        if reservation['status'] == 'cached':
            return {**reservation['result'], **base, **receipt, 'reused': True}
        if reservation['status'] != 'reserved':
            return {**base, **receipt, 'status': 'skipped',
                    'reason': 'request_pending' if reservation['status'] == 'pending' else 'daily_quota_exhausted'}
        result = await run_in_threadpool(client.evaluate, **prepared)
        await call(control.finish, request_id, reservation['claim'], result, limit)
        # Transient duplicate-control receipt only; no case mutation or automatic verdict.
        return {**result, **base, **receipt, 'reused': False}

    @router.patch('/{case_id}')
    async def update(case_id: str, payload: CaseReview, request: Request, access=Depends(identity)):
        store, record = await find_record(request.app.state.case_service, case_id)
        return with_kind(await call(store.update, case_id, actor=access[1], **payload.model_dump()), record['kind'])

    return router
