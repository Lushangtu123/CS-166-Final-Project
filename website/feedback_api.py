"""Public, bounded reports for private analyst review."""
import hashlib
import base64
import binascii
import json
import re
import sqlite3
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from case_store import CaseConflict, CaseInvalid
from case_cloud import CaseUnavailable


class FeedbackAnalysis(BaseModel):
    model_config = ConfigDict(extra='forbid')
    risk_level: Literal['safe', 'low', 'medium', 'high', 'critical', 'unknown']
    risk_score: float | None = Field(default=None, ge=0, le=100)
    risk_label: str = Field(default='', max_length=100)
    analysis_complete: bool | None = None
    model_id: str | None = Field(default=None, max_length=90)
    evidence_codes: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode='after')
    def bounded_codes(self):
        if any(not re.fullmatch(r'[a-z0-9_-]{1,48}', code) for code in self.evidence_codes):
            raise ValueError('Evidence codes must be short identifiers')
        return self


class FeedbackInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    report_type: Literal['false_positive', 'false_negative', 'incorrect_risk', 'incorrect_evidence', 'other']
    note: str = Field(default='', max_length=2000)
    include_source: bool = Field(strict=True)
    evaluation_consent: bool = Field(default=False, strict=True)
    input_mode: Literal['sender', 'content', 'eml', 'image']
    input_fingerprint: str
    analysis: FeedbackAnalysis
    source: dict[str, str] | None = None

    @model_validator(mode='after')
    def valid_source(self):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', self.input_fingerprint):
            raise ValueError('Invalid input fingerprint')
        if self.evaluation_consent and (not self.include_source or self.input_mode not in {'content', 'eml'}):
            raise ValueError('Private evaluation requires original email content and separate consent')
        if not self.include_source:
            if self.source is not None:
                raise ValueError('Original input requires explicit consent')
            return self
        if not self.source:
            raise ValueError('Consented input is missing')
        allowed = {
            'sender': {'email'},
            'content': {'subject', 'body'},
            'eml': {'eml_base64'},
            'image': {'ocr_text', 'qr_text'},
        }[self.input_mode]
        if not set(self.source) <= allowed or not any(self.source.values()):
            raise ValueError('Invalid source fields for input mode')
        limits = {'email': 320, 'subject': 500, 'body': 50000, 'eml_base64': 80000,
                  'ocr_text': 12000, 'qr_text': 4000}
        for key, value in self.source.items():
            if len(value.encode('utf-8')) > limits[key] or (key != 'eml_base64' and 'data:' in value.lower()):
                raise ValueError('Original input exceeds retention limits or contains inline data')
        if self.input_mode == 'eml':
            try:
                raw = base64.b64decode(self.source['eml_base64'], validate=True)
            except (binascii.Error, KeyError):
                raise ValueError('Invalid email file encoding') from None
            if not 0 < len(raw) <= 60000:
                raise ValueError('Email file exceeds the 60 KB retention limit')
        return self


def make_feedback_router():
    router = APIRouter()

    @router.post('/api/feedback', status_code=201)
    async def submit(payload: FeedbackInput, request: Request):
        if getattr(request.app.state, 'case_configuration_error', False):
            raise HTTPException(503, 'Feedback storage is not configured')
        service = getattr(request.app.state, 'case_service', None)
        if service is None or service.feedback_store is None:
            raise HTTPException(503, 'Feedback storage is not configured')
        try:
            request_key = str(UUID(request.headers.get('idempotency-key', '')))
        except ValueError:
            raise HTTPException(422, 'A UUID Idempotency-Key header is required') from None
        canonical = json.dumps(payload.model_dump(), sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        source = {'subject': '', 'body': ''}
        if payload.source:
            if payload.input_mode == 'sender':
                source['body'] = payload.source['email']
            elif payload.input_mode == 'content':
                source.update(payload.source)
            elif payload.input_mode == 'eml':
                raw = base64.b64decode(payload.source['eml_base64'], validate=True)
                source['body'] = raw.decode('utf-8', errors='replace')[:60000]
                source['eml_base64'] = payload.source['eml_base64']
            else:
                source['body'] = '\n'.join(filter(None, (payload.source.get('ocr_text'), payload.source.get('qr_text'))))
        analysis = payload.analysis.model_dump()
        analysis['risk_label'] = analysis['risk_label'] or analysis['risk_level'].title() + ' risk'
        provenance = {'record_kind': 'user_feedback', 'report_type': payload.report_type,
                      'note': payload.note, 'source_consent': payload.include_source,
                      'evaluation_consent': payload.evaluation_consent,
                      'input_mode': payload.input_mode, 'input_fingerprint': payload.input_fingerprint,
                      'source_schema': 2,
                      'diagnostic_schema': 1, 'client_reported': True}
        try:
            saved = await run_in_threadpool(service.feedback_store.create, actor='user_feedback',
                request_key=request_key, input_sha256=digest, source=source, analysis=analysis,
                provenance=provenance)
        except CaseConflict:
            raise HTTPException(409, 'This report key was used for different input') from None
        except CaseInvalid as exc:
            raise HTTPException(422, str(exc)) from None
        except (CaseUnavailable, sqlite3.Error, OSError):
            raise HTTPException(503, 'Feedback storage is unavailable. Retry with the same report.') from None
        return {'id': saved['id']}

    return router
