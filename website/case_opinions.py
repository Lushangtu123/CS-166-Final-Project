"""Bounded, explicit analyst retention of server-owned auxiliary results."""
import math
import re
from datetime import datetime

from case_store import CaseConflict, CaseInvalid


def saved_opinion(case, actor, receipt_id):
    return next((event['changes']['auxiliary_opinion']['to'] for event in case['events']
                 if event['action'] == 'auxiliary_saved' and event['actor'] == actor
                 and event.get('changes', {}).get('auxiliary_opinion', {}).get('to', {}).get('receipt_id') == receipt_id), None)


def opinion_changes(case, actor, expected_version, opinion):
    required = {'receipt_id', 'requested_at', 'provider', 'model', 'questions_sha256',
                'input_sha256', 'probabilities', 'evidence_incomplete', 'affects_risk'}
    probabilities = opinion.get('probabilities')
    keys = {'credential_request', 'payment_redirection', 'authority_pressure',
            'phishing_intent', 'insufficient_evidence'}
    if set(opinion) != required or opinion['provider'] != 'typesafe' or opinion['affects_risk'] is not False or \
            type(opinion['evidence_incomplete']) is not bool or \
            not isinstance(opinion['model'], str) or not re.fullmatch(r'jev-[0-9.]{1,32}', opinion['model']) or \
            any(not isinstance(opinion[key], str) or not re.fullmatch(r'[0-9a-f]{64}', opinion[key])
                for key in ('receipt_id', 'questions_sha256', 'input_sha256')) or \
            not isinstance(probabilities, dict) or set(probabilities) != keys or \
            any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1
                for value in probabilities.values()):
        raise CaseInvalid('Invalid auxiliary opinion')
    try:
        timestamp = datetime.fromisoformat(opinion['requested_at'].replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise CaseInvalid('Invalid auxiliary timestamp') from None
    prior = saved_opinion(case, actor, opinion['receipt_id'])
    if prior is not None:
        if prior != opinion:
            raise CaseConflict('Saved auxiliary opinion differs')
        return None
    if case['version'] != expected_version:
        raise CaseConflict('Case changed; reload before saving the opinion')
    if case['status'] == 'closed' or case.get('provenance', {}).get('record_kind') == 'user_feedback':
        raise CaseInvalid('Save auxiliary opinions only to an open case')
    if len(case['events']) >= 200:
        raise CaseInvalid('Case reached its 200-event limit; contact the administrator')
    return {'auxiliary_opinion': {'from': None, 'to': opinion}}
