"""Fail-closed, no-regression comparison of two reports on the same fixed cohort.

This is a deterministic regression gate, not a statistical significance test or
proof of production quality. Models and extraction code may change; ground truth,
scoring definitions and inclusion rules must remain identical.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import re

PUBLIC = 'public_corpus_local_serving_pipeline'
VISION = 'phishguard-vision-benchmark/v1'


def compare(baseline: dict, candidate: dict) -> dict:
    errors, changes = [], []

    def same(a, b, key, prefix=''):
        if key not in a or key not in b or a[key] != b[key]:
            errors.append(f'Incomparable {prefix}{key}')

    def positive(value):
        return type(value) is int and value > 0

    def metric(a, b, key, direction, prefix='', count=False):
        av, bv = a.get(key), b.get(key)
        def valid(v):
            return type(v) in (int, float) and math.isfinite(v) and v >= 0 and (count or key == 'character_error_rate' or v <= 1)
        if not valid(av) or not valid(bv):
            errors.append(f'Missing or invalid metric {prefix}{key}')
            return
        delta = bv - av
        changes.append({'metric':prefix+key, 'baseline':av, 'candidate':bv, 'delta':delta})
        if delta * direction < -1e-9:
            errors.append(f'Regression {prefix}{key}')

    def public_group(a, b, prefix, require_classes=False):
        for key in ('n','phishing_count','legitimate_count'):
            same(a,b,key,prefix)
            if type(a.get(key)) is not int or a[key] < 0:
                errors.append(f'Invalid denominator {prefix}{key}')
        if not positive(a.get('n')) or a.get('n') != a.get('phishing_count',0)+a.get('legitimate_count',0):
            errors.append(f'Empty or inconsistent cohort {prefix}')
        if require_classes and not all(positive(a.get(k)) for k in ('phishing_count','legitimate_count')):
            errors.append('Both email classes are required for a release comparison')
        for key, denominator, direction in [('phishing_alert_recall','phishing_count',1),('legitimate_false_alert_rate','legitimate_count',-1)]:
            if positive(a.get(denominator)):
                metric(a,b,key,direction,prefix)
        for key,direction in [('unknown_rate',-1),('complete_rate',1),('ml_available_rate',1)]:
            metric(a,b,key,direction,prefix)

    def vision_group(a,b,prefix):
        for key in ('count','reference_characters','qr_positive_count','url_scored_count','english_count','risk_labeled_count'):
            same(a,b,key,prefix)
            if type(a.get(key)) is not int or a[key] < 0:
                errors.append(f'Invalid denominator {prefix}{key}')
        if not positive(a.get('count')):
            return
        for report in (a,b):
            statuses=report.get('statuses',{})
            if (not statuses or any(type(v) is not int or v < 0 for v in statuses.values())
                    or sum(statuses.values()) != report['count']):
                errors.append(f'Invalid status accounting {prefix}')
            if any(v for k,v in statuses.items() if k not in ('processed','partial')):
                errors.append(f'Failed extraction {prefix}')
        if b.get('statuses',{}).get('partial',0) > a.get('statuses',{}).get('partial',0):
            errors.append(f'Increased partial extraction {prefix}')
        for key in ('text_exact_rate','qr_exact_set_rate'):
            metric(a,b,key,1,prefix)
        for key in ('qr_extra_payload_count','empty_reference_false_text_count'):
            metric(a,b,key,-1,prefix,count=True)
        for key,denominator,direction in [('character_error_rate','reference_characters',-1),
                ('qr_positive_exact_set_rate','qr_positive_count',1),('qr_payload_recall','qr_positive_count',1),
                ('url_exact_set_rate','url_scored_count',1),('unexpected_han_image_rate','english_count',-1)]:
            if positive(a.get(denominator)):
                metric(a,b,key,direction,prefix)
        if candidate.get('identity',{}).get('risk_requested') and positive(a.get('risk_labeled_count')):
            metric(a,b,'risk_correct_rate',1,prefix)
            metric(a,b,'risk_undetermined_count',-1,prefix,count=True)
            for report in (a,b):
                if report.get('risk_unavailable_count') != 0:
                    errors.append(f'Risk analysis unavailable {prefix}')

    try:
        if not isinstance(baseline,dict) or not isinstance(candidate,dict):
            raise ValueError('Reports must be objects')
        same(baseline,candidate,'schema_version')
        if baseline.get('evaluation_scope') == PUBLIC and baseline.get('schema_version') == 1:
            for key in ('evaluation_scope','dataset_sha256','manifest_sha256','records_sha256','evaluated_cohort_sha256','scoring_sha256','alert_policy','exploratory_only'):
                same(baseline,candidate,key)
            for key in ('dataset_sha256','manifest_sha256','records_sha256','evaluated_cohort_sha256','scoring_sha256'):
                if not re.fullmatch('[a-f0-9]{64}',str(baseline.get(key,''))):
                    errors.append(f'Invalid identity {key}')
            same(baseline['reproducibility'],candidate['reproducibility'],'configuration')
            for key in ('reference_dataset_sha256','status','template_algorithm'):
                same(baseline['overlap_check'],candidate['overlap_check'],key,'overlap_check.')
            for key in ('input','evaluated','duplicates','overlap_exact','overlap_template','excluded'):
                same(baseline['counts'],candidate['counts'],key,'counts.')
                if type(baseline['counts'].get(key)) is not int or baseline['counts'][key] < 0:
                    errors.append(f'Invalid count {key}')
            for report in (baseline,candidate):
                counts=report['counts']
                if counts.get('failures') != 0 or not positive(counts.get('evaluated')):
                    errors.append('Run has inference failures or no evaluated records')
                if counts['evaluated'] + counts['excluded'] != counts['input'] or counts['evaluated'] != report['overall']['n']:
                    errors.append('Inconsistent record accounting')
            public_group(baseline['overall'],candidate['overall'],'overall.',True)
            for dimension in ('by_source','by_provider','by_language','by_month'):
                a,b=baseline[dimension],candidate[dimension]
                if set(a) != set(b): errors.append(f'Incomparable groups {dimension}')
                for key in sorted(set(a)&set(b)):
                    public_group(a[key],b[key],f'{dimension}.{key}.')
        elif baseline.get('schema_version') == VISION:
            for key in ('dataset_id','semantics'):
                same(baseline,candidate,key)
            a,b=baseline['identity'],candidate['identity']
            for key in ('manifest_sha256','risk_requested'):
                same(a,b,key,'identity.')
            same(a['evaluation_sha256'],b['evaluation_sha256'],'metrics.mjs','scorer.')
            if not re.fullmatch('[a-f0-9]{64}',str(a['evaluation_sha256'].get('metrics.mjs',''))):
                errors.append('Missing scoring implementation identity')
            if not re.fullmatch('[a-f0-9]{64}',str(a.get('manifest_sha256',''))):
                errors.append('Invalid visual manifest identity')
            for identity in (a,b):
                if identity.get('asset_manifest_verified') is not True:
                    errors.append('Recognition assets are not verified')
            keys=('id','language','label','reference_characters','expected_qr_count','urls_scored')
            cohort=lambda r: [{k:row[k] for k in keys} for row in r['records']]
            if cohort(baseline) != cohort(candidate): errors.append('Incomparable visual cohort')
            if not positive(baseline['summary'].get('count')) or len(baseline['records']) != baseline['summary']['count']:
                errors.append('Empty or inconsistent visual cohort')
            vision_group(baseline['summary'],candidate['summary'],'summary.')
            a,b=baseline['by_language'],candidate['by_language']
            if set(a) != set(b): errors.append('Incomparable language groups')
            for key in sorted(set(a)&set(b)): vision_group(a[key],b[key],f'by_language.{key}.')
        else:
            errors.append('Unsupported report schema')
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append('Malformed or incomplete evaluation report')
    return {'schema_version':1,'passed':not errors,'policy':'same cohort and scoring; no worsening or failed runs; partial extractions may not increase',
            'errors':list(dict.fromkeys(errors)), 'metrics':changes,
            'limitation':'Regression check only; a passing baseline is not proof of enterprise accuracy or statistical significance.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',required=True,type=Path)
    parser.add_argument('--candidate',required=True,type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        reports=[]
        for path in (args.baseline,args.candidate):
            if path.stat().st_size > 16_000_000: raise ValueError('Report exceeds 16 MB')
            reports.append(json.loads(path.read_text()))
        result=compare(*reports)
    except (OSError,ValueError):
        parser.error('Cannot read valid bounded report JSON')
    text=json.dumps(result,indent=2,allow_nan=False)+'\n'
    if args.output: args.output.write_text(text)
    else: print(text,end='')
    if not result['passed']: raise SystemExit(1)


if __name__=='__main__': main()
