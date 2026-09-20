import asyncio
from email.message import EmailMessage
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app


class HTMLInputCoverageTests(unittest.TestCase):
    def deployment_pipeline(self):
        from content_inference import load_content_pipeline_artifact
        project_root = WEBSITE_DIR.parent
        deployment_python = (project_root / '.python-version').read_text().strip()
        current_python = f'{sys.version_info.major}.{sys.version_info.minor}'
        if current_python != deployment_python:
            self.skipTest(f'Committed artifact targets Python {deployment_python}, not {current_python}')
        profile = json.loads((project_root / 'vercel.json').read_text())['env']
        return load_content_pipeline_artifact(
            project_root / profile['CONTENT_MODEL_ARTIFACT'],
            profile['CONTENT_MODEL_ARTIFACT_SHA256'],
        )

    def analyze(self, *, subject='Project update', body='', raw_email=None):
        request = app.ContentRequest(
            subject=subject, body=body, raw_email=raw_email or '',
        )
        return json.loads(asyncio.run(app.analyze_content_endpoint(request)).body)

    def test_model_receives_visible_html_text_in_both_manual_and_mime_modes(self):
        html = ('<p>Please review the project notes before our meeting tomorrow.</p>'
                '<style>urgent suspended account password ' + 'verify ' * 100 + '</style>')
        message = EmailMessage()
        message['Subject'] = 'Project update'
        message.set_content(html, subtype='html')
        captured = []

        def predict(_pipeline, subject, body, **_kwargs):
            captured.append((subject, body))
            return {
                'ml_status': 'insufficient_context', 'ml_phishing_probability': None,
                'ml_legitimate_probability': None, 'ml_label': None,
                'ml_prediction': None, 'ml_top_contributors': [],
            }

        with patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}), \
                patch.object(app, 'predict_content', side_effect=predict):
            self.analyze(body=html)
            self.analyze(raw_email=message.as_string())
        self.assertEqual(len(captured), 2)
        for subject, body in captured:
            self.assertEqual(subject, 'Project update')
            self.assertEqual(body, 'Please review the project notes before our meeting tomorrow.')

    def test_plain_mime_markup_remains_literal_for_model(self):
        message = EmailMessage()
        message['Subject'] = 'Project update'
        message.set_content('<style>Literal note for our project meeting.</style>')
        with patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}), \
                patch.object(app, 'predict_content') as predict:
            predict.return_value = {
                'ml_status': 'insufficient_context', 'ml_phishing_probability': None,
                'ml_legitimate_probability': None, 'ml_label': None,
                'ml_prediction': None, 'ml_top_contributors': [],
            }
            self.analyze(raw_email=message.as_string())
        self.assertIn('<style>Literal note', predict.call_args.args[2])

    def test_mime_alternatives_keep_visibility_independent(self):
        message = EmailMessage()
        message['Subject'] = 'Project update'
        message.set_content('<style>literal plain text</style>')
        message.add_alternative('<style>hidden words</style><p>Visible meeting note.</p>', subtype='html')
        with patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}), \
                patch.object(app, 'predict_content') as predict:
            predict.return_value = {
                'ml_status': 'insufficient_context', 'ml_phishing_probability': None,
                'ml_legitimate_probability': None, 'ml_label': None,
                'ml_prediction': None, 'ml_top_contributors': [],
            }
            self.analyze(raw_email=message.as_string())
        body = predict.call_args.args[2]
        self.assertIn('<style>literal plain text</style>', body)
        self.assertIn('Visible meeting note.', body)
        self.assertNotIn('hidden words', body)

    def test_inline_data_images_mark_incomplete_without_risk_points(self):
        clean_text = 'Please review the project notes before our meeting tomorrow.'
        for image in (
            '<img src="data:image/png;base64,aGVsbG8=">',
            '<source srcset="data:image/svg+xml;base64,PHN2Zz4= 2x">',
            '<div style="background:url(data:image/png;base64,aGVsbG8=)"></div>',
            '<style>.hero { background:url("data:image/svg+xml;base64,PHN2Zz4=") }</style>',
            '<div style="background:url(\\64 ata:image/png;base64,aGVsbG8=)"></div>',
            '<div style=\'background:url("data:\\\nimage/png;base64,aGVsbG8=")\'></div>',
        ):
            with self.subTest(image=image), patch.object(app, '_content_pipeline', None):
                result = self.analyze(body=f'<p>{clean_text}</p>{image}')
            self.assertEqual(result['inline_image_coverage'], {
                'count': 1, 'inspection_status': 'metadata_only',
            })
            self.assertEqual(result['total_score'], 0)
            self.assertEqual(result['risk_level'], 'unknown')
            self.assertIsNone(result['combined_phishing_score'])
            self.assertFalse(result['analysis_complete'])
            self.assertEqual(sum('embedded image content was not inspected' in warning.lower()
                                 for warning in result['analysis_warnings']), 1)

    def test_inline_images_are_bounded_and_keep_independent_link_risk(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=('<img src="data:image/png;base64,eA==">' * 25
                + '<a href="https://paypal.com.login.example">Continue</a>'))
        self.assertEqual(result['inline_image_coverage']['count'], 20)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(sum('embedded image content was not inspected' in warning.lower()
                             for warning in result['analysis_warnings']), 1)

    def test_malformed_css_image_url_cannot_mask_a_separate_anchor(self):
        html = ('<div style="background:url(data:image/png;base64,eA==">'
                '<a href="https://paypal.com.login.example">Continue</a><p>)</p></div>')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertGreater(result['url_count'], 0)

    def test_non_image_data_and_hidden_literals_do_not_claim_image_coverage(self):
        for body in (
            '<!-- <img src="data:image/png;base64,eA=="> --><p>Hello team.</p>',
            '<script>const image = "data:image/png;base64,eA==";</script><p>Hello team.</p>',
            '<p>data:image/png;base64,eA==</p>',
            '<img src="data:text/plain;base64,eA==">',
        ):
            with self.subTest(body=body), patch.object(app, '_content_pipeline', None):
                result = self.analyze(body=body)
            self.assertEqual(result['inline_image_coverage'], {
                'count': 0, 'inspection_status': 'not_applicable',
            })
            self.assertFalse(any('embedded image content was not inspected' in warning.lower()
                                 for warning in result['analysis_warnings']))

    def test_plain_text_data_image_literal_is_not_an_inline_image(self):
        message = EmailMessage()
        message.set_content('The literal string data:image/png;base64,eA== is in these notes.')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=message.as_string())
        self.assertEqual(result['inline_image_coverage']['count'], 0)

    def test_raw_html_inline_image_has_same_coverage(self):
        message = EmailMessage()
        message.set_content('<p>Hello team.</p><img src="data:image/svg+xml;base64,PHN2Zz4=">', subtype='html')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=message.as_string())
        self.assertEqual(result['inline_image_coverage'], {
            'count': 1, 'inspection_status': 'metadata_only',
        })
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])

    def test_urls_inside_opaque_image_payload_do_not_add_link_risk(self):
        payload = '%3Csvg%3Ehttps://paypal.com.login.example/%3C/svg%3E'
        images = (
            f'<img src="data:image/svg+xml,{payload}">',
            f'<div style="background:url(\\64 ata:image/svg+xml,{payload})"></div>',
            '<style>.x{background:url("data:image/svg+xml,%3Csvg%3Etext)'
            '%20https://paypal.com.login.example%3C/svg%3E")}</style>',
        )
        for image in images:
            with self.subTest(image=image), patch.object(app, '_content_pipeline', None):
                result = self.analyze(body='<p>Hello team, please review the project notes.</p>' + image)
            self.assertEqual(result['inline_image_coverage']['count'], 1)
            self.assertEqual(result['url_count'], 0)
            self.assertEqual(result['total_score'], 0)
            self.assertEqual(result['risk_level'], 'unknown')

    def test_nested_inline_image_is_aggregated_into_top_level_coverage(self):
        inner = EmailMessage()
        inner.set_content('<p>Hello team.</p><img src="data:image/png;base64,eA==">', subtype='html')
        outer = EmailMessage()
        outer.set_content('Hello team.')
        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=outer.as_string())
        self.assertEqual(result['inline_image_coverage'], {
            'count': 1, 'inspection_status': 'metadata_only',
        })
        self.assertEqual(sum('embedded image content was not inspected' in warning.lower()
                             for warning in result['analysis_warnings']), 1)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])

    def test_short_visible_text_cannot_gain_context_from_hidden_style(self):
        pipeline = self.deployment_pipeline()
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Hi', body='<p>Ok</p><style>' + 'urgent account verify ' * 100 + '</style>')
        self.assertEqual(result['ml_status'], 'insufficient_context')
        self.assertEqual(result['risk_level'], 'unknown')

    def test_committed_model_ignores_hidden_text_in_both_directions(self):
        from content_inference import predict_content
        pipeline = self.deployment_pipeline()
        probes = (
            ('Invoice problem - call support',
             'Your subscription renewal of $499 is complete. If you did not authorize this charge, '
             'call 1-888-555-0199 immediately.',
             'Please review the project notes before our meeting tomorrow.', 1),
            ('Project notes for tomorrow',
             'Hello everyone, please review the agenda before our scheduled meeting.',
             'Your account is suspended. Act now and verify your password immediately.', 0),
        )
        with patch.object(app, '_content_pipeline', pipeline):
            for subject, visible, hidden, expected in probes:
                with self.subTest(subject=subject):
                    control = predict_content(pipeline, subject, visible)
                    result = self.analyze(subject=subject, body=(
                        f'<p>{visible}</p><style>{hidden * 60}</style>'
                    ))
                    self.assertEqual(control['ml_status'], 'available')
                    self.assertEqual(control['ml_prediction'], expected)
                    self.assertEqual(result['ml_status'], 'available')
                    self.assertEqual(result['ml_prediction'], expected)
                    self.assertEqual(result['ml_phishing_probability'], control['ml_phishing_probability'])
                    self.assertEqual(result['analysis_complete'], True)
                    if expected:
                        self.assertIn(result['risk_level'], {'high', 'critical'})
                    else:
                        self.assertNotIn(result['risk_level'], {'high', 'critical'})

    def test_malformed_html_stays_incomplete_and_preserves_link(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=(
                '<![broken><img src="data:image/png;base64,eA==">'
                '<a href="https://paypal.com.login.example">Continue</a>'
            ))
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('Malformed HTML' in warning for warning in result['analysis_warnings']))
        self.assertIn(result['risk_level'], {'high', 'critical'})


if __name__ == '__main__':
    unittest.main()
