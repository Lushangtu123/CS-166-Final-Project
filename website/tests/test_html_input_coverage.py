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

    def test_remote_image_is_disclosed_without_turning_text_rich_mail_unknown(self):
        body = ('<p>Hello team, the project meeting is Thursday morning. '
                'Please bring your current progress notes and use the normal calendar invitation.</p>'
                '<img src="https://images.example.org/logo.png" alt="Company logo">')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage'], {
            'count': 1, 'inspection_status': 'metadata_only',
        })
        self.assertEqual(result['total_score'], 0)
        self.assertEqual(result['risk_level'], 'safe')
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('remote image content was not inspected' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_image_dominant_remote_mail_cannot_be_called_safe(self):
        message = EmailMessage()
        message['Subject'] = 'Message for you'
        message.set_content('<p>Please see the image below.</p>'
                            '<img src="https://images.example.org/notice.png" alt="">', subtype='html')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=message.as_string())
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertIsNone(result['combined_phishing_score'])
        self.assertFalse(result['analysis_complete'])

    def test_plain_alternative_cannot_hide_image_dominant_html(self):
        message = EmailMessage()
        message['Subject'] = 'Meeting notes'
        message.set_content('Hello team, the project meeting is Thursday morning. '
                            'Please bring your current progress notes and use the normal calendar invitation.')
        message.add_alternative('<p>Please see the image.</p>'
                                '<img src="https://images.example.org/notice.png">', subtype='html')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=message.as_string())
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])

    def test_invisible_format_controls_cannot_pad_image_dominant_text(self):
        body = '<p>See image</p>' + '\u200b' * 100 + '<img src="https://images.example.org/notice.png">'
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')

    def test_text_rich_nested_remote_image_does_not_force_unknown(self):
        inner = EmailMessage()
        inner['Subject'] = 'Project update'
        inner.set_content('<p>Hello team, the project meeting is Thursday morning. '
                          'Please bring your current progress notes and use the normal calendar invitation.</p>'
                          '<img src="https://images.example.org/logo.png">', subtype='html')
        outer = EmailMessage()
        outer['Subject'] = 'Forwarded notes'
        outer.set_content('Hello team, the project meeting is Thursday morning. '
                          'Please bring your current progress notes and use the normal calendar invitation.')
        outer.add_attachment(inner, filename='forwarded.eml')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=outer.as_string())
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'safe')
        self.assertFalse(result['analysis_complete'])

    def test_remote_image_references_in_srcset_and_css_are_bounded(self):
        body = ('<p>Hello team, please review the detailed project notes for our next meeting.</p>'
                '<source srcset="https://images.example.org/a.png 1x, '
                '//images.example.org/b.png 2x">'
                '<div style="background:url(https://images.example.org/c.png)"></div>'
                + '<img src="https://images.example.org/d.png">' * 25)
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 20)
        self.assertEqual(result['inline_image_coverage']['count'], 0)

    def test_vml_and_svg_image_references_are_disclosed(self):
        text = ('<p>Hello team, the project meeting is Thursday morning. '
                'Please bring your current progress notes and use the normal calendar invitation.</p>')
        images = (
            '<v:imagedata src="https://images.example.org/notice.png">',
            '<v:fill src="https://images.example.org/background.png">',
            '<svg><image href="https://images.example.org/notice.png"></image></svg>',
            '<svg><image xlink:href="https://images.example.org/notice.png"></image></svg>',
        )
        with patch.object(app, '_content_pipeline', None):
            for image in images:
                with self.subTest(image=image):
                    result = self.analyze(body=text + image)
                    self.assertEqual(result['remote_image_coverage']['count'], 1)
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(any('remote image content was not inspected' in warning.lower()
                                        for warning in result['analysis_warnings']))

    def test_vml_and_svg_image_references_in_raw_email_are_disclosed(self):
        message = EmailMessage()
        message['Subject'] = 'Project update'
        message.set_content('<p>Please see the image below.</p>'
                            '<v:imagedata src="https://images.example.org/notice.png">'
                            '<svg><image href="data:image/png;base64,eA=="></image></svg>',
                            subtype='html')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(raw_email=message.as_string())
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['inline_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])

    def test_outlook_conditional_vml_image_is_disclosed(self):
        body = ('<p>Please see the image below.</p>'
                '<!--[if mso]><v:rect><v:imagedata src="https://images.example.org/notice.png">'
                '</v:rect><![endif]-->')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])

    def test_negated_outlook_conditional_does_not_claim_image_coverage(self):
        with patch.object(app, '_content_pipeline', None):
            for condition in ('!mso', '!(mso)', '! (mso)', 'not mso', 'not (mso)'):
                with self.subTest(condition=condition):
                    body = ('<p>Hello team, please review the detailed project notes for our next meeting.</p>'
                            f'<!--[if {condition}]><v:imagedata '
                            'src="https://images.example.org/hidden.png"><![endif]-->')
                    result = self.analyze(body=body)
                    self.assertEqual(result['remote_image_coverage']['count'], 0)
                    self.assertTrue(result['analysis_complete'])

    def test_compound_mso_conditional_still_discloses_image(self):
        body = ('<p>Please see the image below.</p>'
                '<!--[if (mso)|(!mso)]><v:imagedata '
                'src="https://images.example.org/notice.png"><![endif]-->')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertFalse(result['analysis_complete'])

    def test_svg_icon_and_unrelated_vml_element_are_not_images(self):
        body = ('<p>Hello team, please review the detailed project notes for our next meeting.</p>'
                '<svg><use href="https://images.example.org/icon.svg#check"></use></svg>'
                '<v:shape src="https://images.example.org/shape.png"></v:shape>'
                '<!-- <v:imagedata src="https://images.example.org/comment.png"> -->')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 0)
        self.assertEqual(result['inline_image_coverage']['count'], 0)
        self.assertTrue(result['analysis_complete'])

    def test_data_srcset_payload_does_not_create_a_remote_image(self):
        body = ('<p>Hello team, please review the detailed project notes for our next meeting.</p>'
                '<source srcset="data:image/png;base64,//8= 1x, '
                'https://images.example.org/notice.png 2x">')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['inline_image_coverage']['count'], 1)
        self.assertEqual(result['remote_image_coverage']['count'], 1)

    def test_relative_image_with_remote_base_is_uninspected(self):
        body = ('<base href="https://images.example.org/assets/">'
                '<p>Please see the image below.</p><img src="notice.png">')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')

    def test_relative_css_image_with_remote_base_is_uninspected(self):
        body = ('<base href="https://images.example.org/assets/">'
                '<p>Please see the image below.</p>'
                '<div style="background:url(logo.png)"></div>')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')

    def test_video_source_is_not_counted_as_an_image(self):
        body = ('<p>Hello team, please review the detailed project notes for our next meeting.</p>'
                '<video><source src="https://media.example.org/demo.mp4" type="video/mp4"></video>')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 0)
        self.assertFalse(any('remote image content' in warning.lower()
                             for warning in result['analysis_warnings']))

    def test_explicit_data_image_source_keeps_existing_coverage(self):
        body = '<p>Please see the image below.</p><source src="data:image/png;base64,eA==">'
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['inline_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')

    def test_html_background_attribute_is_counted_as_image_content(self):
        body = ('<p>Please see the image below.</p>'
                '<table background="https://images.example.org/notice.png"><tr><td></td></tr></table>')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage']['count'], 1)
        self.assertEqual(result['risk_level'], 'unknown')

    def test_hidden_remote_image_literals_are_not_counted(self):
        body = ('<!-- <img src="https://images.example.org/a.png"> -->'
                '<script>const image = "https://images.example.org/b.png";</script>'
                '<p>Hello team, please review the detailed project notes.</p>')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=body)
        self.assertEqual(result['remote_image_coverage'], {
            'count': 0, 'inspection_status': 'not_applicable',
        })
        self.assertTrue(result['analysis_complete'])

    def test_substantial_han_text_warns_that_language_coverage_is_limited(self):
        body = ('本月发票的收款银行账户已经变更，请将未结款项汇入附件所列的新账户。'
                '旧账户已停用，请今天完成转账并回复确认。')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(subject='付款账户变更', body=body)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('han-script' in warning.lower() and 'limited' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_english_subject_cannot_supply_all_model_features_for_chinese_body(self):
        pipeline = self.deployment_pipeline()
        bodies = (
            '本月发票的收款银行账户已经变更，请将未结款项汇入附件所列的新账户。旧账户已停用，请今天完成转账并回复确认。',
            '本月发票已经按原来的银行账户完成付款，无需更改收款信息。我们会在下周的例会上核对记录，谢谢大家。',
        )
        with patch.object(app, '_content_pipeline', pipeline):
            for body in bodies:
                with self.subTest(body=body):
                    result = self.analyze(subject='Invoice notice', body=body)
                    self.assertEqual(result['total_score'], 0)
                    self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
                    self.assertIsNone(result['ml_phishing_probability'])
                    self.assertEqual(result['risk_level'], 'unknown')
                    self.assertFalse(result['analysis_complete'])

    def test_extension_b_han_body_cannot_be_scored_from_english_subject(self):
        pipeline = self.deployment_pipeline()
        body = ' '.join(''.join(chr(0x20000 + offset) for offset in range(10))
                        for _ in range(5))
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Invoice notice', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])
        self.assertTrue(any('han-script' in warning.lower()
                            for warning in result['analysis_warnings']))
        self.assertEqual(result['risk_level'], 'unknown')

    def test_newer_han_extensions_are_not_missed_by_deployment_unicode_database(self):
        pipeline = self.deployment_pipeline()
        with patch.object(app, '_content_pipeline', pipeline):
            for codepoint in (0x2EBF0, 0x323B0):  # Unicode Extensions I and J
                with self.subTest(codepoint=codepoint):
                    result = self.analyze(
                        subject='Routine project invoice notice for reference',
                        body=chr(codepoint) * 50,
                    )
                    self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
                    self.assertTrue(any('han-script' in warning.lower()
                                        for warning in result['analysis_warnings']))
                    self.assertEqual(result['risk_level'], 'unknown')

    def test_english_body_features_remain_usable_with_han_footer(self):
        pipeline = self.deployment_pipeline()
        body = ('Please review the project notes before our regular meeting tomorrow. '
                'Bring the agenda and the latest release schedule. '
                '本月发票已经按原来的银行账户完成付款，无需更改收款信息。')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'available')
        self.assertTrue(any('han-script' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_chinese_body_model_abstention_preserves_link_risk(self):
        pipeline = self.deployment_pipeline()
        body = ('<p>本月发票的收款银行账户已经变更，请今天登录新网站完成付款。'
                '旧账户已停用，请立即核对付款记录并回复确认。</p>'
                '<a href="https://paypal.com.login.example">继续</a>')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Invoice notice', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])
        self.assertGreater(result['url_count'], 0)
        self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_english_padding_cannot_hide_substantial_han_text(self):
        body = ('Hello team, these are routine project meeting notes for everyone. '
                'Please review the ordinary planning details and calendar invitation. ' * 4
                + '本月发票的收款银行账户已经变更，请将未结款项汇入新账户并回复确认。')
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertTrue(any('han-script' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_single_han_character_in_english_text_does_not_trigger_language_warning(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body='Hello team, the project meeting is on Thursday. Thanks, 李')
        self.assertFalse(any('han-script' in warning.lower()
                             for warning in result['analysis_warnings']))

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

    def test_committed_model_routine_invoice_is_not_critical_without_independent_evidence(self):
        pipeline = self.deployment_pipeline()
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(
                subject='September invoice',
                body=('Your September invoice is attached for your records. Payment was completed '
                      'last week through our usual billing process; no further action is required.'),
            )
        self.assertEqual(result['ml_status'], 'available')
        self.assertEqual(result['total_score'], 0)
        self.assertEqual(result['fusion_basis'], 'model_only')
        self.assertEqual(result['risk_level'], 'high')
        self.assertGreaterEqual(result['ml_phishing_probability'], 80)

    def test_committed_model_payment_change_still_triggers_review(self):
        pipeline = self.deployment_pipeline()
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(
                subject='Invoice update',
                body=('We changed the bank account for your invoice. Send payment today '
                      'to the new account and keep this confidential.'),
            )
        self.assertEqual(result['ml_status'], 'available')
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertGreater(result['ml_phishing_probability'], result['ml_decision_threshold'])

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
