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

    def test_substantial_han_footer_abstains_despite_english_body_features(self):
        pipeline = self.deployment_pipeline()
        body = ('Please review the project notes before our regular meeting tomorrow. '
                'Bring the agenda and the latest release schedule. '
                '本月发票已经按原来的银行账户完成付款，无需更改收款信息。')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])
        self.assertTrue(any('han-script' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_short_han_instruction_cannot_borrow_english_body_features(self):
        pipeline = self.deployment_pipeline()
        body = ('Please review the ordinary project meeting notes and calendar invitation. '
                '银行账户已变更,请立即转账并保密。')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])

    def test_digits_cannot_supply_features_for_uncovered_han_instruction(self):
        pipeline = self.deployment_pipeline()
        body = ('Please review the ordinary project planning agenda for tomorrow. '
                '本月发票付款账户已经变更请转账1234567890')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])

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

    def test_hidden_attribute_and_inline_style_cannot_pad_visible_text(self):
        pipeline = self.deployment_pipeline()
        subject = 'Invoice problem - call support'
        visible = ('Your subscription renewal of $499 is complete. If you did not authorize '
                   'this charge, call 1-888-555-0199 immediately.')
        padding = 'Please review the project notes before our meeting tomorrow. ' * 30
        with patch.object(app, '_content_pipeline', pipeline):
            control = self.analyze(subject=subject, body=visible)
            for hidden in (f'<div hidden>{padding}</div>',
                           f'<div style="display:none">{padding}</div>',
                           f'<div style="visibility: hidden">{padding}</div>'):
                with self.subTest(hidden=hidden[:40]):
                    result = self.analyze(subject=subject, body=f'<p>{visible}</p>{hidden}')
                    self.assertEqual(result['ml_phishing_probability'],
                                     control['ml_phishing_probability'])
                    self.assertEqual(result['risk_level'], control['risk_level'])
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(any('hidden html text' in warning.lower()
                                        for warning in result['analysis_warnings']))

    def test_inline_zero_opacity_cannot_pad_the_model_or_rules(self):
        pipeline = self.deployment_pipeline()
        subject = 'Invoice problem - call support'
        visible = ('Your subscription renewal of $499 is complete. If you did not authorize '
                   'this charge, call 1-888-555-0199 immediately.')
        padding = 'Please review the project notes before our meeting tomorrow. ' * 30
        with patch.object(app, '_content_pipeline', pipeline):
            control = self.analyze(subject=subject, body=visible)
            result = self.analyze(subject=subject, body=(
                f'<p>{visible}</p><div style="opacity:0">{padding}</div>'
            ))
        self.assertEqual(result['ml_phishing_probability'], control['ml_phishing_probability'])
        self.assertEqual(result['total_score'], control['total_score'])
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('hidden html text' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_zero_percent_and_clamped_negative_opacity_are_hidden(self):
        for style in ('opacity:0%', 'opacity:0.0', 'opacity:-1',
                      'opacity:0 !important; opacity:1'):
            with self.subTest(style=style):
                warnings = []
                self.assertEqual(app._visible_content_text(
                    f'<div style="{style}">Hidden benign padding</div>', warnings,
                ), '')
                self.assertTrue(any('hidden html text' in warning.lower()
                                    for warning in warnings))

    def test_stylesheet_hide_rule_cannot_produce_complete_low_risk(self):
        pipeline = self.deployment_pipeline()
        subject = 'Invoice problem - call support'
        visible = ('Your subscription renewal of $499 is complete. If you did not authorize '
                   'this charge, call 1-888-555-0199 immediately.')
        padding = 'Please review the project notes before our meeting tomorrow. ' * 30
        html = f'<style>.pad {{ display:none }}</style><p>{visible}</p><div class="pad">{padding}</div>'
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject=subject, body=html)
        self.assertFalse(result['analysis_complete'])
        self.assertNotEqual(result['risk_level'], 'low')
        self.assertIsNone(result['ml_phishing_probability'])
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertTrue(any('stylesheet' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_quoted_css_brace_cannot_bypass_stylesheet_warning(self):
        pipeline = self.deployment_pipeline()
        visible = ('Your subscription renewal of $499 is complete. If you did not '
                   'authorize this charge, call 1-888-555-0199 immediately.')
        padding = 'Please review the project notes before our meeting tomorrow. ' * 30
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Invoice problem - call support', body=(
                '<style>.pad { content:"}"; display:none }</style>'
                f'<p>{visible}</p><div class="pad">{padding}</div>'
            ))
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertIsNone(result['ml_phishing_probability'])

    def test_inert_template_stylesheet_does_not_abstain(self):
        warnings = []
        text = app._visible_content_text(
            '<template><style>.pad { display:none }</style></template>'
            '<p>Visible project meeting agenda.</p>', warnings,
        )
        self.assertEqual(text, 'Visible project meeting agenda.')
        self.assertEqual(warnings, [])

    def test_stylesheet_warning_does_not_hide_independent_link_risk(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=(
                '<style>.pad{display:none}</style><div class="pad">Routine project notes.</div>'
                '<a href="https://paypal.com.login.example">Continue</a>'
            ))
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['analysis_complete'])

    def test_stylesheet_hidden_phishing_padding_does_not_create_false_high_risk(self):
        pipeline = self.deployment_pipeline()
        padding = ('Urgent security alert: your account will be suspended immediately unless '
                   'you enter your password now. Final warning: verify your password or lose '
                   'access to your account permanently. ') * 10
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project notes for tomorrow', body=(
                '<style>.pad{display:none}</style>'
                '<p>Hello everyone, please review the normal project agenda.</p>'
                f'<div class="pad">{padding}</div>'
            ))
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertEqual(result['total_score'], 0)
        self.assertFalse(result['analysis_complete'])

    def test_uncertain_html_part_does_not_suppress_plain_mime_evidence(self):
        plain = ('Urgent security alert: your account will be suspended immediately '
                 'unless you enter your password now. Final warning: verify your '
                 'password or lose access permanently.')
        plain_part = {'content': plain, 'content_type': 'text/plain'}
        control = app.analyze_email_content('Project update', '', content_parts=[plain_part])
        result = app.analyze_email_content('Project update', '', content_parts=[
            plain_part,
            {'content': '<style>.pad{display:none}</style><p>Routine agenda.</p>',
             'content_type': 'text/html'},
        ])
        self.assertGreater(control['total_score'], 0)
        self.assertEqual(result['total_score'], control['total_score'])
        self.assertEqual(result['risk_level'], control['risk_level'])
        self.assertTrue(any('stylesheet' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_broken_image_alt_is_scored_as_fallback_text(self):
        pipeline = self.deployment_pipeline()
        alt = ('Your account is suspended. Act now and verify your password immediately. '
               'Enter your password to restore access.')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project notes for tomorrow', body=(
                '<p>Hello everyone, please review the agenda before our scheduled meeting.</p>'
                f'<img alt="{alt}">'
            ))
        self.assertIn('password', app._visible_content_text(f'<img alt="{alt}">').lower())
        self.assertGreater(result['total_score'], 0)
        self.assertNotEqual(result['risk_level'], 'safe')

    def test_sourced_image_alt_cannot_leave_complete_safe_verdict(self):
        pipeline = self.deployment_pipeline()
        alt = 'Your account is suspended. Act now and verify your password immediately.'
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project notes for tomorrow', body=(
                '<p>Hello everyone, please review the agenda before our scheduled meeting.</p>'
                f'<img src="https://images.example.org/notice.png" alt="{alt}">'
            ))
        self.assertFalse(result['analysis_complete'])
        self.assertNotEqual(result['risk_level'], 'safe')
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertTrue(any('alternative text' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_no_space_han_alt_cannot_leave_complete_safe_verdict(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(subject='Project meeting', body=(
                '<p>Please review the ordinary project planning agenda and meeting notes '
                'before our scheduled discussion tomorrow morning.</p>'
                '<img src="cid:notice" alt="您的账户已暂停请立即输入密码完成验证">'
            ))
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('alternative text' in warning.lower()
                            for warning in result['analysis_warnings']))

    def test_hidden_image_alt_does_not_become_visible_text(self):
        warnings = []
        text = app._visible_content_text(
            '<div hidden><img alt="Enter your password immediately"></div>'
            '<p>Visible project meeting notes.</p>', warnings,
        )
        self.assertEqual(text, 'Visible project meeting notes.')
        self.assertTrue(any('hidden html text' in warning.lower() for warning in warnings))

    def test_picture_source_keeps_alt_conditional(self):
        warnings = []
        text = app._visible_content_text(
            '<picture><source srcset="https://images.example.org/notice.png">'
            '<img alt="Your account is suspended. Verify your password immediately."></picture>',
            warnings,
        )
        self.assertEqual(text, '')
        self.assertTrue(any('alternative text' in warning.lower() for warning in warnings))

    def test_picture_without_source_scores_missing_img_fallback(self):
        warnings = []
        text = app._visible_content_text(
            '<picture><img alt="Enter your password immediately"></picture>', warnings,
        )
        self.assertEqual(text, 'Enter your password immediately')
        self.assertEqual(warnings, [])

    def test_short_decorative_alt_does_not_disable_text_model(self):
        pipeline = self.deployment_pipeline()
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project notes for tomorrow', body=(
                '<p>Hello everyone, please review the agenda before our scheduled meeting. '
                'We will discuss the regular project plan and calendar.</p>'
                '<img src="https://images.example.org/logo.png" alt="Company logo">'
            ))
        self.assertEqual(result['ml_status'], 'available')
        self.assertFalse(any('alternative text' in warning.lower()
                             for warning in result['analysis_warnings']))

    def test_css_comments_and_overrides_do_not_claim_hidden_text(self):
        for style in ('opacity:0; opacity:1',
                      'opacity:0 !important; opacity:1 !important',
                      'content:"; opacity:0"; color:red'):
            with self.subTest(style=style):
                warnings = []
                visible = app._visible_content_text(
                    f'<p style=\'{style}\'>Visible meeting agenda.</p>', warnings,
                )
                self.assertEqual(visible, 'Visible meeting agenda.')
                self.assertEqual(warnings, [])
        warnings = []
        visible = app._visible_content_text(
            '<style>/* .pad { display:none } */</style><p>Visible meeting agenda.</p>',
            warnings,
        )
        self.assertEqual(visible, 'Visible meeting agenda.')
        self.assertEqual(warnings, [])

    def test_hidden_phishing_text_is_not_scored_and_visible_sibling_survives(self):
        pipeline = self.deployment_pipeline()
        subject = 'Project notes for tomorrow'
        visible = 'Hello everyone, please review the agenda before our scheduled meeting.'
        hidden = 'Your account is suspended. Act now and verify your password immediately. ' * 30
        html = f'<p>{visible}</p><div style="display:none">{hidden}</div><p>Thank you.</p>'
        with patch.object(app, '_content_pipeline', pipeline):
            control = self.analyze(subject=subject, body=visible + ' Thank you.')
            manual = self.analyze(subject=subject, body=html)
            message = EmailMessage()
            message['Subject'] = subject
            message.set_content(html, subtype='html')
            mime = self.analyze(raw_email=message.as_string())
        for result in (manual, mime):
            self.assertEqual(result['ml_phishing_probability'], control['ml_phishing_probability'])
            self.assertEqual(result['total_score'], control['total_score'])
            self.assertFalse(result['analysis_complete'])
            self.assertTrue(any('hidden html text' in warning.lower()
                                for warning in result['analysis_warnings']))

    def test_implied_paragraph_and_list_end_tags_restore_visible_text(self):
        for html in (
            '<p hidden>Hidden note<p>Visible urgent send password immediately',
            '<p hidden>Hidden note<div>Visible urgent send password immediately</div>',
            '<ul><li hidden>Hidden note<li>Visible urgent send password immediately</ul>',
            '<table><tr><td hidden>Hidden note<td>Visible urgent send password immediately</tr></table>',
            '<table><tr style="display:none"><td>Hidden note<tr><td>Visible urgent send password immediately</table>',
        ):
            with self.subTest(html=html):
                warnings = []
                visible = app._visible_content_text(html, warnings)
                self.assertIn('Visible urgent send password immediately', visible)
                self.assertNotIn('Hidden note', visible)
                self.assertTrue(any('hidden html text' in warning.lower()
                                    for warning in warnings))

    def test_nonvoid_self_closing_syntax_does_not_expose_hidden_text(self):
        html = ('<div hidden/>Hidden account password instruction</div>'
                '<p>Visible regular project meeting note for tomorrow.</p>')
        warnings = []
        visible = app._visible_content_text(html, warnings)
        self.assertNotIn('Hidden account password', visible)
        self.assertIn('Visible regular project meeting', visible)
        self.assertTrue(any('hidden html text' in warning.lower() for warning in warnings))

    def test_first_duplicate_style_attribute_controls_visibility(self):
        warnings = []
        hidden = app._visible_content_text(
            '<div style="display:none" style="display:block">Hidden password instruction</div>',
            warnings,
        )
        self.assertEqual(hidden, '')
        self.assertTrue(any('hidden html text' in warning.lower() for warning in warnings))
        warnings = []
        visible = app._visible_content_text(
            '<div style="display:block" style="display:none">Visible project meeting note</div>',
            warnings,
        )
        self.assertEqual(visible, 'Visible project meeting note')
        self.assertEqual(warnings, [])

    def test_link_inside_hidden_text_keeps_independent_destination_risk(self):
        with patch.object(app, '_content_pipeline', None):
            result = self.analyze(body=(
                '<p>Please review the project notes before our meeting tomorrow.</p>'
                '<div hidden><a href="https://paypal.com.login.example">Continue</a></div>'
            ))
        self.assertGreater(result['url_count'], 0)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['analysis_complete'])

    def test_hidden_anchor_label_does_not_create_display_domain_mismatch(self):
        visible = '<a href="https://example.org/review">Continue</a>'
        hidden_label = ('<a href="https://example.org/review">'
                        '<span hidden>paypal.com</span>Continue</a>')
        with patch.object(app, '_content_pipeline', None):
            control = self.analyze(body=visible)
            result = self.analyze(body=hidden_label)
        self.assertEqual(result['total_score'], control['total_score'])
        self.assertFalse(any('does not match' in finding['msg']
                             for finding in result['extra_indicators']))
        self.assertFalse(result['analysis_complete'])

    def test_hidden_naked_and_markdown_urls_do_not_become_link_evidence(self):
        for hidden in ('https://paypal.com.login.example',
                       '[PayPal](https://paypal.com.login.example)'):
            with self.subTest(hidden=hidden), patch.object(app, '_content_pipeline', None):
                result = self.analyze(body=(
                    '<p>Please review the regular project meeting notes for tomorrow.</p>'
                    f'<div hidden>{hidden}</div>'
                ))
            self.assertEqual(result['url_count'], 0)
            self.assertEqual(result['total_score'], 0)
            self.assertFalse(result['analysis_complete'])

    def test_hidden_manual_subject_punctuation_does_not_add_rule_points(self):
        body = 'Please review the regular project planning notes for tomorrow.'
        with patch.object(app, '_content_pipeline', None):
            control = self.analyze(subject='Project update', body=body)
            result = self.analyze(subject='<span hidden>??</span>Project update', body=body)
        self.assertEqual(result['total_score'], control['total_score'])
        self.assertFalse(result['analysis_complete'])

    def test_uncovered_kana_and_cyrillic_bodies_do_not_inherit_english_subject_score(self):
        pipeline = self.deployment_pipeline()
        bodies = (
            'この請求書の支払い先口座が変更されました。今日中に新しい口座へ送金してください。',
            'Ваш банковский счет для оплаты счета изменился. Срочно переведите деньги на новый счет сегодня.',
        )
        with patch.object(app, '_content_pipeline', pipeline):
            for body in bodies:
                with self.subTest(body=body):
                    result = self.analyze(subject='Routine invoice notice for your records', body=body)
                    self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
                    self.assertIsNone(result['ml_phishing_probability'])
                    self.assertFalse(result['analysis_complete'])

    def test_inline_visibility_override_does_not_hide_displayed_child(self):
        html = ('<div style="visibility:hidden">Ignored note.'
                '<span style="visibility:visible">Visible meeting agenda for the regular '
                'project planning session tomorrow.</span></div>')
        visible = app._visible_content_text(html)
        self.assertNotIn('Ignored note', visible)
        self.assertIn('Visible meeting agenda', visible)

    def test_inherited_or_invalid_visibility_cannot_clear_hidden_parent(self):
        for value in ('inherit', 'unset', 'banana'):
            with self.subTest(value=value):
                warnings = []
                html = (f'<div style="visibility:hidden"><span style="visibility:{value}">'
                        'Hidden account password instruction</span></div>')
                self.assertNotIn('Hidden account', app._visible_content_text(html, warnings))
                self.assertTrue(any('hidden html text' in warning.lower()
                                    for warning in warnings))

    def test_later_display_declaration_can_restore_visibility(self):
        html = '<p style="display:none; display:block">Visible meeting agenda.</p>'
        warnings = []
        self.assertEqual(app._visible_content_text(html, warnings), 'Visible meeting agenda.')
        self.assertEqual(warnings, [])

    def test_css_string_or_url_does_not_create_a_hidden_declaration(self):
        for style in ('content:"; display:none;"; color:red',
                      'background:url(data:image/svg+xml;display:none); color:red'):
            with self.subTest(style=style):
                warnings = []
                html = f'<p style=\'{style}\'>Visible meeting agenda.</p>'
                self.assertEqual(app._visible_content_text(html, warnings),
                                 'Visible meeting agenda.')
                self.assertEqual(warnings, [])

    def test_substantial_uncovered_chinese_segment_abstains_despite_english_body(self):
        pipeline = self.deployment_pipeline()
        body = ('Hello team, these are routine project meeting notes for everyone. '
                'Please review the ordinary planning details and calendar invitation. '
                '本月发票的收款银行账户已经变更，请将未结款项汇入新账户并回复确认。')
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'insufficient_feature_coverage')
        self.assertIsNone(result['ml_phishing_probability'])
        self.assertFalse(result['analysis_complete'])

    def test_scattered_chinese_names_do_not_force_model_abstention(self):
        pipeline = self.deployment_pipeline()
        names = ('张伟', '李娜', '王芳', '刘洋', '陈明', '赵敏', '孙强', '周静',
                 '吴军', '郑丽', '王磊', '陈芳', '张敏', '李伟', '刘芳', '赵强')
        body = ('Please review the normal project planning agenda for tomorrow. '
                + ' '.join(f'The contact {name} will join the meeting.' for name in names))
        with patch.object(app, '_content_pipeline', pipeline):
            result = self.analyze(subject='Project update', body=body)
        self.assertEqual(result['ml_status'], 'available')
        self.assertTrue(any('han-script' in warning.lower()
                            for warning in result['analysis_warnings']))

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
