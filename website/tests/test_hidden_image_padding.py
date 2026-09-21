"""Structural hidden-text/image conjunction, never classify hidden prose itself."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

PADDING = 'Project resources documentation and community discussion. ' * 30
IMAGE = '<a href="https://example.org/notice"><img src="https://images.example/notice.png"></a>'
SIGNAL = 'Large hidden text block accompanies an image-dominant linked message'


class HiddenImagePaddingTests(unittest.TestCase):
    def analyze(self, body, content_type='text/html'):
        view = {}
        result = app.analyze_email_content('', '', content_parts=[{'content_type':content_type,'content':body}], _model_view=view)
        return result, view

    def flagged(self, result):
        return any(SIGNAL in item['msg'] for item in result['extra_indicators'])

    def test_explicit_hidden_padding_and_visible_linked_image_flags_structure(self):
        for attr in ('hidden', 'style="display:none"', 'style="opacity:0"', 'style="visibility:hidden"'):
            with self.subTest(attr=attr):
                result, view = self.analyze(IMAGE + f'<div {attr}>{PADDING}</div>')
                self.assertTrue(self.flagged(result))
                self.assertEqual(result['risk_floor'], 'medium')
                self.assertEqual(sum(SIGNAL in i['msg'] for i in result['extra_indicators']), 1)
                self.assertNotIn('Project resources', view['body'])
                self.assertEqual(result['category_results'], [])

    def test_common_layout_and_inert_code_negative_controls(self):
        for body in (IMAGE, IMAGE+'<span hidden>A short preview of the newsletter.</span>',
                     IMAGE+'<div hidden>Newsletter preview'+('&#8204;&nbsp;'*600)+'</div>',
                     IMAGE+f'<footer>{PADDING}</footer>',
                     IMAGE+f'<script>{PADDING}</script>', IMAGE+f'<template>{PADDING}</template>',
                     IMAGE+f'<style>{PADDING}</style>', IMAGE+f'<!-- {PADDING} -->',
                     f'<div hidden><a href="https://example.org">{PADDING}</a></div><img src="https://images.example/logo.png">',
                     '<a href="#footer"><img src="https://images.example/logo.png"></a>'+f'<div hidden>{PADDING}</div>',
                     '<img src="https://images.example/photo.png">'+f'<div hidden>{PADDING}</div>',
                     IMAGE+f'<p>{PADDING}</p><div hidden>{PADDING}</div>',
                     f'<div hidden>{IMAGE}{PADDING}</div>',
                     '<a href="mailto:team@example.org"><img src="https://images.example/logo.png"></a>'+f'<div hidden>{PADDING}</div>'):
            with self.subTest(body=body[:80]):
                result, _ = self.analyze(body)
                self.assertFalse(self.flagged(result))
        result, view = self.analyze(IMAGE+f'<div hidden>{PADDING}</div>', 'text/plain')
        self.assertFalse(self.flagged(result))
        self.assertIn('Project resources',view['body'])

    def test_unverified_css_and_nested_anchor_do_not_invent_visible_actions(self):
        for body in (
            '<a href="hxxps://example.org"><img src="https://images.example/a.png"></a>'+f'<div hidden>{PADDING}</div>',
            '<a href="https://#fragment"><img src="https://images.example/a.png"></a>'+f'<div hidden>{PADDING}</div>',
            '<style>img { display:none }</style>'+IMAGE+f'<div hidden>{PADDING}</div>',
            '<a href="https://example.org"><a href="mailto:team@example.org"><img src="https://images.example/a.png"></a></a>'+f'<div hidden>{PADDING}</div>',
            '<a href="https://example.org"><a href="#footer">Text</a><img src="https://images.example/a.png"></a>'+f'<div hidden>{PADDING}</div>',
        ):
            result,_=self.analyze(body)
            self.assertFalse(self.flagged(result))

    def test_padding_threshold_and_rich_text_boundary_are_explicit(self):
        for size, expected in ((499, False), (500, True)):
            result,_=self.analyze(IMAGE+'<div hidden>'+('x'*size)+'</div>')
            self.assertEqual(self.flagged(result),expected)
        result,_=self.analyze(IMAGE+'<p>'+('x'*80)+'</p><div hidden>'+PADDING+'</div>')
        self.assertFalse(self.flagged(result))

    def test_hidden_padding_in_separate_mime_part_is_not_combined_with_image(self):
        result=app.analyze_email_content('', '',content_parts=[
            {'content_type':'text/html','content':IMAGE},
            {'content_type':'text/html','content':f'<div hidden>{PADDING}</div>'}])
        self.assertFalse(self.flagged(result))

    def test_duplicate_attributes_and_visibility_override_use_existing_parser_semantics(self):
        result,_=self.analyze(IMAGE+f'<div style="display:block" style="display:none">{PADDING}</div>')
        self.assertFalse(self.flagged(result))
        result,_=self.analyze(IMAGE+f'<div style="visibility:hidden"><span style="visibility:visible">{PADDING}</span></div>')
        self.assertFalse(self.flagged(result))

if __name__=='__main__': unittest.main()
