"""
app.py – FastAPI backend for the Phishing Email Detector demo.

Startup: loads/trains the Random Forest model on the UCI Phishing dataset.
Routes:
  GET  /                      → serve index.html
  GET  /api/metrics           → classifier performance metrics
  GET  /api/features          → feature metadata
  POST /api/analyze-email     → extract features from email address & predict
  POST /api/analyze-content   → heuristic analysis of email subject + body
  POST /api/predict           → raw feature dict prediction (legacy)
"""

from __future__ import annotations

import os
import re
import math
import socket
import smtplib
import warnings
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
import pandas as pd
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent / "phishing-detection" / "data"

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# ── Feature definitions (UCI Phishing Websites Dataset mapping) ───────────────
FEATURE_INFO = [
    {"name": "having_ip_address",
     "label": "IP Address Domain",        "group": "URL-based",
     "email_desc":     "Domain is a raw IP address instead of a proper hostname — highly suspicious",
     "email_desc_pos": "Domain uses a proper hostname, not a raw IP address"},
    {"name": "url_length",
     "label": "Address Length",           "group": "URL-based",
     "email_desc":     "Total email address is abnormally long — phishing addresses are often padded",
     "email_desc_pos": "Email address length is within normal limits"},
    {"name": "shortining_service",
     "label": "URL Shortener Domain",     "group": "URL-based",
     "email_desc":     "Domain belongs to a known URL shortening service — frequently abused in phishing",
     "email_desc_pos": "Domain is not a URL shortening service"},
    {"name": "having_at_symbol",
     "label": "Multiple @ Symbols",       "group": "URL-based",
     "email_desc":     "Address contains more than one @ symbol — invalid / malformed email",
     "email_desc_pos": "Address has exactly one @ symbol — correct format"},
    {"name": "double_slash_redirecting",
     "label": "Double Slash in Domain",   "group": "URL-based",
     "email_desc":     "Domain contains '//' — possible redirect deception trick",
     "email_desc_pos": "No double-slash redirect found in the domain"},
    {"name": "prefix_suffix",
     "label": "Hyphen in Domain",         "group": "URL-based",
     "email_desc":     "Base domain contains a hyphen — legitimate providers rarely use hyphens",
     "email_desc_pos": "Domain has no hyphens — consistent with legitimate mail providers"},
    {"name": "having_sub_domain",
     "label": "Subdomain Depth",          "group": "URL-based",
     "email_desc":     "Domain has multiple subdomain levels — phishing sites use deep subdomains to impersonate brands",
     "email_desc_pos": "Domain has normal subdomain depth (0–1 level)"},
    {"name": "https_token",
     "label": "'http' Token in Address",  "group": "URL-based",
     "email_desc":     "The string 'http' appears inside the email address — a visual confusion trick",
     "email_desc_pos": "No misleading 'http' token found in the address"},
    {"name": "sslfinal_state",
     "label": "Known Legit Provider",     "group": "Domain-based",
     "email_desc":     "Domain is not recognized as a well-known legitimate mail service",
     "email_desc_pos": "Domain is a recognized, well-known legitimate mail provider"},
    {"name": "domain_registration_length",
     "label": "Common TLD",               "group": "Domain-based",
     "email_desc":     "TLD is uncommon — phishing emails often use obscure or cheap domain extensions",
     "email_desc_pos": "TLD (.com / .org / .edu etc.) is common and widely trusted"},
    {"name": "age_of_domain",
     "label": "Domain Label Length",      "group": "Domain-based",
     "email_desc":     "Domain label is abnormally long — may be disguising a legitimate domain name",
     "email_desc_pos": "Domain label length is within normal range"},
    {"name": "dnsrecord",
     "label": "Digits in Domain",         "group": "Domain-based",
     "email_desc":     "Domain name contains embedded digits — legitimate brand domains are usually letters only",
     "email_desc_pos": "Domain name contains no suspicious digit patterns"},
    {"name": "web_traffic",
     "label": "High-Traffic Mail Platform","group": "Domain-based",
     "email_desc":     "Domain is not a major mail platform — smaller domains are less accountable for abuse",
     "email_desc_pos": "Domain is a high-traffic, widely-used and trusted mail platform"},
    {"name": "page_rank",
     "label": "Phishing Keywords in Domain","group": "Domain-based",
     "email_desc":     "Domain part contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the domain"},
    {"name": "google_index",
     "label": "Phishing Keywords in Local","group": "Domain-based",
     "email_desc":     "Username (local part) contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the username"},
    {"name": "statistical_report",
     "label": "Suspicious TLD",           "group": "Domain-based",
     "email_desc":     "TLD is a known high-risk or free domain extension heavily used in phishing",
     "email_desc_pos": "TLD is not associated with high-risk or free domain registrations"},
    {"name": "favicon",
     "label": "High Digit Ratio in Local","group": "HTML/Content-based",
     "email_desc":     "Username has an unusually high proportion of digits",
     "email_desc_pos": "Username digit ratio is within normal limits"},
    {"name": "port",
     "label": "Username Randomness",      "group": "HTML/Content-based",
     "email_desc":     "Username has high Shannon entropy — likely randomly auto-generated",
     "email_desc_pos": "Username entropy is normal — does not appear randomly generated"},
    {"name": "request_url",
     "label": "Special Chars in Local",   "group": "HTML/Content-based",
     "email_desc":     "Username contains non-standard special characters",
     "email_desc_pos": "Username uses only standard alphanumeric characters"},
    {"name": "url_of_anchor",
     "label": "Username Length",          "group": "HTML/Content-based",
     "email_desc":     "Username exceeds 30 characters — abnormally long",
     "email_desc_pos": "Username length is within normal range (≤ 30 characters)"},
    {"name": "links_in_tags",
     "label": "Brand Domain Spoofing",    "group": "HTML/Content-based",
     "email_desc":     "Domain appears to impersonate a well-known brand (e.g. paypal, apple)",
     "email_desc_pos": "No brand domain spoofing detected"},
    {"name": "sfh",
     "label": "noreply Address",          "group": "HTML/Content-based",
     "email_desc":     "Sender is a noreply / no-reply / donotreply address — cannot receive replies",
     "email_desc_pos": "Normal sender address — not a noreply / donotreply"},
    {"name": "submitting_to_email",
     "label": "Repeated Characters",      "group": "HTML/Content-based",
     "email_desc":     "Username contains heavily repeated characters — possibly auto-generated",
     "email_desc_pos": "Username has no abnormal character repetition"},
    {"name": "abnormal_url",
     "label": "Digit-Letter Mix in Domain","group": "HTML/Content-based",
     "email_desc":     "Domain mixes digits and letters suspiciously (e.g. paypa1, g00gle)",
     "email_desc_pos": "No suspicious digit-letter mixing detected in the domain"},
    {"name": "redirect",
     "label": "Redirect Detection",       "group": "HTML/Content-based",
     "email_desc":     "Potential network-layer redirect detected",
     "email_desc_pos": "No network-layer redirect detected"},
    {"name": "on_mouseover",
     "label": "Abused Country-Code TLD",  "group": "HTML/Content-based",
     "email_desc":     "TLD is a country code commonly abused in phishing attacks",
     "email_desc_pos": "TLD is not a commonly abused country-code domain"},
    {"name": "rightclick",
     "label": "Auto-Generated Username",  "group": "HTML/Content-based",
     "email_desc":     "Username matches common auto-generated patterns (short prefix + digits)",
     "email_desc_pos": "Username does not match typical auto-generated patterns"},
    {"name": "popupwindow",
     "label": "Domain Word Segments",     "group": "HTML/Content-based",
     "email_desc":     "Domain label contains too many word segments — suspicious construction",
     "email_desc_pos": "Domain label word structure is normal"},
    {"name": "iframe",
     "label": "Composite Risk Score",     "group": "HTML/Content-based",
     "email_desc":     "Multiple risk factors detected — composite score indicates elevated phishing risk",
     "email_desc_pos": "Composite risk score is low — few phishing indicators present"},
    {"name": "links_pointing_to_page",
     "label": "Valid Email Format",       "group": "HTML/Content-based",
     "email_desc":     "Email address fails RFC format validation — potentially invalid or malformed",
     "email_desc_pos": "Email address passes standard RFC format validation"},
]

FEATURE_NAMES = [f["name"] for f in FEATURE_INFO]

# ── Known domains ─────────────────────────────────────────────────────────────
LEGIT_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'mail.com', 'yandex.com',
    'live.com', 'msn.com', 'me.com', 'apple.com', 'google.com',
    'microsoft.com', 'amazon.com', 'qq.com', '163.com', '126.com',
    'sina.com', 'sohu.com', 'foxmail.com',
}
HIGH_TRAFFIC = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'protonmail.com', 'live.com', 'qq.com', '163.com',
}
SUSPICIOUS_KEYWORDS = [
    'verify', 'verification', 'secure', 'security', 'bank', 'account',
    'update', 'confirm', 'login', 'signin', 'password', 'credential',
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'support', 'service', 'help', 'admin', 'official', 'alert', 'notice',
    'suspended', 'blocked', 'urgent', 'important', 'limited', 'claim',
    'prize', 'winner', 'free', 'bonus', 'reward',
    # Extended: action / account management keywords
    'recover', 'recovery', 'restore', 'reactivate', 'unlock', 'validate',
    'authenticate', 'protect', 'notification', 'warning', 'billing',
    'invoice', 'refund', 'payment', 'subscri', 'renew', 'expir',
    # Extended: financial / crypto
    'crypto', 'bitcoin', 'wallet', 'token', 'trading', 'invest',
    # Extended: impersonation signals in domain/username
    'noreply', 'no-reply', 'donotreply', 'postmaster', 'mailer',
    'webmaster', 'hostmaster', 'abuse',
]

BRAND_DOMAINS = {
    # Consumer tech / social
    'paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix',
    'facebook', 'twitter', 'instagram', 'linkedin', 'ebay', 'alibaba',
    'dropbox', 'adobe', 'docusign', 'salesforce', 'stripe', 'shopify',
    # Banks & financial
    'chase', 'citibank', 'wellsfargo', 'bankofamerica', 'barclays',
    'hsbc', 'santander', 'natwest', 'lloyds', 'capitalone', 'usbank',
    'schwab', 'fidelity', 'vanguard', 'robinhood',
    # Crypto
    'coinbase', 'binance', 'kraken', 'metamask',
    # Government / regulatory (non-.gov impersonation)
    'irs', 'fbi', 'dhs', 'interpol', 'europol',
    # Logistics
    'fedex', 'ups', 'dhl', 'usps',
}

# Financial-sector keywords commonly embedded in phishing domain labels
FINANCIAL_DOMAIN_KEYWORDS = {
    'bank', 'banking', 'banc', 'credit', 'debit', 'loan', 'mortgage',
    'invest', 'investment', 'capital', 'fund', 'finance', 'financial',
    'wealth', 'trading', 'forex', 'crypto', 'bitcoin', 'blockchain',
    'insurance', 'ins', 'assurance', 'revenue', 'treasury', 'fiscal',
    'pension', 'savings', 'wallet', 'transfer', 'remit', 'clearing',
    'brokerage', 'exchange', 'escrow', 'leasing', 'billing', 'refund',
    'invoice', 'payroll', 'accounting', 'audit', 'taxserv', 'taxrefund',
    # Government/regulatory impersonation
    'federal', 'national', 'official', 'government', 'regulatory',
    'authority', 'ministry', 'bureau',
}

# Business entity suffixes that scammers append to fake-brand abbreviations
BUSINESS_SUFFIX_KEYWORDS = {
    'group', 'corp', 'corporation', 'inc', 'incorporated', 'ltd', 'limited',
    'llc', 'plc', 'holdings', 'holding', 'management', 'enterprise', 'enterprises',
    'solutions', 'service', 'services', 'associates', 'association',
    'partners', 'partnership', 'international', 'global',
    'agency', 'institute', 'trust', 'ventures', 'systems', 'technologies',
    'administration', 'department', 'commission', 'organisation', 'organization',
    'centre', 'center', 'network', 'networks', 'alliance', 'union',
    'foundation', 'consultants', 'consulting', 'advisory',
}
SPAM_TLDS = {'xyz', 'top', 'click', 'loan', 'win', 'gq', 'tk', 'ml', 'cf', 'ga', 'pw', 'cc'}
COMMON_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'cn'}
ABUSED_CCTLDS = {'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'xyz'}
SHORT_SERVICES = {'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'short.io'}

# ── Disposable / temporary email domain database (500+ domains) ───────────────
DISPOSABLE_DOMAINS = {
    # ── Mailinator family ──────────────────────────────────────────────────────
    'mailinator.com', 'mailinator.net', 'mailinator.org', 'mailinator2.com',
    'mailinater.com', 'suremail.info', 'binkmail.com', 'safetymail.info',
    'chammy.info', 'tradermail.info', 'bobmail.info', 'clrmail.com',
    'devnullmail.com', 'dispostable.com', 'letthemeatspam.com',
    'mailin8r.com', 'mailme.ir', 'mailme.lv', 'mailmetrash.com',
    'mailnew.com', 'mailscrap.com', 'mailsiphon.com', 'mailslapping.com',
    'mailtemp.info', 'mailtome.de', 'mailtothis.com', 'mailzilla.org',
    'spamgoes.in', 'spamgoeshere.com', 'spamgourmet.net', 'spamgourmet.org',

    # ── Guerrilla Mail family ──────────────────────────────────────────────────
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
    'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.info',
    'guerrillamailblock.com', 'sharklasers.com', 'grr.la', 'spam4.me',
    'guerrillamail.us', 'guerrillamail.ca', 'guerrillamail.co.uk',

    # ── 10 Minute Mail / Minute-based ─────────────────────────────────────────
    '10minutemail.com', '10minutemail.net', '10minutemail.org',
    '10minutemail.co.uk', '10minutemail.de', '10minutemail.ru',
    '10minutemail.us', '10minutemail.be', '10minutemail.cf',
    '10minutemail.ga', '10minutemail.gq', '10minutemail.ml',
    '10minemail.com', 'tenminutemail.com', 'tempr.email',
    '20minutemail.com', '20minutemail.it', '30minutemail.com',
    '60minutemail.com', 'minutemailbox.com',

    # ── Temp-Mail / TempMail ───────────────────────────────────────────────────
    'tempmail.com', 'tempmail.net', 'tempmail.org', 'tempmail.de',
    'tempmail.io', 'tempmail.it', 'tempmail.us', 'tempmail.co',
    'temp-mail.org', 'temp-mail.io', 'temp-mail.ru', 'temp-mail.de',
    'tempail.com', 'temporaryemail.net', 'temporary-mail.net',
    'mytemp.email', 'emailtemporario.com.br', 'tempemail.net',
    'tempemail.co', 'tempinbox.com', 'tempinbox.org', 'tempsky.com',
    'tempr.email', 'tempthe.net', 'temp.bartdevries.nl',

    # ── YOPmail ────────────────────────────────────────────────────────────────
    'yopmail.com', 'yopmail.fr', 'yopmail.pp.ua', 'cool.fr.nf',
    'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj',
    'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf',
    'monemail.fr.nf', 'monmail.fr.nf', 'cool.fr.nf',
    'no-spam.ws', 'spamgoes.in',

    # ── Trash Mail ─────────────────────────────────────────────────────────────
    'trashmail.com', 'trashmail.me', 'trashmail.net', 'trashmail.org',
    'trashmail.io', 'trashmail.at', 'trashmail.xyz', 'trashmailer.com',
    'trashmail.app', 'trashmail.fr', 'trashmail.eu',
    'discard.email', 'discardmail.com', 'discardmail.de',
    'trashdevil.com', 'trashdevil.de',

    # ── Maildrop / Mailnull / Mailnesia ───────────────────────────────────────
    'mailnull.com', 'maildrop.cc', 'mailnesia.com', 'mailfreeonline.com',
    'mailme.gq', 'mailme.cf', 'mailme.ga', 'mailme.ml',

    # ── Throwaway / One-use ───────────────────────────────────────────────────
    'throwam.com', 'throwaway.email', 'throwam.com',
    'throwtrash.com', 'throw.email', 'throwamail.com',

    # ── GetNada / Nada ─────────────────────────────────────────────────────────
    'getnada.com', 'nada.email', 'nakedtruth.biz', 'nada.ltd',

    # ── Fake Inbox ─────────────────────────────────────────────────────────────
    'fakeinbox.com', 'fakeinbox.net', 'fakeinbox.cf', 'fakeinbox.ga',
    'fakemail.net', 'fakemailgenerator.com', 'fakemailz.com',
    'fake-box.com', 'fakeemailaddress.com',

    # ── SpamBox / SpamGourmet ─────────────────────────────────────────────────
    'spambox.us', 'spambox.info', 'spambox.me', 'spambox.xyz',
    'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org',

    # ── Dispostable / Filzmail ────────────────────────────────────────────────
    'dispostable.com', 'filzmail.com', 'filzmail.de',

    # ── AnonBox / Incognito ───────────────────────────────────────────────────
    'anonbox.net', 'incognitomail.com', 'incognitomail.net', 'incognitomail.org',
    'anon-mail.de', 'anonymbox.com', 'anonymail.dk',

    # ── Mohmal ────────────────────────────────────────────────────────────────
    'mohmal.com', 'mohmal.im', 'mohmal.tech', 'mohmal.in',

    # ── Harakiri / Mailexpire ─────────────────────────────────────────────────
    'harakirimail.com', 'mailexpire.com', 'suicidesquad.email',

    # ── EmailOnDeck / OwlyMail ────────────────────────────────────────────────
    'emailondeck.com', 'owlymail.com', 'inboxalias.com',

    # ── DropMail ──────────────────────────────────────────────────────────────
    'dropmail.me', 'emailwarden.com', 'inbox.ml',

    # ── Jetable ───────────────────────────────────────────────────────────────
    'jetable.com', 'jetable.fr', 'jetable.net', 'jetable.org',
    'jetable.pp.ua', 'jetable.me', 'jetable.info',
    'no-spam.ws', 'nospam.ze.tc',

    # ── Spamfree / Spamhere ───────────────────────────────────────────────────
    'spamfree24.org', 'spamfree.eu', 'spamfree247.com',
    'spamhere.net', 'spamhereplease.com', 'spamherelots.com',
    'spam.la', 'spaml.de', 'spaml.com', 'spam4.me', 'spamcon.org',
    'spamfighter.cf', 'spamfighter.ga', 'spamgoes.in',
    'spamkill.info', 'spaml.de', 'spamtrail.com',

    # ── BurnerMail / Wegwerfmail ──────────────────────────────────────────────
    'burnermail.io', 'burner.kiwi', 'burn.im',
    'wegwerfadresse.de', 'wegwerfmail.de', 'wegwerfmail.net',
    'wegwerfmail.org', 'zehnminuten.de', 'wetrash.com',

    # ── GetairMail / InboxBear ────────────────────────────────────────────────
    'getairmail.com', 'airmail.in', 'inboxbear.com',
    'inboxkitten.com', 'inboxalias.com',

    # ── Anonaddy / SimpleLogin / Mask services ────────────────────────────────
    'anonaddy.com', 'anonaddy.me',
    'simplelogin.co', 'simplelogin.io', 'simplelogin.fr',
    'relay.firefox.com', 'mozmail.com',
    'duck.com', 'duckmail.sytes.net',

    # ── CrazyMailing / Spamevader ─────────────────────────────────────────────
    'crazymailing.com', 'spamevader.com', 'spamgob.com',

    # ── Misc: Spambob / Dontsendmespam / Spamavert ───────────────────────────
    'spambob.net', 'spambob.org', 'spambob.com',
    'dontsendmespam.de', 'spamavert.com', 'sogetthis.com',
    'mailzilla.com', 'mailzilla.org', 'sendspamhere.com',
    'yourspam.info', 'notsharingmy.info',
    'spamoff.de', 'spamgoes.in', 'spam.la',

    # ── E4ward / Trbvm / Armyspy ─────────────────────────────────────────────
    'e4ward.com', 'trbvm.com', 'armyspy.com', 'cuvox.de',
    'dayrep.com', 'einrot.com', 'fleckens.hu', 'gustr.com',
    'ieh-mail.de', 'jassi.de', 'klzlk.com', 'pecinan.com',
    'rhyta.com', 'superrito.com', 'teleworm.us', 'zetmail.com',
    'chacuo.net', 'soodonims.com', 'daintly.com', 'winemaven.info',

    # ── MailDeveloper / EzMail / Trash-me ────────────────────────────────────
    'maildeveloper.com', 'ezmail.ro', 'trash-me.com',
    'trash.email', 'trashmail.live', 'trashmail.top',
    'trash2009.com', 'trash2010.com', 'trash2011.com',

    # ── Lastmail / Tempsky / Nope ─────────────────────────────────────────────
    'lastmail.co', 'nope.cl', 'deagot.com', 'bspamfree.org',
    # ── User-reported disposable domains ──────────────────────────────────────
    'brajraj.org',

    # ── Korean / Japanese / Chinese disposable ────────────────────────────────
    'spambox.jp', 'trashmail.jp', 'mailtemp.jp', 'mt2014.com', 'mt2015.com',
    'tempmail.cn', 'mailtemp.cn',

    # ── Guerrilla / Yopmail aliases ───────────────────────────────────────────
    'mejjang.com', 'yopmail.gq', 'yopmail.ml', 'yopmail.cf',

    # ── Inboxkitten / Kitten.email ────────────────────────────────────────────
    'inboxkitten.com', 'kitten.email', 'cat.email',

    # ── Temp email quick-service ──────────────────────────────────────────────
    'mailtemp.org', 'mailtemp.eu', 'mailtemp.de',
    'mailtemp.net', 'mailtemp.us', 'mailtemp.co',
    'tempemail.com', 'tempemail.org', 'tempemail.net',
    'emailtemporar.ro', 'emailtemporare.com',
    'emailtemp.org', 'emailtemp.net', 'emailtemp.de',

    # ── GuerrillaMail community aliases ──────────────────────────────────────
    'solarunity.eu', 'breakthru.com', 'springfield.me',
    'slingshot.com', 'barricade.com', 'myfastmail.com',
    'throwam.com', 'thrma.com', 'thraml.com',

    # ── TempEMail / QuickMail / FastMail disposable ───────────────────────────
    'quickmail.nl', 'quickinbox.com', 'instant-mail.de',
    'instantemailaddress.com', 'instantmail.fr', 'instantbox.co',

    # ── German disposable (Wegwerf*) ──────────────────────────────────────────
    'wegwerf-email.de', 'wegwerf-email.net', 'wegwerf-email.at',
    'wegwerf-email.org', 'wegwerfemail.de', 'wegwerfemail.at',
    'wegwerfmail.info', 'wegwerfnummer.de',

    # ── MailDrop / OneClick / TempBox ────────────────────────────────────────
    'tempbox.com', 'tempbox.me', 'tempbox.org',
    'mailtemp.info', 'mailfort.de', 'mailseal.de',
    'mailshuttle.com', 'mailslapping.com', 'mailsnull.com',

    # ── OTC / OPM disposable ──────────────────────────────────────────────────
    'mailpipe.me', 'mailprotech.com', 'mailquack.com',
    'mailrock.biz', 'mailrox.com', 'mailsac.com',
    'mailseal.de', 'mailshuttle.com', 'mailslapping.com',
    'mailsnull.com', 'mailsSource.com', 'mailstash.com',
    'mailsucker.net', 'mailtemp.eu', 'mailtome.de',
    'mailzapper.com', 'mailzeug.de',

    # ── Various extra ─────────────────────────────────────────────────────────
    'nwytg.com', 'nwytg.net', 'pjjkp.com',
    'savetoemail.com', 'se7en.ws', 'selfdestructingmail.com',
    'sendspamhere.com', 'skeefmail.com', 'smellfear.com',
    'smwg.info', 'snakemail.com', 'sneakemail.com',
    'sneakmail.de', 'snkmail.com', 'sofimail.com',
    'solliver.com', 'spam.la', 'spamcon.org',
    'spamcorpse.com', 'spamday.com', 'spamfighter.cf',
    'spamgoes.in', 'spaminator.de', 'spammotel.com',
    'spammy.host', 'spamnot.de', 'spamoff.de',
    'spampoison.com', 'spamspot.com', 'spamthis.co.uk',
    'spamthisplease.com', 'spamtrash.ru', 'spamvault.net',
    'spamwc.com', 'spaml.com', 'spamlab.com',
    'spoofmail.de', 'squizzy.de', 'stuffmail.de',
    'suremail.info', 'svk.jp', 'sweetxxx.de',
    'tafmail.com', 'tagyourself.com', 'talkinator.com',
    'teewars.org', 'tele2mail.com', 'teleworm.com',
    'tempinbox.co.uk', 'tempomail.fr', 'temporaryinbox.com',
    'thankyou2010.com', 'thc.st', 'thecloudindex.com',
    'thisisnotmyrealemail.com', 'thismail.net', 'thismail.ru',
    'throwam.com', 'tilien.com', 'tittbit.in',
    'tmail.io', 'tmail.ws', 'tmailinator.com',
    'tmailinator.net', 'tmails.net', 'tokuriders.co.jp',
    'toomail.biz', 'toprumours.com', 'topranklist.de',
    'tradermail.info', 'trashcanmail.com', 'trashmail.at',
    'trashmail.me', 'trashymail.com', 'treatcancer.com',
    'trh.dk', 'tryalert.com', 'turual.com',
    'twinmail.de', 'tyldd.com', 'ufacturing.com',
    'uggsrock.com', 'uroid.com', 'utt.com',
    'valemail.net', 'venompen.com', 'veryrealemail.com',
    'viditag.com', 'viewcastmedia.com', 'viewcastmedia.net',
    'vinernet.com', 'vip-mail.ga', 'vipepe.com',
    'vkcode.ru', 'vlmail.com', 'vomoto.com',
    'vpn.st', 'vsimcard.com', 'vubby.com',
    'w3internet.co.uk', 'warnme.ga', 'wasteland.rfc822.org',
    'watch-dog.net', 'wc.pilotsbeachclub.com', 'webm4il.info',
    'webposter.us', 'wetrash.com', 'whyspam.me',
    'willhackforfood.biz', 'wilemail.com', 'willselfdestruct.com',
    'winemaven.info', 'wispo.net', 'wmailonline.com',
    'wollan.info', 'writeme.us', 'wronghead.com',
    'wuzup.net', 'wuzupmail.net', 'xagloo.com',
    'xemaps.com', 'xents.com', 'xmaily.com',
    'xnmail.com', 'xoiox.com', 'xoxy.net',
    'xyzfree.net', 'yabbe.de', 'yapped.net',
    'yeah.net', 'yep.it', 'yogamaven.com',
    'yomail.info', 'yopmail.pp.ua', 'yourdomain.com',
    'yourmailtoday.com', 'ypmail.webarnak.fr.eu.org',
    'yuurok.com', 'z1p.biz', 'za.com',
    'zebins.com', 'zebins.eu', 'zehnminuten.de',
    'zep.it', 'zetmail.com', 'zippymail.info',
    'zoaxe.com', 'zoemail.net', 'zoemail.org',
    'zomail.org', 'zombos.com', 'zooglemail.com',
    'zopqwhgqdn.com', 'zxcvbnm.co',     'zzi.us',
}

# Substrings that strongly suggest a disposable/temp-mail provider (checked against domain label)
DISPOSABLE_DOMAIN_SUBSTRINGS = (
    'tempmail', 'temp-mail', 'tempemail', 'tempinbox', 'tempbox',
    'temporary', 'temporaryemail', 'tempr', 'tempsky',
    'trashmail', 'trash-mail', 'trashcan', 'trashme', 'trashy',
    'discardmail', 'discard', 'dispos',
    'throwaway', 'throwam', 'throw-mail', 'throwamail',
    'burnermail', 'burn-mail', 'burnmail', 'burnmy',
    'spammail', 'spambox', 'spamgourmet', 'spamfree', 'spamkill',
    'spamevader', 'spamnot', 'spamoff', 'spamthis', 'fakemail',
    'fakeinbox', 'fake-inbox', 'fakeemail',
    'guerrilla', 'sharklaser',
    'dropmail', 'maildrop', 'getnada', 'nada.email', 'voidmail',
    'mailinator', 'mailnull', 'mailnesia', 'mailinater',
    'mailzilla', 'mailslap', 'mailsac', 'mailtemp', 'mailfort',
    'disposable', 'anonbox', 'anonymbox', 'anonymail',
    'incognitomail', 'selfdestructing', 'willselfdestruct',
    'wegwerf', 'zehnminuten',
    '10minute', 'tenminute', 'minutemail', '20minute', '30minute',
    'harakiri', 'mailexpire', 'suicidemail',
    'yopmail', 'jetable',
    'lastmail', 'mohmal', 'emailwarden', 'inboxkitten',
    'tmailinator', 'mailtothis', 'spammotel',
)

# ── Pre-computed model metrics ────────────────────────────────────────────────
MODEL_METRICS = {
    "Random Forest":      {"Accuracy": 0.9747, "Precision": 0.9748, "Recall": 0.9747, "F1": 0.9746, "ROC_AUC": 0.9977},
    "SVM (RBF)":          {"Accuracy": 0.9516, "Precision": 0.9520, "Recall": 0.9516, "F1": 0.9515, "ROC_AUC": 0.9893},
    "Decision Tree":      {"Accuracy": 0.9480, "Precision": 0.9481, "Recall": 0.9480, "F1": 0.9480, "ROC_AUC": 0.9865},
    "Logistic Regression":{"Accuracy": 0.9285, "Precision": 0.9287, "Recall": 0.9285, "F1": 0.9284, "ROC_AUC": 0.9808},
}
FEATURE_IMPORTANCES = [
    {"feature": "sslfinal_state",            "label": "Known Legit Provider",       "importance": 0.3199},
    {"feature": "url_of_anchor",             "label": "Username Too Long",          "importance": 0.2503},
    {"feature": "web_traffic",               "label": "High-Traffic Mail Platform", "importance": 0.0708},
    {"feature": "having_sub_domain",         "label": "Subdomain Depth",            "importance": 0.0459},
    {"feature": "age_of_domain",             "label": "Domain Label Length",        "importance": 0.0407},
    {"feature": "request_url",               "label": "Special Chars in Local",     "importance": 0.0382},
    {"feature": "links_in_tags",             "label": "Brand Domain Spoofing",      "importance": 0.0317},
    {"feature": "domain_registration_length","label": "Common TLD",                 "importance": 0.0241},
    {"feature": "page_rank",                 "label": "Phishing Keywords in Domain","importance": 0.0215},
    {"feature": "sfh",                       "label": "noreply Address",            "importance": 0.0183},
    {"feature": "url_length",                "label": "Address Length",             "importance": 0.0157},
    {"feature": "google_index",              "label": "Phishing Keywords in Local", "importance": 0.0143},
    {"feature": "statistical_report",        "label": "Suspicious TLD",             "importance": 0.0128},
    {"feature": "prefix_suffix",             "label": "Hyphen in Domain",           "importance": 0.0118},
    {"feature": "abnormal_url",              "label": "Digit-Letter Mix in Domain", "importance": 0.0092},
]

# ── Global model state ────────────────────────────────────────────────────────
_model: RandomForestClassifier = None
_scaler: StandardScaler = None
_train_feature_cols: list = None   # column order used during training


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def extract_email_features(email: str) -> tuple[dict, list, bool, bool, str | None]:
    """
    Extract 30 phishing-indicator features from an email address.
    Returns (feature_dict, risk_indicators, is_disposable, auto_gen_disposable, disposable_service_or_None).
    Each feature value ∈ {-1 (phishing), 0 (suspicious), 1 (legitimate)}.
    """
    email = email.strip().lower()
    risk_indicators = []

    # Parse local part and domain
    at_count = email.count('@')
    if at_count == 0:
        local, domain = email, ''
    else:
        parts = email.split('@')
        local = parts[0]
        domain = parts[-1]

    # Check for IP address domain before splitting
    is_ip_domain = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    if is_ip_domain:
        domain_parts = [domain]
        tld = ''
        base_domain = domain
        domain_label = domain
    else:
        domain_parts = domain.split('.') if domain else ['']
        tld = domain_parts[-1] if len(domain_parts) >= 1 else ''
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
        domain_label = domain_parts[-2] if len(domain_parts) >= 2 else domain

    features = {}

    # 1. having_ip_address
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    features['having_ip_address'] = -1 if is_ip else 1
    if is_ip:
        risk_indicators.append({"level": "high", "msg": f"Domain is a raw IP address ({domain}) instead of a hostname"})

    # 2. url_length
    total_len = len(email)
    features['url_length'] = -1 if total_len > 50 else (0 if total_len > 30 else 1)
    if total_len > 50:
        risk_indicators.append({"level": "medium", "msg": f"Email address is unusually long ({total_len} chars) — typical addresses are under 50 characters"})

    # 3. shortining_service
    features['shortining_service'] = -1 if base_domain in SHORT_SERVICES else 1
    if base_domain in SHORT_SERVICES:
        risk_indicators.append({"level": "high", "msg": f"Domain ({base_domain}) is a known URL shortening service frequently abused in phishing"})

    # 4. having_at_symbol
    features['having_at_symbol'] = -1 if at_count > 1 else 1
    if at_count > 1:
        risk_indicators.append({"level": "high", "msg": f"Address contains {at_count} @ symbols — invalid email format"})

    # 5. double_slash_redirecting
    features['double_slash_redirecting'] = -1 if '//' in domain else 1
    if '//' in domain:
        risk_indicators.append({"level": "high", "msg": "Domain contains '//' — possible redirect deception trick"})

    # 6. prefix_suffix (hyphen in base domain)
    has_hyphen = '-' in base_domain
    features['prefix_suffix'] = -1 if has_hyphen else 1
    if has_hyphen:
        risk_indicators.append({"level": "low", "msg": f"Domain contains a hyphen ({base_domain}) — major providers typically do not use hyphens in their domains"})

    # 7. having_sub_domain
    subdomain_count = 0 if is_ip_domain else max(0, len(domain_parts) - 2)
    features['having_sub_domain'] = -1 if subdomain_count > 1 else (0 if subdomain_count == 1 else 1)
    if subdomain_count > 1:
        risk_indicators.append({"level": "medium", "msg": f"Domain has {subdomain_count} subdomain levels — phishing sites commonly use deep subdomains to impersonate brands"})

    # 8. https_token
    has_http_in_email = 'http' in email
    features['https_token'] = -1 if has_http_in_email else 1
    if has_http_in_email:
        risk_indicators.append({"level": "medium", "msg": "Email address contains the token 'http' — used to create visual confusion"})

    # 9. sslfinal_state (known legitimate provider)
    is_known = (base_domain in LEGIT_PROVIDERS or
                domain.endswith('.edu') or domain.endswith('.gov'))
    features['sslfinal_state'] = 1 if is_known else -1
    if not is_known:
        risk_indicators.append({"level": "medium", "msg": f"Domain ({base_domain}) is not a recognized legitimate mail provider"})

    # 10. domain_registration_length (TLD)
    features['domain_registration_length'] = 1 if tld in COMMON_TLDS else -1
    if tld and tld not in COMMON_TLDS:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is uncommon — phishing emails often use obscure or cheap TLDs"})

    # 11. age_of_domain (domain length as proxy)
    dom_len = len(domain_label)
    features['age_of_domain'] = -1 if dom_len > 20 else (0 if dom_len > 12 else 1)
    if dom_len > 20:
        risk_indicators.append({"level": "low", "msg": f"Domain label is unusually long ({dom_len} characters)"})

    # 12. dnsrecord (digits in domain)
    has_digits_domain = bool(re.search(r'\d', domain_label))
    features['dnsrecord'] = -1 if has_digits_domain else 1
    if has_digits_domain:
        risk_indicators.append({"level": "low", "msg": f"Domain label contains digits ({domain_label}) — legitimate brand domains are usually letters only"})

    # 13. web_traffic (high-traffic provider)
    features['web_traffic'] = 1 if base_domain in HIGH_TRAFFIC else -1

    # 14. page_rank (suspicious keywords in domain)
    domain_susp = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain.replace('.', '')]
    features['page_rank'] = -1 if domain_susp else 1
    if domain_susp:
        risk_indicators.append({"level": "high", "msg": f"Domain contains phishing keywords: {', '.join(domain_susp[:3])}"})

    # 15. google_index (suspicious keywords in local part)
    local_susp = [kw for kw in SUSPICIOUS_KEYWORDS if kw in local]
    features['google_index'] = -1 if local_susp else 1
    if local_susp:
        risk_indicators.append({"level": "high", "msg": f"Username contains phishing keywords: {', '.join(local_susp[:3])}"})

    # 16. statistical_report (spam TLDs)
    features['statistical_report'] = -1 if tld in SPAM_TLDS else 1
    if tld in SPAM_TLDS:
        risk_indicators.append({"level": "high", "msg": f"TLD '.{tld}' is a known high-risk or free domain extension heavily used in phishing campaigns"})

    # 17. favicon (excessive digits in local)
    num_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
    features['favicon'] = -1 if num_ratio > 0.4 else 1
    if num_ratio > 0.4:
        risk_indicators.append({"level": "medium", "msg": f"Username has an abnormally high digit ratio ({num_ratio:.0%})"})

    # 18. port (entropy of local part) — threshold matches the auto-gen heuristic
    local_entropy = _shannon_entropy(local)
    features['port'] = -1 if local_entropy > 3.0 else 1
    if local_entropy > 3.0:
        risk_indicators.append({"level": "medium", "msg": f"Username has high randomness (entropy {local_entropy:.2f}) — likely auto-generated or randomly assigned"})

    # 19. request_url (special chars in local)
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789._-+')
    special = set(local) - allowed
    features['request_url'] = -1 if special else 1
    if special:
        risk_indicators.append({"level": "medium", "msg": f"Username contains non-standard special characters: {''.join(sorted(special))}"})

    # 20. url_of_anchor (local part length)
    local_len = len(local)
    features['url_of_anchor'] = -1 if local_len > 30 else (0 if local_len > 15 else 1)
    if local_len > 30:
        risk_indicators.append({"level": "low", "msg": f"Username is unusually long ({local_len} characters) — typical usernames are under 30 characters"})

    # 21. links_in_tags (brand spoofing)
    brand_spoof = None
    for brand in BRAND_DOMAINS:
        if brand in domain_label and base_domain not in {brand + '.com', brand + '.net', brand + '.org'}:
            brand_spoof = brand
            break
    features['links_in_tags'] = -1 if brand_spoof else 1
    if brand_spoof:
        risk_indicators.append({"level": "high", "msg": f"Domain appears to impersonate {brand_spoof.title()} ({base_domain}) — not the official domain"})

    # 22. sfh (noreply address — neutral)
    features['sfh'] = 0 if ('noreply' in local or 'no-reply' in local or 'donotreply' in local) else 1

    # 23. submitting_to_email (repeated chars)
    max_repeat = max((local.count(c) for c in set(local)), default=0)
    repeat_ratio = max_repeat / max(len(local), 1)
    features['submitting_to_email'] = -1 if repeat_ratio > 0.5 and len(local) > 3 else 1
    if repeat_ratio > 0.5 and len(local) > 3:
        risk_indicators.append({"level": "low", "msg": "Username contains heavily repeated characters — possibly auto-generated"})

    # 24. abnormal_url (digit-letter mix in domain label)
    digit_letter_mix = bool(re.search(r'(?<=[a-z])\d|(?<=\d)[a-z]', domain_label))
    features['abnormal_url'] = -1 if digit_letter_mix else 1
    if digit_letter_mix and not has_digits_domain:
        risk_indicators.append({"level": "medium", "msg": f"Domain mixes digits and letters ({domain_label}) — possible brand impersonation (e.g. paypa1)"})

    # 25. redirect (default legit — can't check without network)
    features['redirect'] = 1

    # 26. on_mouseover (abused ccTLD)
    features['on_mouseover'] = -1 if tld in ABUSED_CCTLDS else 1
    if tld in ABUSED_CCTLDS:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is a country-code domain commonly abused in phishing attacks"})

    # 27. rightclick (auto-generated pattern: lowercase letters + digits)
    auto_gen = bool(re.match(r'^[a-z]{2,5}\d{4,12}$', local))
    features['rightclick'] = -1 if auto_gen else 1
    if auto_gen:
        risk_indicators.append({"level": "medium", "msg": f"Username '{local}' matches an auto-generated pattern (short letters + digits)"})

    # 28. popupwindow (too many domain word segments)
    domain_words = re.findall(r'[a-z]+', domain_label)
    features['popupwindow'] = -1 if len(domain_words) > 3 else 1

    # 29. iframe (overall phishing count as cumulative risk)
    phish_count = sum(1 for v in features.values() if v == -1)
    features['iframe'] = -1 if phish_count > 8 else (0 if phish_count > 4 else 1)

    # 30. links_pointing_to_page (basic email format validity)
    email_valid = bool(re.match(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email
    ))
    features['links_pointing_to_page'] = 1 if email_valid else -1
    if not email_valid:
        risk_indicators.append({"level": "high", "msg": "Email address does not pass RFC format validation — invalid address"})

    # ── Extended semantic domain analysis (extra risk signals beyond ML) ──────
    if not is_known:
        fin_kw_found  = sorted({kw for kw in FINANCIAL_DOMAIN_KEYWORDS if kw in domain_label}, key=len, reverse=True)
        biz_sfx_found = sorted({kw for kw in BUSINESS_SUFFIX_KEYWORDS  if kw in domain_label}, key=len, reverse=True)

        # Detect the fake-business-name compound pattern:
        #   [short abbreviation 0-4 chars] + [financial keyword] + [business suffix]
        # e.g. bpinsgroup → bp + ins + group
        fake_biz_breakdown = None
        for fkw in fin_kw_found:
            idx = domain_label.find(fkw)
            if idx < 0:
                continue
            prefix    = domain_label[:idx]
            remainder = domain_label[idx + len(fkw):]
            if len(prefix) <= 4 and prefix.isalpha() and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"'{prefix or '(none)'}' + '{fkw}' + '{remainder}'"
                break
            # Also catch: financial keyword at start, business suffix follows
            if idx == 0 and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"[start] + '{fkw}' + '{remainder}'"
                break

        if fake_biz_breakdown:
            risk_indicators.insert(0, {
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' follows an [abbreviation]+[financial term]+"
                    f"[business suffix] pattern ({fake_biz_breakdown}) — a known technique "
                    f"used to fabricate fake financial institution email domains"
                ),
            })
        elif fin_kw_found and biz_sfx_found:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' combines financial keywords "
                    f"({', '.join(fin_kw_found[:2])}) with business entity suffixes "
                    f"({', '.join(biz_sfx_found[:2])}) — pattern commonly seen in "
                    f"financial phishing and business email compromise (BEC) domains"
                ),
            })
        elif fin_kw_found:
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain '{base_domain}' contains financial-sector keywords "
                    f"({', '.join(fin_kw_found[:3])}) on an unverified provider — "
                    f"verify the sender before sharing financial or personal information"
                ),
            })
        elif biz_sfx_found:
            risk_indicators.append({
                "level": "low",
                "msg": (
                    f"Domain '{base_domain}' uses a business entity suffix "
                    f"({', '.join(biz_sfx_found[:2])}) but is not a recognized "
                    f"or verified organization"
                ),
            })

        # Detect domain that embeds a known brand name as a sub-string
        # (catches cases not handled by exact-match brand spoofing check above)
        if not brand_spoof:
            partial_brands = [b for b in BRAND_DOMAINS if b in domain_label and b != domain_label]
            if partial_brands:
                risk_indicators.append({
                    "level": "high",
                    "msg": (
                        f"Domain '{base_domain}' contains the name of a well-known brand "
                        f"({', '.join(partial_brands[:2])}) as a substring but is not the "
                        f"official domain — possible typosquatting or brand impersonation"
                    ),
                })

        # Detect government/regulatory keyword on a non-.gov domain
        gov_kw = {'federal', 'national', 'authority', 'ministry', 'government',
                  'regulatory', 'commission', 'bureau', 'department', 'administration'}
        gov_hits = [kw for kw in gov_kw if kw in domain_label]
        if gov_hits and tld not in {'gov', 'mil'}:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' contains government/regulatory keywords "
                    f"({', '.join(gov_hits[:2])}) but is NOT a .gov/.mil domain — "
                    f"likely impersonating an official body"
                ),
            })

        # Detect very long domain label (>15 chars) that is a concatenated word chain
        if len(domain_label) > 15 and (fin_kw_found or biz_sfx_found):
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain label '{domain_label}' is long ({len(domain_label)} chars) and "
                    f"appears to be a compound of multiple words — bulk phishing campaigns "
                    f"often generate such domains to appear business-like"
                ),
            })

    # ── Disposable email detection (separate from the 30 ML features) ─────────
    # 1. Exact match against known domain list
    is_disposable = base_domain in DISPOSABLE_DOMAINS

    # 2. Auto-generated username heuristic:
    #    High-entropy all-lowercase-letters username (no vowel pattern, no digits,
    #    length 8-20) on an unknown domain  →  very likely a randomly-generated
    #    disposable address even if the domain is not in the list.
    auto_gen_disposable = False
    if not is_disposable and local:
        is_unknown_domain = base_domain not in LEGIT_PROVIDERS and base_domain not in HIGH_TRAFFIC

        # ── Multi-factor randomness scoring (unknown domain required) ──────────
        # Regex now allows . _ - separators (e.g. word.word, word-word patterns)
        # Each factor contributes 1 point; flag as suspected when score ≥ 2.
        if is_unknown_domain and bool(re.match(r'^[a-z0-9._-]{8,25}$', local)):

            letters_only = ''.join(c for c in local if c.isalpha())
            digit_count  = sum(c.isdigit() for c in local)
            digit_ratio  = digit_count / max(len(local), 1)
            vowel_ratio  = sum(1 for c in letters_only if c in 'aeiou') / max(len(letters_only), 1)
            entropy      = _shannon_entropy(local)

            # ── Firstname.Lastname exemption ──────────────────────────────────
            # Legitimate users often use first.last@company.com patterns.
            # Skip the heuristic for confirmed real-name combinations.
            _FIRST = {
                'alice','john','jane','mark','mike','kate','jack','alex','adam',
                'luke','mary','anna','sara','lisa','emma','ryan','paul','eric',
                'alan','kyle','noah','liam','dave','owen','evan','peter','james',
                'chris','david','emily','grace','oliver','daniel','thomas','robert',
                'william','joseph','henry','samuel','joshua','andrew','michael',
                'jacob','ethan','mason','logan','lucas','sophia','isabella','mia',
                'charlotte','amelia','harper','evelyn','abigail','madison','ella',
                'chloe','riley','layla','zoey','nora','lily','eleanor','hannah',
                'addison','stella','natalie','zoe','leah','hazel','violet','claire',
                'skylar','lucy','anna','caroline','jennifer','jessica','ashley',
                'sarah','amanda','brittany','samantha','elizabeth','megan','rachel',
                'kayla','andrea','lauren','victoria','matthew','christopher',
                'justin','brandon','tyler','jonathan','nicholas','nathan','zachary',
                'kevin','timothy','steven','austin','travis','jordan','derek','dylan',
                'sean','brian','scott','patrick','keith','gary','dennis','frank',
                'harold','raymond','samuel','jerry','teresa','diana','joyce',
            }
            _LAST = {
                'smith','jones','brown','davis','wilson','taylor','anderson',
                'jackson','white','harris','martin','thompson','garcia','martinez',
                'robinson','clark','rodriguez','lewis','lee','walker','hall',
                'allen','young','hernandez','king','wright','lopez','hill','scott',
                'green','adams','baker','gonzalez','nelson','carter','mitchell',
                'perez','roberts','turner','phillips','campbell','parker','evans',
                'edwards','collins','stewart','sanchez','morris','rogers','reed',
                'cook','morgan','bell','murphy','bailey','rivera','cooper',
                'richardson','cox','howard','ward','torres','peterson','gray',
                'ramirez','watson','brooks','kelly','sanders','price','bennett',
                'wood','barnes','ross','henderson','coleman','jenkins','perry',
                'powell','long','patterson','hughes','flores','washington','butler',
                'simmons','foster','gonzales','bryant','alexander','russell',
                'griffin','diaz','hayes','fisher','cole','frank','owens',
                'reynolds','mills','grant','wells','ford','porter','hunt','stone',
                'dixon','hawkins','burns','berry','shaw','reyes','medina',
                'doe','johnson','williams','miller','moore','thomas','wright',
                'walker','hall','allen','young','adams','nelson','carter',
            }
            sep_parts = re.split(r'[._-]', local)
            is_real_name = (
                len(sep_parts) == 2 and
                all(p.isalpha() and len(p) >= 2 for p in sep_parts) and
                ((sep_parts[0] in _FIRST and sep_parts[1] in _LAST) or
                 (sep_parts[0] in _LAST  and sep_parts[1] in _FIRST))
            )

            if not is_real_name:
                # Factor 1 – Shannon entropy indicates near-uniform character spread
                f_entropy = entropy > 3.0

                # Factor 2 – Low vowel ratio (random strings often lack vowels)
                f_vowels = vowel_ratio <= 0.30

                # Factor 3 – Digits scattered inside the string, not just at the end
                f_digits = (digit_count >= 2 and
                            bool(re.search(r'[a-z]\d[a-z]|\d[a-z]\d', local)))

                # Factor 4 – High unique-character ratio (random = few repeats)
                unique_ratio = len(set(local)) / max(len(local), 1)
                f_unique = unique_ratio >= 0.75

                # Factor 5 – No recognisable English word embedded
                _COMMON = {'user','mail','info','test','home','name','blog','help',
                           'shop','work','love','life','data','code','tech','site',
                           'link','post','news','real','best','john','jane','mark',
                           'mike','kate','jack','alex','adam','luke','mary','anna',
                           'sara','lisa','emma','ryan','paul','eric','alan','kyle',
                           'noah','liam','dave','owen','evan','alice','smith','jones',
                           'peter','james','chris','david','emily','grace','hello',
                           'world','super','admin','sales','brown','davis','thomas',
                           'robert','oliver','daniel','master','shadow','dragon','tiger',
                           'support','contact','service','secure','account','email',
                           'notify','alert','update','welcome','newsletter','webmaster',
                           'phoenix','mighty','dark','light','storm','fire','ice',
                           'wolf','hawk','eagle','falcon','raven','fox','bear','lion',
                           'night','star','moon','blue','red','black','white','gold',
                           'cyber','neon','nova','omega','alpha','prime','mega','ninja',
                           'king','queen','lord','knight','warrior','hunter','ranger',
                           'swift','brave','sharp','smart','bold','wild','free',}
                letters_lower = letters_only.lower()
                has_real_word = any(w in letters_lower for w in _COMMON)
                f_noword = not has_real_word

                # Factor 6 – word.word separator pattern where words are NOT real names
                #             (username generators often combine random words with dots)
                word_parts = [p for p in sep_parts if p.isalpha() and len(p) >= 3]
                f_word_combo = (
                    len(word_parts) >= 2 and
                    not any(w in (_FIRST | _LAST | _COMMON) for w in word_parts)
                )

                rnd_score = sum([f_entropy, f_vowels, f_digits, f_unique, f_noword, f_word_combo])

                if rnd_score >= 2:
                    auto_gen_disposable = True
                    is_disposable = True
                    factors_hit = []
                    if f_entropy:    factors_hit.append(f"entropy {entropy:.2f}")
                    if f_vowels:     factors_hit.append(f"vowel {vowel_ratio:.0%}")
                    if f_digits:     factors_hit.append("digits scattered")
                    if f_unique:     factors_hit.append(f"unique-ratio {unique_ratio:.0%}")
                    if f_noword:     factors_hit.append("no real word")
                    if f_word_combo: factors_hit.append("unusual word combo")
                    risk_indicators.insert(0, {
                        "level": "high",
                        "msg": (
                            f"Username '{local}' matches {rnd_score}/6 randomness factors "
                            f"({', '.join(factors_hit)}) on an unknown domain — "
                            f"likely auto-generated disposable address"
                        ),
                    })

    # 3. Pattern-based detection for unlisted providers
    if not is_disposable and domain_label:
        dl = domain_label.lower()
        is_disposable = any(pat in dl for pat in DISPOSABLE_DOMAIN_SUBSTRINGS)

    disposable_service = base_domain if is_disposable else None
    if is_disposable:
        # Treat as strongest phishing signal — override statistical_report
        features['statistical_report'] = -1
        if not auto_gen_disposable:
            # Only insert domain-based banner when it wasn't already inserted above
            risk_indicators.insert(0, {
                "level": "high",
                "msg": f"Disposable/temporary email address detected ({base_domain}) — these are anonymous, untrackable, and frequently used to bypass verification",
            })

    return features, risk_indicators, is_disposable, auto_gen_disposable, disposable_service


def _load_and_train():
    global _model, _scaler, _train_feature_cols
    csv_path = DATA_DIR / "phishing_dataset.csv"
    if csv_path.exists():
        df = pd.read_csv(csv_path)
        df.columns = [c.strip().lower() for c in df.columns]
    else:
        print("Dataset not found, generating synthetic data…")
        rng = np.random.RandomState(42)
        n = 11055
        data = {col: rng.choice([-1, 0, 1], size=n, p=[0.45, 0.10, 0.45]) for col in FEATURE_NAMES}
        data["result"] = rng.choice([-1, 1], size=n, p=[0.55, 0.45])
        df = pd.DataFrame(data)

    feature_cols = [c for c in df.columns if c != "result"]
    _train_feature_cols = feature_cols
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    y = df["result"].map({-1: 0, 1: 1}).fillna(0).astype(int)

    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    _scaler = StandardScaler()
    X_train_scaled = _scaler.fit_transform(X_train)
    _model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    _model.fit(X_train_scaled, y_train)
    print("Model trained and ready.")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_and_train()
    yield


app = FastAPI(title="Phishing Email Detector", version="2.0.0", lifespan=lifespan)


# ── Static files ──────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def serve_index():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/health")
async def health():
    """Liveness/readiness probe for deployments and load balancers."""
    ok = _model is not None and _scaler is not None
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ok" if ok else "starting", "model_loaded": ok},
    )


# ── API ───────────────────────────────────────────────────────────────────────
@app.get("/api/metrics")
async def get_metrics():
    return JSONResponse({"metrics": MODEL_METRICS, "feature_importances": FEATURE_IMPORTANCES})


@app.get("/api/features")
async def get_features():
    return JSONResponse({"features": FEATURE_INFO})


class EmailRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


@app.post("/api/analyze-email")
async def analyze_email(request: EmailRequest):
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not yet loaded")

    email = request.email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email address is required")

    feature_dict, risk_indicators, is_disposable, is_suspected_disposable, disposable_service = extract_email_features(email)

    # Build feature vector in the order the scaler was fitted on
    cols = _train_feature_cols if _train_feature_cols else FEATURE_NAMES
    feature_values = [feature_dict.get(name, 0) for name in cols]
    X = np.array([feature_values], dtype=float)
    X_scaled = _scaler.transform(X)

    prediction = int(_model.predict(X_scaled)[0])
    proba = _model.predict_proba(X_scaled)[0]
    phishing_prob = float(proba[0])
    legitimate_prob = float(proba[1])

    # Annotate feature values with metadata
    importances = _model.feature_importances_
    cols = _train_feature_cols if _train_feature_cols else FEATURE_NAMES
    info_map = {f["name"]: f for f in FEATURE_INFO}
    feature_breakdown = []
    for i, name in enumerate(cols):
        info = info_map.get(name, {"label": name, "email_desc": "", "group": ""})
        val = int(float(feature_values[i]))
        # Choose description that matches the current value direction
        if val == 1:
            desc = info.get("email_desc_pos") or info.get("email_desc", "")
        else:
            desc = info.get("email_desc", "")
        feature_breakdown.append({
            "name": name,
            "label": info["label"],
            "email_desc": desc,
            "group": info["group"],
            "value": val,
            "importance": round(float(importances[i]), 4),
        })

    # Sort by importance
    feature_breakdown.sort(key=lambda x: x["importance"], reverse=True)

    # Risk level summary
    high_risks = sum(1 for r in risk_indicators if r["level"] == "high")
    med_risks = sum(1 for r in risk_indicators if r["level"] == "medium")
    phish_features = sum(1 for v in feature_values if v == -1)

    # "Suspected phishing": ML classifies as legitimate, but ≥1 high-risk indicator
    # flags a serious structural problem (fake business domain, brand impersonation, etc.)
    is_suspected_phishing = (prediction == 1 and high_risks >= 1)

    if is_suspected_phishing:
        label = "Suspected Phishing"
    elif prediction == 1:
        label = "Legitimate Email"
    else:
        label = "Likely Phishing"

    return JSONResponse({
        "email": email,
        "prediction": prediction,
        "label": label,
        "phishing_probability": round(phishing_prob * 100, 1),
        "legitimate_probability": round(legitimate_prob * 100, 1),
        "risk_indicators": risk_indicators,
        "high_risk_count": high_risks,
        "med_risk_count": med_risks,
        "phish_feature_count": phish_features,
        "feature_breakdown": feature_breakdown[:10],
        "is_disposable": is_disposable,
        "is_suspected_disposable": is_suspected_disposable,
        "disposable_service": disposable_service,
        "is_suspected_phishing": is_suspected_phishing,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Email Content Analysis (heuristic rule-based, no ML model required)
# ─────────────────────────────────────────────────────────────────────────────

CONTENT_RULES: dict = {
    "urgency": {
        "label": "Urgency & Pressure",
        "level": "high",
        "icon": "⏰",
        "description": "Phishing emails create artificial time pressure to prevent careful thinking.",
        "keywords": [
            "urgent", "immediately", "act now", "respond within", "respond today",
            "within 24 hours", "within 48 hours", "within 72 hours", "limited time",
            "today only", "expires soon", "expiring", "deadline", "last chance",
            "final notice", "final warning", "time sensitive", "time-sensitive",
            "asap", "do not delay", "action required", "response required",
            "reply immediately", "prompt action", "critical alert", "important notice",
            "account will be deleted", "service will be discontinued",
            "must respond", "failure to respond", "failure to act",
            "your access will be", "expiration notice",
        ],
    },
    "threats": {
        "label": "Threats & Fear Tactics",
        "level": "high",
        "icon": "🚨",
        "description": "Scammers use fear of account loss, legal trouble, or arrest to coerce victims.",
        "keywords": [
            "account suspended", "account blocked", "account terminated", "account closed",
            "access denied", "access revoked", "will be terminated", "will be suspended",
            "legal action", "lawsuit", "arrested", "penalty", "criminal charges",
            "your account has been", "unusual activity", "suspicious activity",
            "unauthorized access", "security breach", "compromised", "hacked",
            "report you", "law enforcement", "police", "fbi", "irs audit",
            "debt collection", "warrant issued", "court order",
            "face prosecution", "civil lawsuit", "criminal investigation",
            "your ip address", "your device has been", "data breach",
            "identity theft", "we have recorded", "we have detected",
        ],
    },
    "financial": {
        "label": "Financial Lure",
        "level": "high",
        "icon": "💰",
        "description": "Promises of unexpected money or urgent payment demands are classic scam patterns.",
        "keywords": [
            "free money", "lottery", "you won", "you have won", "prize winner",
            "million dollar", "billion dollar", "inheritance", "unclaimed funds",
            "transfer funds", "wire transfer", "bitcoin", "cryptocurrency", "crypto wallet",
            "investment opportunity", "guaranteed return", "100% profit", "risk-free",
            "send money", "western union", "moneygram", "gift card", "itunes card",
            "google play card", "steam card",
            "overdue payment", "unpaid invoice", "outstanding balance",
            "refund pending", "tax refund", "claim your refund", "unclaimed prize",
            "processing fee", "advance fee", "release fee", "activation fee",
            "donation", "charity fund", "humanitarian fund",
            "next of kin", "deceased customer", "estate",
        ],
    },
    "credential": {
        "label": "Credential Harvesting",
        "level": "high",
        "icon": "🔑",
        "description": "Requests for passwords, card numbers, SSN, or account details are major red flags.",
        "keywords": [
            "click here to verify", "verify your account", "verify your email",
            "confirm your account", "confirm your identity", "confirm your details",
            "reset your password", "update your password", "enter your password",
            "provide your password", "validate your account", "re-enter your",
            "social security number", "ssn", "credit card number",
            "bank account number", "routing number", "date of birth",
            "mother's maiden name", "security question", "pin number",
            "login to your account", "sign in to verify", "update your information",
            "submit your details", "fill in the form below",
            "complete the form", "fill out the form", "enter your details",
            "passport number", "driver's license", "national id",
            "two-factor", "one-time password", "otp code",
        ],
    },
    "impersonation": {
        "label": "Possible Brand Impersonation",
        "level": "medium",
        "icon": "🎭",
        "description": "Mentions of well-known brands alongside action requests may indicate spoofing.",
        "keywords": [
            "paypal", "amazon", "apple id", "google account", "microsoft account",
            "netflix", "facebook", "instagram", "twitter", "linkedin", "ebay",
            "fedex", "ups delivery", "dhl express", "usps", "royal mail",
            "bank of america", "chase bank", "wells fargo", "citibank", "hsbc",
            "barclays", "santander", "natwest", "lloyds",
            "internal revenue service", "irs", "social security administration",
            "department of homeland security", "interpol", "europol",
            "world health organization", "who", "united nations",
            "dropbox", "docusign", "adobe sign", "wetransfer",
        ],
    },
    "deception": {
        "label": "Deceptive Tactics",
        "level": "medium",
        "icon": "🎪",
        "description": "Phrases designed to manipulate behavior, bypass skepticism, or avoid scrutiny.",
        "keywords": [
            "do not share this", "keep this confidential", "keep this secret",
            "delete this email", "do not forward", "burn after reading",
            "you have been specially selected", "you have been chosen",
            "congratulations you are", "dear valued customer",
            "dear account holder", "dear user", "dear beneficiary",
            "dear friend", "dear sir", "dear madam", "dear sir/madam",
            "your package is waiting", "delivery attempt failed",
            "click the link below", "click the button below",
            "download the attachment", "open the attachment",
            "we will never ask for your password",
            "this is not spam", "this email is legitimate",
            "100% safe", "guaranteed secure", "verified by",
            "forward this email", "share with your friends",
            "as seen on cnn", "as seen on bbc",
        ],
    },
    # ── New categories ────────────────────────────────────────────────────────
    "attachments": {
        "label": "Suspicious Attachment References",
        "level": "high",
        "icon": "📎",
        "description": "References to file attachments, especially executables or documents with macros, are a primary malware delivery vector.",
        "keywords": [
            "see the attached", "please find attached", "open the attached file",
            "attached invoice", "attached document", "attached receipt",
            "download and run", "run the installer", "execute the file",
            "attached .exe", "attached .zip", "attached .doc", "attached .pdf",
            "scan the attached", "view the attached", "enable macros",
            "enable editing", "enable content", "allow this document",
            "extract the zip", "unzip the file", "password is attached",
            "attachment contains", "file attached",
        ],
    },
    "tech_scam": {
        "label": "Tech Support / Malware Scam",
        "level": "high",
        "icon": "💻",
        "description": "Fake security alerts claiming your device is infected, designed to make you call fraudulent 'support' numbers.",
        "keywords": [
            "your computer is infected", "your device is infected", "virus detected",
            "malware detected", "spyware detected", "ransomware detected",
            "call microsoft", "call apple support", "call our toll-free",
            "windows has detected", "microsoft security alert", "apple security alert",
            "your subscription has expired", "renew your antivirus",
            "your computer has been hacked", "hacker has access to your webcam",
            "your files have been encrypted", "pay to decrypt",
            "remote access", "allow remote connection", "install this software",
            "technical support", "tech support", "call immediately",
            "do not turn off your computer", "do not restart",
        ],
    },
    "job_scam": {
        "label": "Job / Money Mule Scam",
        "level": "medium",
        "icon": "💼",
        "description": "Fake job offers, work-from-home schemes, or requests to receive and forward money on behalf of others.",
        "keywords": [
            "work from home", "work at home", "home-based job", "remote job offer",
            "earn per day", "earn per week", "earn $", "make money online",
            "no experience required", "no experience needed",
            "part time job", "flexible hours", "be your own boss",
            "package forwarding", "parcel forwarding", "reshipping agent",
            "receive payment", "transfer the funds", "keep a commission",
            "money transfer agent", "financial agent", "payment processor",
            "lottery agent", "claims agent", "prize agent",
            "data entry job", "typing job", "easy job", "simple task",
            "multi-level marketing", "mlm", "pyramid scheme",
        ],
    },
    "social_engineering": {
        "label": "Social Engineering",
        "level": "medium",
        "icon": "🧠",
        "description": "Psychological manipulation tactics that exploit trust, authority, or reciprocity to bypass judgment.",
        "keywords": [
            "i am the ceo", "i am a doctor", "i am a lawyer", "i am an agent",
            "on behalf of", "acting on behalf",
            "god bless you", "may god bless", "in god we trust",
            "i need your help", "please help me", "only you can help",
            "i trust you", "you are the only person", "i chose you",
            "our mutual friend", "your friend recommended",
            "strictly confidential", "top secret", "classified information",
            "do not tell anyone", "between you and me",
            "i found your contact", "i got your email from",
            "dying of cancer", "terminal illness", "last wish",
            "refugee", "stranded abroad", "stuck in",
            "revert back", "kindly revert", "do the needful",
            "i am mr", "i am mrs", "i am dr", "i am barrister",
        ],
    },
}

CONTENT_SAFETY_SIGNALS: list = [
    ("unsubscribe", "Contains unsubscribe link — typical of legitimate bulk emails"),
    ("privacy policy", "Mentions privacy policy — sign of compliance"),
    ("terms of service", "References terms of service"),
    ("terms and conditions", "References terms and conditions"),
    ("to stop receiving", "Provides opt-out option"),
    ("if you did not request", "Acknowledges you may not have requested this"),
    ("if you didn't request", "Acknowledges you may not have requested this"),
    ("contact us at", "Provides official contact information"),
    ("© ", "Contains copyright notice"),
    ("all rights reserved", "Contains copyright notice"),
    ("sent from", "Identifies sender system transparently"),
    ("view in browser", "Provides web version link — common in legitimate newsletters"),
    ("manage preferences", "Offers subscription preference management"),
    ("update your preferences", "Offers subscription preference management"),
    ("you are receiving this", "Explains why the email was sent"),
    ("you subscribed", "Acknowledges subscription consent"),
    ("hello [name]", "Personalized greeting (legitimate systems use names)"),
    ("hi [name]", "Personalized greeting"),
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "buff.ly",
    "ift.tt", "dlvr.it", "wp.me", "tiny.cc", "clck.ru",
    "qr.ae", "su.pr", "lnkd.in", "db.tt", "qr.net",
]

# Character obfuscation substitution map (leetspeak / homoglyph tricks)
_OBFUSCATION_PAIRS = [
    (r'p[@4]yp[@4]l', 'PayPal'),
    (r'am[@4]z[o0]n', 'Amazon'),
    (r'[a4]ppl[e3]', 'Apple'),
    (r'm[i1]cr[o0]s[o0]ft', 'Microsoft'),
    (r'g[o0][o0]gl[e3]', 'Google'),
    (r'n[e3]tfl[i1]x', 'Netflix'),
    (r'[i1]nst[@a4]gr[@a4]m', 'Instagram'),
    (r'f[@a4]c[e3]b[o0][o0]k', 'Facebook'),
    (r'[l1][o0]g[i1]n', 'login'),
    (r'v[e3]r[i1]fy', 'verify'),
    (r'[a4]cc[o0]unt', 'account'),
    (r'p[@a4]ssw[o0]rd', 'password'),
    (r'b[a4]nk', 'bank'),
]


def _count_urls(text: str) -> int:
    return len(re.findall(r'https?://\S+', text))


def _has_ip_url(text: str) -> bool:
    return bool(re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))


def _has_shortener_url(text: str) -> bool:
    lower = text.lower()
    return any(s in lower for s in SHORTENER_DOMAINS)


def _excessive_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _detect_obfuscation(text: str) -> list[str]:
    """Detect leetspeak / homoglyph substitution tricks (e.g. P@yP@l, Amaz0n)."""
    found = []
    for pattern, brand in _OBFUSCATION_PAIRS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(brand)
    return found


def _large_currency_amounts(text: str) -> list[str]:
    """Find patterns like $5,000,000 or USD 2000000 suggesting implausible winnings."""
    raw = re.findall(r'(?:\$|usd|gbp|eur|€|£)\s*[\d,\.]+', text, re.IGNORECASE)
    results = []
    for m in raw:
        digits = re.sub(r'[^\d]', '', m)
        if digits and int(digits) >= 10_000:
            results.append(m.strip())
    return results[:4]


def _count_generic_cta(text: str) -> int:
    """Count generic call-to-action phrases that hide real link destinations."""
    patterns = [
        r'\bclick here\b', r'\bclick now\b', r'\bclick below\b',
        r'\bclick this link\b', r'\bpress here\b', r'\btap here\b',
        r'\bfollow this link\b', r'\bopen this link\b',
    ]
    return sum(len(re.findall(p, text, re.IGNORECASE)) for p in patterns)


def _has_generic_salutation(text: str) -> bool:
    """Detect impersonal greetings that suggest bulk phishing campaigns."""
    generics = [
        r'\bdear\s+(sir|madam|sir/madam|customer|user|account\s+holder|'
        r'beneficiary|friend|winner|client|member|valued\s+customer|'
        r'valued\s+member|applicant)\b',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in generics)


def _detect_non_native_phrases(text: str) -> list[str]:
    """Detect English phrases atypical of native speakers, common in overseas scam emails."""
    markers = [
        "kindly revert", "kindly do", "kindly note", "kindly confirm",
        "kindly send", "kindly provide", "revert back to me",
        "do the needful", "at the earliest", "i am mr.", "i am mrs.",
        "i am barrister", "i am dr.", "attached herewith",
        "please do the", "for your kind", "your swift response",
        "your prompt response", "be informed that",
        "we wish to inform", "we are pleased to inform",
        "i write to inform", "i write to bring",
        "seeking for", "in need of your",
    ]
    lower = text.lower()
    return [m for m in markers if m in lower]


def _has_mismatched_link_text(text: str) -> bool:
    """Detect markdown-style [text](url) or HTML href patterns where link text ≠ domain."""
    md_links = re.findall(r'\[([^\]]+)\]\((https?://[^)]+)\)', text)
    for link_text, url in md_links:
        domain_match = re.search(r'https?://([^/\s]+)', url)
        if domain_match:
            domain = domain_match.group(1).lower()
            if link_text.lower() not in domain and domain not in link_text.lower():
                return True
    return False


def analyze_email_content(subject: str, body: str) -> dict:
    """Rule-based heuristic phishing analysis of email subject + body text."""
    full_lower = (subject + "\n" + body).lower()
    full_orig  = subject + "\n" + body

    category_results = []
    total_score = 0

    for cat_key, cat_info in CONTENT_RULES.items():
        matched = [kw for kw in cat_info["keywords"] if kw in full_lower]
        if matched:
            capped = min(len(matched), 5)
            total_score += capped
            category_results.append({
                "key":         cat_key,
                "label":       cat_info["label"],
                "level":       cat_info["level"],
                "icon":        cat_info["icon"],
                "description": cat_info["description"],
                "matched":     matched[:6],
                "count":       len(matched),
                "score":       capped,
            })

    extra_indicators = []

    # ── Structural & heuristic checks ────────────────────────────────────────

    # 1. IP-based URLs
    if _has_ip_url(full_orig):
        total_score += 3
        extra_indicators.append({
            "level": "high",
            "msg": "Contains URLs using raw IP addresses — strong phishing signal (legitimate services never do this)",
        })

    # 2. URL shorteners
    if _has_shortener_url(full_orig):
        total_score += 2
        extra_indicators.append({
            "level": "high",
            "msg": "Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain",
        })

    # 3. Mismatched link text vs URL
    if _has_mismatched_link_text(full_orig):
        total_score += 2
        extra_indicators.append({
            "level": "high",
            "msg": "Link display text does not match the actual URL destination — classic deceptive link technique",
        })

    # 4. Excessive exclamation marks
    excl = full_orig.count("!")
    if excl >= 3:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Excessive exclamation marks ({excl}) — emotional manipulation tactic common in scam emails",
        })

    # 5. Excessive capitalization
    caps_ratio = _excessive_caps_ratio(full_orig)
    if caps_ratio > 0.40 and len(full_orig) > 60:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Excessive capitalization ({caps_ratio:.0%} uppercase) — used to simulate alarm and urgency",
        })

    # 6. Excessive question marks in subject
    subj_q = subject.count("?")
    if subj_q >= 2:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Multiple question marks in subject line ({subj_q}) — manipulative rhetorical device",
        })

    # 7. High URL count
    url_count = _count_urls(full_orig)
    if url_count > 6:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Unusually high number of URLs ({url_count}) — suggests bulk phishing template",
        })

    # 8. Generic/impersonal salutation
    if _has_generic_salutation(full_orig):
        total_score += 2
        extra_indicators.append({
            "level": "medium",
            "msg": "Generic impersonal greeting (Dear Customer/User/Valued Member) — legitimate services address you by name",
        })

    # 9. Implausibly large currency amounts
    large_amounts = _large_currency_amounts(full_orig)
    if large_amounts:
        total_score += 2
        extra_indicators.append({
            "level": "high",
            "msg": f"Implausibly large monetary amounts mentioned: {', '.join(large_amounts)} — hallmark of advance-fee and lottery scams",
        })

    # 10. Excessive generic CTAs
    cta_count = _count_generic_cta(full_orig)
    if cta_count >= 2:
        total_score += 1
        extra_indicators.append({
            "level": "medium",
            "msg": f"Generic call-to-action phrases used {cta_count}× ('click here', 'click now') — legitimate emails use descriptive link text",
        })

    # 11. Non-native English patterns
    non_native = _detect_non_native_phrases(full_orig)
    if non_native:
        total_score += min(len(non_native), 2)
        extra_indicators.append({
            "level": "medium",
            "msg": f"Non-native English phrasing detected ({len(non_native)} pattern{'s' if len(non_native)>1 else ''}): \"{non_native[0]}\"{'…' if len(non_native)>1 else ''} — common in overseas scam campaigns",
        })

    # 12. Character obfuscation / leetspeak
    obfuscated = _detect_obfuscation(full_orig)
    if obfuscated:
        total_score += 3
        extra_indicators.append({
            "level": "high",
            "msg": f"Character substitution / homoglyph obfuscation detected for: {', '.join(set(obfuscated))} — e.g. P@yP@l, Amaz0n — used to evade spam filters",
        })

    # ── Safety signals (each reduces score by 1) ─────────────────────────────
    safety_found = [
        desc for (kw, desc) in CONTENT_SAFETY_SIGNALS if kw.lower() in full_lower
    ]
    total_score = max(0, total_score - len(safety_found))

    if total_score == 0:
        risk_level, risk_label = "safe",     "No Phishing Indicators Found"
    elif total_score <= 3:
        risk_level, risk_label = "low",      "Low Risk — Minor Concerns"
    elif total_score <= 8:
        risk_level, risk_label = "medium",   "Medium Risk — Suspicious Content"
    elif total_score <= 15:
        risk_level, risk_label = "high",     "High Risk — Likely Phishing"
    else:
        risk_level, risk_label = "critical", "Critical Risk — Very Likely Phishing"

    return {
        "risk_level":        risk_level,
        "risk_label":        risk_label,
        "total_score":       total_score,
        "category_results":  category_results,
        "extra_indicators":  extra_indicators,
        "safety_signals":    safety_found,
        "url_count":         url_count,
        "has_ip_url":        _has_ip_url(full_orig),
        "has_shortener":     _has_shortener_url(full_orig),
    }


class ContentRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=50_000)


@app.post("/api/analyze-content")
async def analyze_content_endpoint(request: ContentRequest):
    subject = request.subject.strip()
    body    = request.body.strip()
    if not subject and not body:
        raise HTTPException(status_code=400, detail="Subject or body is required")
    result = analyze_email_content(subject, body)
    return JSONResponse(result)


# ── Email Authenticity Verification ──────────────────────────────────────────

from concurrent.futures import ThreadPoolExecutor, wait as futures_wait


class VerifyRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


# ── Helper: SMTP mailbox probe ────────────────────────────────────────────────
def _smtp_probe(email: str, mx_host: str, timeout: int = 8) -> dict:
    result = {"connectable": False, "result": "unverifiable", "message": ""}
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        smtp.connect(mx_host, 25)
        result["connectable"] = True
        smtp.helo("verify.phishguard.local")
        smtp.mail("")
        code, msg_bytes = smtp.rcpt(email)
        msg_str = msg_bytes.decode(errors="replace") if isinstance(msg_bytes, bytes) else str(msg_bytes)
        try:
            smtp.quit()
        except Exception:
            pass
        if code == 250:
            result["result"] = "exists"
            result["message"] = f"Mail server accepted the address (SMTP {code})"
        elif code in (550, 551, 552, 553):
            result["result"] = "does_not_exist"
            result["message"] = f"Mail server rejected the address (SMTP {code}): {msg_str[:120]}"
        elif code in (421, 450, 451, 452):
            result["result"] = "temporarily_unavailable"
            result["message"] = f"Server returned a temporary error (SMTP {code}) — try again later"
        else:
            result["result"] = "unknown"
            result["message"] = f"Unexpected server response (SMTP {code}): {msg_str[:120]}"
    except smtplib.SMTPConnectError as e:
        result["message"] = f"Cannot connect to {mx_host}:25 — {e}"
    except smtplib.SMTPServerDisconnected as e:
        result["message"] = f"Server disconnected unexpectedly — {e}"
    except socket.timeout:
        result["message"] = f"Connection to {mx_host} timed out after {timeout}s"
    except OSError as e:
        result["message"] = f"Network error: {e}"
    except Exception as e:
        result["message"] = str(e)[:150]
    return result


# ── Helper: SPF record check ──────────────────────────────────────────────────
def _check_spf(domain: str) -> dict:
    """Look up SPF TXT record and parse the enforcement policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "message": ""}
    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=5):
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["found"]  = True
                result["record"] = txt[:250]
                if "-all" in txt:
                    result["policy"]  = "strict"
                    result["message"] = "Strict policy (-all): unauthorized senders are rejected."
                elif "~all" in txt:
                    result["policy"]  = "softfail"
                    result["message"] = "Soft-fail policy (~all): unauthorized senders are flagged but not blocked."
                elif "?all" in txt:
                    result["policy"]  = "neutral"
                    result["message"] = "Neutral policy (?all): no enforcement — spoofing possible."
                elif "+all" in txt:
                    result["policy"]  = "open"
                    result["message"] = "Open policy (+all): ANY server may send — high spoofing risk!"
                else:
                    result["policy"]  = "unknown"
                    result["message"] = "SPF record found but enforcement policy is unclear."
                break
        if not result["found"]:
            result["message"] = "No SPF record — this domain is vulnerable to email spoofing."
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = "No TXT records found for domain."
    except dns.exception.DNSException as e:
        result["message"] = f"DNS error: {e}"
    except Exception as e:
        result["message"] = f"SPF check error: {str(e)[:100]}"
    return result


# ── Helper: DMARC policy check ────────────────────────────────────────────────
def _check_dmarc(domain: str) -> dict:
    """Look up DMARC TXT record at _dmarc.<domain> and parse the p= policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "pct": None, "message": ""}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        for r in dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5):
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                result["found"]  = True
                result["record"] = txt[:250]
                m_p   = re.search(r'\bp=(\w+)',   txt)
                m_pct = re.search(r'\bpct=(\d+)', txt)
                if m_p:
                    p = m_p.group(1).lower()
                    result["policy"] = p
                    pct = int(m_pct.group(1)) if m_pct else 100
                    result["pct"] = pct
                    pct_str = f" (applied to {pct}% of messages)" if pct < 100 else ""
                    if p == "reject":
                        result["message"] = f"p=reject{pct_str}: unauthorized emails are rejected."
                    elif p == "quarantine":
                        result["message"] = f"p=quarantine{pct_str}: unauthorized emails go to spam."
                    elif p == "none":
                        result["message"] = f"p=none: monitoring only — no enforcement, spoofing possible."
                    else:
                        result["message"] = f"DMARC policy: {p}{pct_str}"
                else:
                    result["message"] = "DMARC record found but p= policy tag is missing."
                break
        if not result["found"]:
            result["message"] = f"No DMARC record at _dmarc.{domain} — no anti-spoofing policy set."
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = f"No DMARC record at _dmarc.{domain}."
    except dns.exception.DNSException as e:
        result["message"] = f"DNS error: {e}"
    except Exception as e:
        result["message"] = f"DMARC check error: {str(e)[:100]}"
    return result


# ── Helper: Domain age via WHOIS ──────────────────────────────────────────────
def _check_domain_age(domain: str) -> dict:
    """Retrieve domain creation date via WHOIS and assess age."""
    result = {"found": False, "creation_date": None, "age_days": None,
              "registrar": None, "message": ""}
    try:
        import whois
        from datetime import datetime, timezone
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now - creation).days
            result["found"]         = True
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["age_days"]      = age
            result["registrar"]     = (w.registrar or "")[:80] if w.registrar else None
            if age < 30:
                result["message"] = (
                    f"Domain is only {age} days old — newly registered domains "
                    f"are a major phishing red flag."
                )
            elif age < 180:
                result["message"] = (
                    f"Domain is {age} days old (~{age//30} months) — "
                    f"relatively new, proceed with caution."
                )
            elif age < 365:
                result["message"] = f"Domain is {age} days old (< 1 year) — moderately established."
            else:
                years = age // 365
                result["message"] = (
                    f"Domain registered {creation.strftime('%Y-%m-%d')} "
                    f"({years} year{'s' if years != 1 else ''} old) — well-established."
                )
        else:
            result["message"] = "WHOIS returned no creation date for this domain."
    except Exception as e:
        result["message"] = f"WHOIS lookup failed or data unavailable: {str(e)[:100]}"
    return result


# ── Helper: MX PTR (reverse DNS) check ───────────────────────────────────────
def _check_mx_ptr(mx_host: str) -> dict:
    """Check if the primary MX server has a valid PTR (reverse DNS) record."""
    import dns.resolver, dns.reversename, dns.exception
    result = {"found": False, "ptr": None, "ip": None, "message": ""}
    try:
        a_records = dns.resolver.resolve(mx_host, "A", lifetime=5)
        ip = str(a_records[0])
        result["ip"] = ip
        rev = dns.reversename.from_address(ip)
        ptr_records = dns.resolver.resolve(rev, "PTR", lifetime=5)
        ptr = str(ptr_records[0]).rstrip(".")
        result["found"] = True
        result["ptr"]   = ptr
        result["message"] = f"MX server {ip} → PTR: {ptr}"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["message"] = (
            f"No PTR record for MX server{(' ' + result['ip']) if result['ip'] else ''} "
            f"— legitimate mail servers almost always have reverse DNS configured."
        )
    except dns.exception.DNSException as e:
        result["message"] = f"PTR lookup error: {e}"
    except Exception as e:
        result["message"] = f"PTR check error: {str(e)[:100]}"
    return result


@app.post("/api/verify-email")
def verify_email_endpoint(req: VerifyRequest):
    """
    Six-stage email authenticity check (stages 3-6 run in parallel):
      1. RFC 5321 format validation
      2. DNS MX (+ A fallback) record lookup
      3. SMTP RCPT TO mailbox probe   ┐
      4. SPF record & policy          ├─ parallel
      5. DMARC record & policy        │
      6. MX PTR / reverse-DNS         │
      7. Domain age (WHOIS)           ┘
    """
    import dns.resolver
    import dns.exception

    email = req.email.strip()
    out = {
        "email": email,
        "format_valid": False,
        "mx_found": False,
        "mx_records": [],
        "smtp_connectable": False,
        "smtp_result": None,
        "smtp_message": None,
        "spf":  None,
        "dmarc": None,
        "domain_age": None,
        "mx_ptr": None,
        "note": None,
        "overall": None,
    }

    # ── Stage 1: Format ───────────────────────────────────────────────────────
    _EMAIL_RE = re.compile(
        r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~.\-]{1,64}'
        r'@'
        r'[a-zA-Z0-9.\-]{1,253}'
        r'\.[a-zA-Z]{2,}$'
    )
    if not _EMAIL_RE.match(email) or ".." in email:
        out["overall"]       = "invalid_format"
        out["smtp_message"]  = "Email address does not conform to RFC 5321 format."
        return JSONResponse(out)
    out["format_valid"] = True
    domain = email.split("@")[1].lower()

    # ── Stage 2: DNS MX / A lookup ────────────────────────────────────────────
    mx_host = None
    try:
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=6)
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in mx_answers]
        )
        out["mx_found"]   = True
        out["mx_records"] = records
        mx_host = records[0][1]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        try:
            dns.resolver.resolve(domain, "A", lifetime=4)
            out["mx_found"]   = True
            out["mx_records"] = [[0, domain]]
            mx_host = domain
            out["note"] = "No MX record found; domain has an A record — using domain directly."
        except Exception:
            out["overall"]      = "likely_invalid"
            out["smtp_message"] = (
                f"Domain '{domain}' has no MX or A records in DNS — "
                f"this address cannot receive email."
            )
            return JSONResponse(out)

    # ── Stages 3-7: run in parallel ───────────────────────────────────────────
    _TIMEOUT = 12  # seconds to wait for all parallel tasks
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_smtp  = pool.submit(_smtp_probe,      email,  mx_host)
        f_spf   = pool.submit(_check_spf,       domain)
        f_dmarc = pool.submit(_check_dmarc,     domain)
        f_age   = pool.submit(_check_domain_age, domain)
        f_ptr   = pool.submit(_check_mx_ptr,    mx_host)
        futures_wait([f_smtp, f_spf, f_dmarc, f_age, f_ptr], timeout=_TIMEOUT)

    def safe_result(future, fallback):
        try:
            return future.result(timeout=0)
        except Exception:
            return fallback

    probe        = safe_result(f_smtp,  {"connectable": False, "result": "unverifiable",
                                          "message": "SMTP probe timed out."})
    spf_info     = safe_result(f_spf,   {"found": False, "policy": None,
                                          "message": "SPF check timed out."})
    dmarc_info   = safe_result(f_dmarc, {"found": False, "policy": None,
                                          "message": "DMARC check timed out."})
    age_info     = safe_result(f_age,   {"found": False, "age_days": None,
                                          "message": "WHOIS lookup timed out."})
    ptr_info     = safe_result(f_ptr,   {"found": False, "ptr": None,
                                          "message": "PTR check timed out."})

    out["smtp_connectable"] = probe["connectable"]
    out["smtp_result"]      = probe["result"]
    out["smtp_message"]     = probe["message"]
    out["spf"]              = spf_info
    out["dmarc"]            = dmarc_info
    out["domain_age"]       = age_info
    out["mx_ptr"]           = ptr_info

    # ── Overall verdict ───────────────────────────────────────────────────────
    if probe["result"] == "exists":
        out["overall"] = "verified"
    elif probe["result"] == "does_not_exist":
        out["overall"] = "likely_invalid"
    elif not probe["connectable"]:
        out["overall"] = "unverifiable"
        if not out["smtp_message"]:
            out["smtp_message"] = (
                "Port 25 appears blocked by your network. "
                "MX records exist, so the domain is real, but mailbox existence cannot be confirmed."
            )
    else:
        out["overall"] = "unverifiable"

    # Escalate: very new domain is a serious additional red flag
    age_days = age_info.get("age_days")
    if age_days is not None and age_days < 30 and out["overall"] != "likely_invalid":
        out["overall"] = "suspicious"

    return JSONResponse(out)


# ── Legacy predict endpoint ───────────────────────────────────────────────────
class PredictRequest(BaseModel):
    features: dict


@app.post("/api/predict")
async def predict(request: PredictRequest):
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not yet loaded")
    cols = _train_feature_cols if _train_feature_cols else FEATURE_NAMES
    feature_values = [int(request.features.get(name, 0)) for name in cols]
    X = np.array([feature_values], dtype=float)
    X_scaled = _scaler.transform(X)
    prediction = int(_model.predict(X_scaled)[0])
    proba = _model.predict_proba(X_scaled)[0]
    return JSONResponse({
        "prediction": prediction,
        "label": "Legitimate Email" if prediction == 1 else "Likely Phishing",
        "phishing_probability": round(float(proba[0]) * 100, 1),
        "legitimate_probability": round(float(proba[1]) * 100, 1),
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
