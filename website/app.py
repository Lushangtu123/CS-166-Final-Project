"""
app.py – FastAPI backend for the Phishing Email Detector demo.

Startup: loads/trains the Random Forest model on the UCI Phishing dataset.
Routes:
  GET  /                    → serve index.html
  GET  /api/metrics         → classifier performance metrics
  GET  /api/features        → feature metadata
  POST /api/analyze-email   → extract features from email & predict
  POST /api/predict         → raw feature dict prediction (legacy)
"""

import os
import re
import math
import sys
import warnings
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
import pandas as pd
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent / "phishing-detection" / "data"

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

app = FastAPI(title="Phishing Email Detector", version="2.0.0")

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
]
BRAND_DOMAINS = {
    'paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix',
    'facebook', 'twitter', 'instagram', 'linkedin', 'ebay', 'alibaba',
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
    'zopqwhgqdn.com', 'zxcvbnm.co', 'zzi.us',
}

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


def extract_email_features(email: str) -> tuple[dict, list]:
    """
    Extract 30 phishing-indicator features from an email address.
    Returns (feature_dict, risk_indicators).
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
        DISPOSABLE_PATTERNS = [
            # Temp / temporary
            'tempmail', 'temp-mail', 'tempemail', 'tempinbox', 'tempbox',
            'temporary', 'temporaryemail', 'tempr', 'tempsky',
            # Trash / discard
            'trashmail', 'trash-mail', 'trashcan', 'trashme', 'trashy',
            'discardmail', 'discard', 'dispos',
            # Throwaway / burn
            'throwaway', 'throwam', 'throw-mail', 'throwamail',
            'burnermail', 'burn-mail', 'burnmail', 'burnmy',
            # Spam / fake
            'spammail', 'spambox', 'spamgourmet', 'spamfree', 'spamkill',
            'spamevader', 'spamnot', 'spamoff', 'spamthis', 'fakemail',
            'fakeinbox', 'fake-inbox', 'fakeemail',
            # Guerrilla / sharklaser
            'guerrilla', 'sharklaser',
            # Drop / nada / void
            'dropmail', 'maildrop', 'getnada', 'nada.email', 'voidmail',
            # Mailinator / mailnull
            'mailinator', 'mailnull', 'mailnesia', 'mailinater',
            'mailzilla', 'mailslap', 'mailsac', 'mailtemp', 'mailfort',
            # Disposable / anon / incognito
            'disposable', 'anonbox', 'anonymbox', 'anonymail',
            'incognitomail', 'selfdestructing', 'willselfdestruct',
            # Wegwerf (German "throw away")
            'wegwerf', 'zehnminuten',
            # Minute mail
            '10minute', 'tenminute', 'minutemail', '20minute', '30minute',
            # Harakiri / expire
            'harakiri', 'mailexpire', 'suicidemail',
            # Yopmail / jetable
            'yopmail', 'jetable',
            # Other
            'lastmail', 'mohmal', 'emailwarden', 'inboxkitten',
            'tmailinator', 'mailinator', 'mailtothis', 'spammotel',
        ]
        is_disposable = any(pat in dl for pat in DISPOSABLE_PATTERNS)

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


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    _load_and_train()


# ── Static files ──────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def serve_index():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


# ── API ───────────────────────────────────────────────────────────────────────
@app.get("/api/metrics")
async def get_metrics():
    return JSONResponse({"metrics": MODEL_METRICS, "feature_importances": FEATURE_IMPORTANCES})


@app.get("/api/features")
async def get_features():
    return JSONResponse({"features": FEATURE_INFO})


class EmailRequest(BaseModel):
    email: str


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

    return JSONResponse({
        "email": email,
        "prediction": prediction,
        "label": "Legitimate Email" if prediction == 1 else "Likely Phishing",
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
    })


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
