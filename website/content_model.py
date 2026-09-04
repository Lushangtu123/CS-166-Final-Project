"""
content_model.py — Machine-learning text classifier for email *content*.

Data pipeline (priority order):
  1. Real-world corpus from
       phishing-detection/data/Phishing_Email.csv
     (18,650 emails, 11,322 Safe + 7,328 Phishing — Hugging Face mirror of the
      'Phishing Email Detection' Kaggle dataset, originally by 'Cyber Cop',
      licensed LGPL-3.0).
     If the file is missing it can be auto-downloaded via
     `ensure_real_dataset()`.
  2. As a fallback (or to AUGMENT the real data) the module also ships a
     ~2,000-sample template-based synthetic corpus.

Model:
  • FeatureUnion of two TF-IDF vectorisers:
        – word 1-2 grams      (semantic phrases)
        – char_wb 3-5 grams   (catches obfuscation like P@yP@l, Amaz0n)
  • Logistic Regression (liblinear, balanced class weights).

Exports:
  build_content_pipeline(...) -> dict with keys:
      "vectorizer"      : fitted FeatureUnion
      "clf"             : fitted LogisticRegression
      "metrics"         : { Accuracy, Precision, Recall, F1, ROC_AUC,
                            n_train, n_test, data_source }
      "top_terms"       : 25 most phishing-indicative tokens
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import random
import time
import urllib.request
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC

# ── Data-source configuration ────────────────────────────────────────────────
_DEFAULT_DATA_DIR = (Path(__file__).resolve().parent.parent
                     / "phishing-detection" / "data")

# Each entry is (csv_name, downloader_url_or_None, schema_hint)
#   schema_hint == "phishing_email_csv"  : columns ['Email Text', 'Email Type']
#   schema_hint == "champa_csv"          : columns ['subject', 'body', 'label']
#   schema_hint == "phishnchips_csv"     : columns ['phish_label', 'email_content' (JSON)]
#   schema_hint == "phishfuzzer_csv"     : columns ['Subject', 'Body', 'Type']
_DATASETS = [
    # Classic / mid-era public corpora (2002–2008)
    ("Phishing_Email.csv",
     "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/"
     "resolve/main/Phishing_Email.csv?download=true",
     "phishing_email_csv"),
    ("CEAS_08.csv",
     "https://zenodo.org/records/8339691/files/CEAS_08.csv",
     "champa_csv"),
    ("Nazario.csv",
     "https://zenodo.org/records/8339691/files/Nazario.csv",
     "champa_csv"),

    # 2026 LLM-generated / modern attack-grounded benchmarks
    ("phishnchips_core.csv",
     "https://huggingface.co/datasets/AreLit/PhishNChips/"
     "resolve/main/core_emails.csv?download=true",
     "phishnchips_csv"),
    ("phishnchips_legit_v5.csv",
     "https://huggingface.co/datasets/AreLit/PhishNChips/"
     "resolve/main/cross_domain_legitimate_v5.csv?download=true",
     "phishnchips_csv"),
    ("phishnchips_infra.csv",
     "https://huggingface.co/datasets/AreLit/PhishNChips/"
     "resolve/main/infrastructure_phishing_expanded.csv?download=true",
     "phishnchips_csv"),
    ("phishfuzzer_train.csv",
     "https://huggingface.co/datasets/hai123xz/PhishFuzzer-split/"
     "resolve/main/train.csv?download=true",
     "phishfuzzer_csv"),
    ("phishfuzzer_val.csv",
     "https://huggingface.co/datasets/hai123xz/PhishFuzzer-split/"
     "resolve/main/val.csv?download=true",
     "phishfuzzer_csv"),
    ("phishfuzzer_test.csv",
     "https://huggingface.co/datasets/hai123xz/PhishFuzzer-split/"
     "resolve/main/test.csv?download=true",
     "phishfuzzer_csv"),
]


def _download(url: str, dest: Path) -> bool:
    print(f"Downloading {dest.name} from {url} …")
    try:
        urllib.request.urlretrieve(url, dest)
        size_mb = dest.stat().st_size / 1e6
        print(f"  ✓ Downloaded {size_mb:.1f} MB")
        return True
    except Exception as exc:
        print(f"  ✗ Download failed: {exc}")
        if dest.exists():
            dest.unlink(missing_ok=True)
        return False


def ensure_real_dataset(data_dir: Path | None = None,
                        force: bool = False) -> Path | None:
    """
    Make sure all configured real datasets are present locally.
    Returns the path of the *primary* dataset (Phishing_Email.csv) for
    backwards compatibility, or None if it could not be obtained.
    """
    data_dir = Path(data_dir) if data_dir else _DEFAULT_DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    primary_path: Path | None = None
    for name, url, _schema in _DATASETS:
        path = data_dir / name
        if path.exists() and not force:
            if name == "Phishing_Email.csv":
                primary_path = path
            continue
        if url and _download(url, path):
            if name == "Phishing_Email.csv":
                primary_path = path
    return primary_path


def _load_one_corpus(path: Path, schema: str
                     ) -> Tuple[List[str], List[int]] | None:
    """Load a single CSV and return (texts, labels) where label 1 = phishing."""
    if not path.exists():
        return None
    try:
        if schema == "phishing_email_csv":
            df = pd.read_csv(path, index_col=0)
            df = df.dropna(subset=["Email Text"])
            df = df[df["Email Text"].astype(str).str.strip().astype(bool)]
            df["label"] = df["Email Type"].map(
                {"Phishing Email": 1, "Safe Email": 0}
            )
            df = df.dropna(subset=["label"])
            df["label"] = df["label"].astype(int)
            return df["Email Text"].astype(str).tolist(), df["label"].tolist()

        elif schema == "champa_csv":
            df = pd.read_csv(path)
            # Champa et al. 2024 corpora have columns: sender, receiver, date,
            # subject, body, urls, label (1 = phishing, 0 = benign)
            df = df.dropna(subset=["body", "label"])
            df["body"]    = df["body"].astype(str)
            df["subject"] = df["subject"].fillna("").astype(str)
            df["text"]    = (df["subject"] + "\n\n" + df["body"]).str.strip()
            df = df[df["text"].str.len() > 20]

            # Nazario contains some mbox-internal control records like
            # "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"
            df = df[~df["text"].str.contains(
                r"FOLDER INTERNAL DATA|MAILER-DAEMON|DELIVERY FAILURE",
                case=False, regex=True, na=False)]

            df["label"] = df["label"].astype(int)
            return df["text"].tolist(), df["label"].tolist()

        elif schema == "phishnchips_csv":
            # PhishNChips v5.2 (April 2026) — email_content is a JSON blob.
            df = pd.read_csv(path)
            df = df.dropna(subset=["email_content", "phish_label"])
            texts:  List[str] = []
            labels: List[int] = []
            for raw, lab in zip(df["email_content"], df["phish_label"]):
                try:
                    obj = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    continue
                subject = str(obj.get("subject", "") or "")
                body    = str(obj.get("body",    "") or "")
                text = (subject + "\n\n" + body).strip()
                if len(text) < 20:
                    continue
                texts.append(text)
                labels.append(int(lab))
            return texts, labels

        elif schema == "phishfuzzer_csv":
            # PhishFuzzer (Nov 2026) — three-class: Phishing / Spam / Valid.
            # Map Phishing → 1, Valid → 0, drop Spam (spam ≠ phishing and
            # mixing them dilutes the binary signal we care about).
            df = pd.read_csv(path)
            df = df.dropna(subset=["Body", "Type"])
            df = df[df["Type"].isin(["Phishing", "Valid"])]
            df["Body"]    = df["Body"].astype(str)
            df["Subject"] = df["Subject"].fillna("").astype(str)
            df["text"]    = (df["Subject"] + "\n\n" + df["Body"]).str.strip()
            df = df[df["text"].str.len() > 20]
            df["label"] = (df["Type"] == "Phishing").astype(int)
            return df["text"].tolist(), df["label"].tolist()

    except Exception as exc:
        print(f"  ✗ Failed to load {path.name}: {exc}")
        return None
    return None


def load_real_corpus(csv_path: Path | None = None,
                     max_rows: int | None = None,
                     ) -> Tuple[List[str], List[int], str] | None:
    """
    Load and merge all available real datasets.
    Returns (texts, labels, source_description) or None if no data is found.
    Labels: 1 = phishing, 0 = legitimate.
    """
    data_dir = (csv_path.parent if csv_path else _DEFAULT_DATA_DIR)
    all_texts:  List[str] = []
    all_labels: List[int] = []
    per_source: List[str] = []

    for name, _url, schema in _DATASETS:
        loaded = _load_one_corpus(data_dir / name, schema)
        if loaded is None:
            continue
        texts, labels = loaded
        all_texts.extend(texts)
        all_labels.extend(labels)
        n_phish = sum(labels)
        per_source.append(
            f"{name} (n={len(texts)}: {n_phish} phishing / {len(labels)-n_phish} legitimate)"
        )

    if not all_texts:
        return None

    if max_rows is not None and len(all_texts) > max_rows:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(all_texts), size=max_rows, replace=False)
        all_texts  = [all_texts[i]  for i in idx]
        all_labels = [all_labels[i] for i in idx]

    source = "Real corpora: " + " + ".join(per_source)
    return all_texts, all_labels, source


# ── Vocabulary pools used to instantiate templates ────────────────────────────
_BRANDS = [
    "PayPal", "Amazon", "Apple", "Microsoft", "Google", "Netflix",
    "Facebook", "Instagram", "LinkedIn", "eBay", "Chase Bank", "Wells Fargo",
    "Bank of America", "Citibank", "HSBC", "Barclays", "FedEx", "UPS", "DHL",
    "USPS", "Dropbox", "DocuSign", "Adobe", "IRS", "Social Security Administration",
]

_AMOUNTS = [
    "$2,500,000", "$5,000,000", "$10,000,000.00", "USD 1,750,000",
    "GBP 850,000", "EUR 920,000", "$25,000", "$48,750", "$999,999",
]

_FAKE_URLS = [
    "http://secure-{b}-verify.com/login",
    "https://bit.ly/3xK9pQ",
    "http://192.168.42.17/account/reset",
    "https://tinyurl.com/y4r3kp",
    "http://{b}-security-update.tk/verify",
    "https://{b}.account-validate.ml/signin",
    "http://login-{b}.xyz/confirm-identity",
    "https://{b}.support-team.cf/auth",
]

_FIRSTNAMES = ["John", "Sarah", "Michael", "Emily", "David", "Jessica",
               "Robert", "Linda", "James", "Karen", "Thomas", "Patricia"]

_LASTNAMES  = ["Smith", "Johnson", "Williams", "Brown", "Davis",
               "Miller", "Wilson", "Anderson", "Taylor", "Thomas"]

_FILLER_FRAGMENTS = [
    "Please respond at your earliest convenience.",
    "We appreciate your immediate attention to this matter.",
    "This message was sent by the automated security system.",
    "Failure to comply will result in further actions.",
    "Best regards,",
    "Yours sincerely,",
    "The Compliance Department",
    "Security Operations Team",
    "Customer Care Unit",
]


def _rand_url(rng: random.Random) -> str:
    template = rng.choice(_FAKE_URLS)
    return template.format(b=rng.choice(_BRANDS).lower().split()[0])


# ── Phishing template library ────────────────────────────────────────────────
# Each template uses {brand}, {url}, {amount}, {name} placeholders.

_PHISHING_TEMPLATES: List[Tuple[str, str]] = [
    # (subject, body)

    # Credential harvesting + urgency
    ("URGENT: Verify your {brand} account",
     "Dear Customer,\n\nWe have detected unusual activity on your {brand} account. "
     "Your account will be suspended within 24 hours unless you verify your identity. "
     "Click here to verify: {url}\n\nFailure to act immediately will result in permanent "
     "account closure.\n\n{brand} Security Team"),

    ("Action Required: Your {brand} account has been suspended",
     "Hello,\n\nYour {brand} account has been temporarily suspended due to suspicious "
     "login attempts. To restore access, please confirm your identity by clicking "
     "the link below:\n\n{url}\n\nThis link expires in 12 hours.\n\nThank you,\n{brand}"),

    ("Password Reset Required - Immediate Action",
     "Dear User,\n\nOur security system has flagged your password as compromised. "
     "Please reset your password immediately by clicking here: {url}\n\n"
     "If you don't reset within 24 hours your account will be locked.\n\nIT Support"),

    ("Security Alert: Unauthorized Access Detected",
     "Dear Account Holder,\n\nWe detected an unauthorized login attempt from an "
     "unrecognized device. Click the link below to verify it was you and secure "
     "your account: {url}\n\nIgnore this message and your account will be "
     "permanently disabled.\n\n{brand} Security"),

    # Lottery / advance fee
    ("Congratulations! You have won {amount}",
     "Dear Beneficiary,\n\nYou have been selected as a winner in the {brand} "
     "International Lottery Programme. Your prize of {amount} is ready to be "
     "transferred to you. To claim your prize, kindly send us your full name, "
     "address, and bank details. A processing fee of $250 will be required.\n\n"
     "Yours sincerely,\nLottery Claims Department"),

    ("Inheritance Notice - {amount} unclaimed",
     "Dear Friend,\n\nI am Barrister James Wilson. A deceased customer with the "
     "same surname as you left an unclaimed estate of {amount}. As next of kin, "
     "you are entitled to inherit this fund. Please reply with your contact "
     "information so we can begin the transfer.\n\nKindly revert back to me "
     "urgently. God bless you.\n\nBarrister James Wilson"),

    ("Confidential business proposal - {amount}",
     "Dear Sir/Madam,\n\nI am writing to inform you of a confidential business "
     "opportunity worth {amount}. I am the CEO of a major firm and I need a "
     "trusted partner to help transfer funds. You will keep 30% commission. "
     "Please respond immediately to discuss further. Keep this strictly "
     "confidential.\n\nYours faithfully,\nMr. Mohammed Al-Hassan"),

    # Tech support scam
    ("CRITICAL: Your computer is infected!",
     "WINDOWS SECURITY ALERT\n\nMultiple viruses have been detected on your "
     "computer. Your personal files, banking credentials, and webcam may be "
     "compromised. Do not turn off your computer. Call Microsoft Support "
     "immediately at 1-800-555-0173 or click here: {url}\n\nMicrosoft Security Team"),

    ("Your antivirus subscription has expired",
     "Your {brand} antivirus subscription expired yesterday. Your device is now "
     "exposed to ransomware and identity theft. Renew now to avoid losing your "
     "data: {url}\n\nA hacker has gained access to your webcam. Pay {amount} in "
     "bitcoin to remove the threat.\n\n{brand} Security"),

    # Package delivery
    ("Delivery attempt failed - action required",
     "Dear Customer,\n\nWe attempted to deliver your package today but you were "
     "not available. Please confirm your delivery address and pay the redelivery "
     "fee of $3.99 here: {url}\n\nFailure to confirm within 48 hours will result "
     "in the package being returned.\n\n{brand} Delivery"),

    ("Your {brand} package is on hold",
     "Hello,\n\nYour package has been placed on hold pending payment of customs "
     "fees. Please click here to release your package: {url}\n\nThis is the "
     "final notice before your package is returned.\n\n{brand} Logistics"),

    # IRS / tax scam
    ("IRS: Tax refund of {amount} pending",
     "Dear Taxpayer,\n\nYou are owed a tax refund of {amount}. To receive it, "
     "verify your information and provide your social security number, bank "
     "routing number, and date of birth here: {url}\n\nFailure to respond will "
     "result in legal action and your refund being forfeited.\n\nInternal "
     "Revenue Service"),

    ("Final notice: IRS audit pending",
     "WARNING: You owe {amount} in unpaid taxes. The IRS has issued a warrant "
     "for your arrest. Pay immediately via wire transfer or face criminal "
     "prosecution. Call our toll-free number now: 1-877-555-0142.\n\n"
     "Internal Revenue Service"),

    # Job / money mule scam
    ("Work from home opportunity - earn $5,000/week",
     "Hi,\n\nWe are hiring payment processors for our company. Work from home, "
     "flexible hours, no experience needed. You will receive payments to your "
     "bank account, keep 10% commission, and forward the rest. Earn {amount} "
     "per week. Reply with your phone number and bank details to apply.\n\n"
     "HR Department"),

    ("Personal Assistant Position - urgent hire",
     "Dear Applicant,\n\nI am Dr. Stephen Brown, a busy executive. I need a "
     "personal assistant to receive packages and process payments on my behalf. "
     "Compensation: $500 per week. No experience required. Please reply with "
     "your full name and address.\n\nKindly do the needful.\n\nDr. S. Brown"),

    # Crypto scam
    ("Your bitcoin wallet has been compromised",
     "Dear customer,\n\nA hacker has gained access to your crypto wallet. To "
     "secure your funds you must transfer them to our secure wallet immediately. "
     "Click here: {url}\n\nFailure to act in the next 6 hours will result in "
     "loss of all funds.\n\n{brand} Wallet Security"),

    ("Investment opportunity - guaranteed 100% returns",
     "Dear investor,\n\nJoin our exclusive crypto trading program. Guaranteed "
     "100% returns risk-free. Limited time offer. Minimum investment {amount}. "
     "Sign up today and double your money in 7 days: {url}\n\nAs seen on CNN "
     "and BBC.\n\nCrypto Investments Inc."),

    # Document / docusign
    ("You have received a secure document",
     "{name} has shared a confidential document with you via {brand}. To view "
     "the document please sign in here: {url}\n\nEnable macros to view the "
     "content. This document expires in 24 hours.\n\n{brand} Document Services"),

    ("Invoice attached - payment overdue",
     "Dear Customer,\n\nPlease find attached your overdue invoice of {amount}. "
     "Open the attached file to view payment details. Payment must be received "
     "within 24 hours or legal action will be taken.\n\nAccounts Receivable"),

    # Brand impersonation + obfuscation
    ("P@yP@l: Verify your account now",
     "Dear customer,\n\nYour P@yP@l acc0unt has been limited due to suspicious "
     "activity. Please log1n here to verify your identity: {url}\n\n"
     "Failure to verify within 24 hours will result in permanent account "
     "closure.\n\nP@yP@l Security Team"),

    ("Amaz0n: Confirm your order",
     "Hello,\n\nYour recent order from Amaz0n could not be processed because "
     "your billing information is invalid. Please update your payment method "
     "here: {url}\n\nThis link expires in 6 hours.\n\nAmaz0n Customer Service"),

    # Social engineering
    ("I need your urgent help",
     "Dear Friend,\n\nI am in trouble and I need your immediate help. I am "
     "stranded abroad and my wallet has been stolen. Please wire {amount} via "
     "Western Union to the following details. I will repay you as soon as I "
     "return. Do not tell anyone, this is between you and me. God bless you.\n\n"
     "{name}"),

    ("CEO Request - Urgent wire transfer needed",
     "Hi,\n\nI am in a meeting and cannot talk. I need you to wire {amount} to "
     "a new vendor immediately. Send the wire transfer to the account I will "
     "forward shortly. Keep this confidential, do not discuss with anyone else. "
     "Reply ASAP.\n\nSent from my iPhone"),
]


# ── Legitimate template library ─────────────────────────────────────────────
_LEGIT_TEMPLATES: List[Tuple[str, str]] = [
    # Newsletters
    ("TechBlog Monthly Newsletter",
     "Hi {name},\n\nThanks for subscribing to our newsletter. Here is a "
     "roundup of this month's articles:\n• Top 10 software engineering practices\n"
     "• Building scalable web applications\n• Community spotlight\n\n"
     "You are receiving this email because you subscribed at techblog.com.\n"
     "If you no longer wish to receive these emails, please click unsubscribe "
     "below or manage your preferences.\n\nPrivacy Policy | Terms of Service\n"
     "© 2026 TechBlog, All Rights Reserved."),

    ("Your weekly recap from Spotify",
     "Hi {name},\n\nHere is your weekly listening recap. You spent 4 hours "
     "listening to music this week. Your top artist was Taylor Swift.\n\n"
     "View your full recap online.\n\nUnsubscribe | Update preferences | "
     "Privacy Policy\n© Spotify"),

    ("Apple Developer News and Updates",
     "Hello {name},\n\nHere are the latest updates from Apple Developer. "
     "WWDC 2026 sessions are now available. Watch them on demand at "
     "developer.apple.com.\n\nYou are receiving this email because you "
     "subscribed at developer.apple.com.\n\nManage subscription | Privacy Policy"),

    # Order confirmations
    ("Order Confirmation #A2410589",
     "Hi {name},\n\nThank you for your order! Your order #A2410589 has been "
     "confirmed.\n\nItems:\n• Wireless headphones - $79.99\n• USB-C cable - $12.99\n"
     "Total: $92.98\n\nWe will send you a shipping confirmation when your "
     "order ships. You can track your order at any time in your account.\n\n"
     "If you did not place this order, please contact us at help@store.com.\n\n"
     "Sent from Store, Inc., 100 Main St, Seattle, WA"),

    ("Your receipt from Uber",
     "Hi {name},\n\nThanks for riding with Uber. Here's your receipt for "
     "today's trip.\n\nTotal: $17.45\nPickup: 100 Main St\nDropoff: 500 "
     "Market St\nTime: 12 minutes\n\nThis charge will appear on your statement "
     "as UBER TRIP. View this trip in the app for more details.\n\nUber Technologies"),

    ("Your monthly statement is ready",
     "Hello {name},\n\nYour monthly statement for account ending in 4827 is "
     "now available. To view your statement, please sign in to online banking.\n\n"
     "If you did not request this statement or need help, contact us at "
     "1-800-CHASE-24.\n\nSincerely,\nChase Customer Service\nPrivacy Notice | "
     "Equal Housing Lender"),

    # Personal correspondence
    ("Re: Lunch tomorrow?",
     "Hey {name},\n\nSounds good! Let's meet at the Italian place at 12:30. "
     "I'll book a table. Looking forward to catching up.\n\nCheers,\n"
     "{name2}"),

    ("Meeting notes from today",
     "Hi team,\n\nThanks for joining today's planning meeting. Here are the "
     "main takeaways:\n1. Q3 roadmap is locked\n2. Hiring two engineers in "
     "the next sprint\n3. Next review is scheduled for July 15\n\nLet me know "
     "if I missed anything.\n\nBest,\n{name}"),

    ("Project update - Sprint 12",
     "Hi all,\n\nQuick update on Sprint 12. The frontend team finished the "
     "dashboard redesign on schedule. The backend team is on track to ship "
     "the search API by Friday. No blockers at this time.\n\nFull notes are "
     "in the Confluence page.\n\nThanks,\n{name}"),

    # Service notifications
    ("Welcome to GitHub",
     "Hi {name},\n\nThanks for joining GitHub! Get started by creating your "
     "first repository or exploring projects you might be interested in.\n\n"
     "Here are some resources to help you get started:\n• GitHub Docs\n"
     "• GitHub Skills\n• GitHub Community\n\nYou are receiving this email "
     "because you signed up at github.com.\n\nGitHub, Inc.\n88 Colin P "
     "Kelly Jr Street, San Francisco, CA"),

    ("Your password was changed",
     "Hi {name},\n\nThis is a confirmation that the password for your account "
     "was changed on June 18, 2026 at 3:42 PM PST. If you made this change, "
     "you can safely ignore this email.\n\nIf you did NOT make this change, "
     "please go to your account settings to secure your account or contact "
     "support at support@example.com.\n\nWe will never ask for your password "
     "by email.\n\nThanks,\nThe Account Team"),

    ("Two-factor authentication enabled",
     "Hi {name},\n\nTwo-factor authentication was successfully enabled on your "
     "account. From now on, you'll need a verification code from your "
     "authenticator app when you sign in.\n\nIf you did not enable this, "
     "please contact us right away.\n\nThanks,\nGoogle Security"),

    ("Your subscription has been renewed",
     "Hi {name},\n\nYour annual subscription was successfully renewed today. "
     "Your next billing date is June 18, 2027.\n\nView your invoice in your "
     "account. If you have any questions, contact us at support@example.com.\n\n"
     "Manage subscription | Privacy Policy\n© 2026 Acme Corp"),

    # Travel
    ("Flight reminder - SFO to JFK",
     "Hi {name},\n\nThis is a reminder about your upcoming flight tomorrow.\n\n"
     "Flight: UA 1245\nFrom: San Francisco (SFO)\nTo: New York (JFK)\nDeparture: "
     "7:30 AM\nGate: B17\n\nCheck in online up to 24 hours before departure.\n\n"
     "View trip details | Manage booking\n\nUnited Airlines"),

    ("Booking confirmation - Hilton Garden Inn",
     "Hi {name},\n\nYour reservation at Hilton Garden Inn from July 10-12 is "
     "confirmed.\n\nConfirmation #: 87456321\nRoom: King Suite\nCheck-in: 3:00 PM\n"
     "Check-out: 11:00 AM\n\nIf you need to modify your booking, you can do so "
     "online up to 24 hours before arrival.\n\nWe look forward to seeing you!\n"
     "Hilton Honors"),

    # Work / HR
    ("Your timesheet is due",
     "Hi {name},\n\nThis is a friendly reminder that your timesheet for the "
     "week of June 14-18 is due by Friday at 5 PM. Please submit it through "
     "the HR portal.\n\nLet me know if you have any questions.\n\nThanks,\n"
     "HR Team"),

    ("Welcome to the team!",
     "Hi {name},\n\nOn behalf of everyone at Acme Corp, welcome aboard! We're "
     "thrilled to have you join us. Your first day is Monday at 9 AM. "
     "Please bring two forms of ID for onboarding.\n\nI've attached the "
     "employee handbook for your review.\n\nLooking forward to meeting you!\n\n"
     "Best,\nSarah Johnson\nHR Director"),

    # Notifications
    ("Your weekly screen time report",
     "Hi {name},\n\nYour average screen time this week was 4 hours 12 minutes "
     "per day, down 8% from last week. Your most used app was Safari.\n\n"
     "View your full report in Settings → Screen Time.\n\nApple"),

    ("New comment on your post",
     "Hi {name},\n\n{name2} commented on your post in the JavaScript discussion "
     "group:\n\n\"Great article! This really helped me understand async/await.\"\n\n"
     "View comment | Unsubscribe from this thread\n\nDev Community"),

    ("Reminder: Your appointment tomorrow",
     "Hi {name},\n\nThis is a reminder that you have an appointment with "
     "Dr. Smith tomorrow at 10:00 AM. The appointment will take place at our "
     "downtown clinic.\n\nIf you need to reschedule please call our office "
     "at (415) 555-2100.\n\nSee you soon!\nDowntown Medical Center"),

    # ── Modern legitimate templates (2024-2026 patterns) ─────────────────────
    # These specifically address the dataset gap: the public corpus is heavy
    # on 2002-2008 mailing-list traffic and under-represents modern e-commerce,
    # SaaS and developer notifications.

    ("Your Amazon order has shipped",
     "Hi {name},\n\nYour order #112-7895432-1009281 has shipped via UPS and "
     "will arrive on Friday June 21.\n\nItems:\n• Wireless headphones - $79.99\n"
     "• USB-C cable - $12.99\nDelivery address: 100 Main St, Seattle, WA\n\n"
     "Track your package or view order details in your account.\n\n"
     "Need help? Visit Help → Your Orders.\n\nAmazon.com Services LLC, "
     "410 Terry Ave N, Seattle, WA 98109"),

    ("Order confirmation - Best Buy #BBY01-806548432",
     "Hi {name},\n\nThanks for your order! We received your order on June 18 "
     "and it is now being prepared for shipment.\n\nOrder #: BBY01-806548432\n"
     "Subtotal: $349.99\nShipping: Free\nTax: $28.87\nTotal: $378.86\n\n"
     "Estimated delivery: June 22-24\n\nYou will receive a separate email "
     "once your order ships. Manage your order in Your Account.\n\n"
     "Best Buy Co., Inc."),

    ("[GitHub] New comment on PR #482",
     "@octocat commented on #482 in your repository:\n\n> Looks good, "
     "I'll review the test changes tomorrow. One small suggestion: can we "
     "rename `getCwd` to `getCurrentWorkingDirectory` for consistency?\n\n"
     "View it on GitHub: https://github.com/your-org/your-repo/pull/482\n\n"
     "You are receiving this because you authored the thread.\n"
     "Reply to this email directly, view it on GitHub, or unsubscribe."),

    ("[GitHub] Build succeeded on main",
     "Workflow run completed:\n\n• Repository: your-org/your-repo\n"
     "• Branch: main\n• Workflow: CI\n• Result: success\n"
     "• Duration: 2m 47s\n• Commit: a3f2c19 - Update dependencies\n\n"
     "View details: https://github.com/your-org/your-repo/actions/runs/789456\n\n"
     "You are receiving this because you enabled email notifications "
     "for workflow runs. Manage notifications in your settings."),

    ("Your Stripe receipt [#3982-1948]",
     "Hi {name},\n\nThanks for your payment. Here is your receipt.\n\n"
     "Amount paid: $49.00\nDate paid: June 18, 2026\nPayment method: Visa "
     "ending in 4242\nDescription: Monthly subscription - Pro plan\n\n"
     "Invoice: https://invoice.stripe.com/i/3982_1948\n\n"
     "Stripe Inc., 354 Oyster Point Blvd, South San Francisco, CA 94080\n"
     "Need help? https://support.stripe.com"),

    ("Your monthly invoice from AWS",
     "Hi {name},\n\nYour AWS bill for May 2026 is now available.\n\n"
     "Total: $127.43\nUsage period: May 1 - May 31, 2026\nAccount ID: "
     "123456789012\n\nView your invoice and detailed usage in the Billing "
     "console: https://console.aws.amazon.com/billing/\n\n"
     "Amazon Web Services, Inc., 410 Terry Ave N, Seattle, WA 98109"),

    ("[Slack] You have 3 new messages in #engineering",
     "Hi {name},\n\nYou have unread messages in your workspace:\n\n"
     "#engineering (3 new messages):\n@mike: Can someone review my PR when "
     "they have a moment?\n@sarah: The deployment looks good, metrics are "
     "stable\n@dave: I will pick this up after lunch\n\n"
     "View in Slack: https://your-team.slack.com\n\n"
     "Manage notifications | Unsubscribe from these emails\n"
     "Slack Technologies, 500 Howard Street, San Francisco, CA"),

    ("Zoom: Your meeting starts in 15 minutes",
     "Hi {name},\n\nYour meeting 'Sprint Planning' starts in 15 minutes.\n\n"
     "When: Today, 2:00 PM PST\nDuration: 1 hour\nJoin URL: "
     "https://us02web.zoom.us/j/12345678901\nMeeting ID: 123 4567 8901\n"
     "Passcode: 982341\n\nAdd to calendar | Reschedule\n\n"
     "Zoom Video Communications, Inc."),

    ("Calendar invite: Q3 Planning Session",
     "{name2} has invited you to:\n\nQ3 Planning Session\nMonday, July 7, "
     "2026 at 10:00 AM - 11:30 AM PST\nLocation: Conference Room B / "
     "https://meet.google.com/abc-defg-hij\n\nDescription:\nLet's align on "
     "Q3 priorities and team allocation. Please come with your top 3 "
     "initiatives.\n\nRespond: Yes | Maybe | No\nGoogle Calendar"),

    ("Your Apple receipt",
     "Receipt from Apple\n\nApple ID: {name}@icloud.com\nDate: Jun 18, 2026\n"
     "Order ID: ML1H2A3B4C\n\nApp: Things 3 - Task manager\nDeveloper: "
     "Cultured Code GmbH\nPrice: $9.99\nTax: $0.85\nTotal: $10.84\n\n"
     "Payment method: Visa ending in 1234\n\nIf you have questions, visit "
     "https://reportaproblem.apple.com\nApple Inc., One Apple Park Way, "
     "Cupertino, CA 95014"),

    ("Your Netflix payment was successful",
     "Hi {name},\n\nThanks for being a Netflix member. We just charged your "
     "payment method for your next month of service.\n\n"
     "Amount: $15.49 USD\nDate: June 18, 2026\nPlan: Standard with ads\n"
     "Payment method: Mastercard ending in 8821\n\nManage your account: "
     "netflix.com/youraccount\n\nQuestions? Visit netflix.com/help\n\n"
     "Netflix, Inc., 121 Albright Way, Los Gatos, CA 95032"),

    ("Your Uber Eats order is on the way",
     "Hi {name},\n\nYour order from Chipotle Mexican Grill is on the way. "
     "Estimated arrival: 6:42 PM (in about 12 minutes).\n\n"
     "Order #: UE-AB12-CD34\nDriver: Marcus, Toyota Camry, plate 7XJ-K23\n\n"
     "Track your order in the Uber Eats app or rate your experience after "
     "delivery.\n\nUber Technologies, Inc."),

    ("DocuSign: Please sign the Mutual NDA",
     "{name2} ({name2}@acme.com) has requested your signature on:\n\n"
     "Document: Mutual Non-Disclosure Agreement\nRequested: June 18, 2026\n"
     "Expires: July 2, 2026\n\nReview and sign:\nhttps://app.docusign.com/"
     "signing/documents/82d4e1c9-...\n\nIf you have questions about the "
     "agreement, contact the sender directly. Otherwise, click the link to "
     "review and sign.\n\nDocuSign, Inc., 221 Main St, San Francisco, CA"),

    ("Your monthly statement - Chase Sapphire",
     "Hi {name},\n\nYour Chase Sapphire Preferred statement for the period "
     "ending June 15, 2026 is now available.\n\n"
     "Statement balance: $1,243.87\nMinimum payment due: $35.00\n"
     "Payment due date: July 12, 2026\n\nView statement or pay your bill: "
     "Sign in to chase.com or the Chase Mobile app.\n\n"
     "If you didn't make these charges, please contact us at the number on "
     "the back of your card.\n\nChase Cardmember Services"),

    ("Your weekly summary from Notion",
     "Hi {name},\n\nHere's your activity summary for the week of June 11-17:\n"
     "• 12 pages edited\n• 4 new pages created\n• 23 comments and mentions\n"
     "• 2 databases updated\n\nTop pages: 'Q3 Roadmap', 'Engineering Wiki', "
     "'Hiring Plan 2026'.\n\nView your workspace: notion.so\n"
     "Unsubscribe from weekly summaries\n\nNotion Labs, Inc., "
     "2300 Harrison St, San Francisco, CA"),

    ("Your LinkedIn weekly summary",
     "Hi {name},\n\nHere's what you might have missed this week:\n\n"
     "• 47 people viewed your profile (+12% from last week)\n"
     "• 3 of your connections started new positions\n"
     "• 8 new job recommendations for Software Engineer roles\n\n"
     "See your full summary on LinkedIn.\n\n"
     "You are receiving Activity Broadcasts emails. Unsubscribe | "
     "Help. © 2026 LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA"),

    ("Lyft: Thanks for riding with us",
     "Thanks for riding with Marcus on June 18!\n\n"
     "Pickup: 100 Main St, Seattle\nDropoff: SeaTac International Airport\n"
     "Distance: 14.2 miles\nDuration: 22 min\nFare: $32.74\n\n"
     "Rate your ride in the app. Need help? Visit help.lyft.com\n\n"
     "Lyft, Inc., 185 Berry Street, San Francisco, CA"),

    ("Spotify Premium: Your payment receipt",
     "Hi {name},\n\nThis is a receipt for your Spotify Premium Individual "
     "subscription.\n\nAmount: $10.99 USD\nNext billing date: July 18, 2026\n"
     "Payment method: Visa ending in 4242\n\nView or manage your account: "
     "spotify.com/account\n\n© 2026 Spotify Technology S.A."),

    ("Confirmation: Your Delta flight reservation",
     "Hi {name},\n\nThanks for booking with Delta. Your reservation is "
     "confirmed.\n\nConfirmation #: H8K2P9\nFlight: DL 442\nFrom: SFO "
     "(San Francisco) - 7:30 AM\nTo: JFK (New York) - 4:05 PM\n"
     "Date: July 15, 2026\nSeat: 14C\n\nCheck in online up to 24 hours "
     "before departure. View itinerary or change your flight in My Trips."
     "\n\nDelta Air Lines, Inc."),

    ("Shopify: Your store had a new order",
     "Order #1187 from {name2}\n\nTotal: $54.99\nItems: 1× Classic Black "
     "Tee (size M)\n\nShipping address:\n{name2} {name}\n123 Elm Street\n"
     "Portland, OR 97201\n\nFulfill in your Shopify admin: "
     "your-store.myshopify.com/admin\n\nShopify International Limited, "
     "Victoria Buildings, Dublin"),

    ("[Datadog] Your weekly usage report",
     "Hi {name},\n\nYour Datadog usage for the week of June 11-17:\n\n"
     "• Custom metrics: 124.5k (78% of plan limit)\n"
     "• Hosts monitored: 47\n• APM traces: 23.1M\n• Logs ingested: 412 GB\n\n"
     "View full report: app.datadoghq.com/billing/usage\n\n"
     "Unsubscribe from weekly usage emails\n\n"
     "Datadog, Inc., 620 8th Avenue, New York, NY 10018"),

    ("Your password was changed",
     "Hi {name},\n\nThis is a confirmation that the password for your "
     "account ({name}@example.com) was changed on June 18, 2026 at 3:42 PM "
     "from a Chrome browser on macOS.\n\nIf you made this change, you can "
     "safely ignore this email.\n\nIf you did NOT make this change, please "
     "go to https://account.example.com/security to secure your account "
     "or contact support.\n\nWe will never ask for your password by email."
     "\n\nThe Security Team"),

    ("Your verification code is 482915",
     "Hi {name},\n\nYour verification code is:\n\n482915\n\n"
     "This code is valid for 10 minutes. If you didn't request a code, "
     "you can safely ignore this email.\n\nWe will never ask you to share "
     "this code with anyone, including support staff.\n\nFor your security, "
     "this code can only be used once."),

    ("Your Coursera receipt - Machine Learning Specialization",
     "Hi {name},\n\nThanks for enrolling in Machine Learning Specialization!\n\n"
     "Receipt #: 8429-5621\nDate: June 18, 2026\nCourse: Machine Learning "
     "Specialization\nProvider: Stanford University & DeepLearning.AI\n"
     "Amount: $49.00/month\n\nStart learning: coursera.org/learn\n\n"
     "Manage your subscription at coursera.org/account.\n\n"
     "Coursera, Inc., 381 East Evelyn Avenue, Mountain View, CA"),

    ("Welcome to Figma - Get started in 3 steps",
     "Hi {name},\n\nWelcome to Figma! We're thrilled to have you join our "
     "design community.\n\nGet started:\n1. Create your first design file\n"
     "2. Invite teammates to collaborate\n3. Explore the Figma Community for "
     "templates\n\nYou are receiving this email because you signed up at "
     "figma.com. To stop receiving onboarding emails, update your email "
     "preferences in Settings → Notifications.\n\n"
     "Figma, Inc., 760 Market Street, San Francisco, CA"),

    # ── Financial / utility statements (real-world banking, mortgage, bills) ─
    ("Your June 2026 mortgage statement is ready",
     "Hello {name},\n\nYour monthly mortgage statement is now available. "
     "Principal balance: $342,891.07. Escrow balance: $4,213.55. "
     "Payment due July 1, 2026: $1,847.23 (Principal $612.40 + Interest "
     "$1,028.91 + Escrow $205.92).\n\nView statement online: "
     "wellsfargo.com/mortgage. Make a one-time payment or set up autopay "
     "from your account.\n\nQuestions? Call 1-800-357-6675.\n\n"
     "Wells Fargo Home Mortgage, Equal Housing Lender."),

    ("Your monthly statement - Chase auto loan",
     "Hi {name},\n\nYour Chase Auto loan statement for May 2026 is now "
     "available.\n\nPrincipal balance: $18,432.51\nNext payment due: "
     "June 28, 2026\nPayment amount: $389.42\nAccount ending in 4827\n\n"
     "View statement or make a payment at chase.com.\n\n"
     "Chase Auto Finance"),

    ("Your PG&E bill is now available",
     "Hi {name},\n\nYour Pacific Gas & Electric bill for the period ending "
     "June 14, 2026 is now available.\n\nAmount due: $127.43\nDue date: "
     "July 8, 2026\nAutopay status: Enrolled\n\nView your bill: "
     "https://m.pge.com/login\n\nGo paperless and save trees. Manage your "
     "delivery preferences online.\n\nPacific Gas and Electric Company"),

    ("Your Comcast Xfinity bill is ready",
     "Hi {name},\n\nYour bill for Internet + Streaming is now available.\n\n"
     "Total: $89.99\nDue: July 5, 2026\nAutopay date: July 3\n\n"
     "View bill at xfinity.com/billing. Manage your services or contact "
     "support 24/7.\n\nComcast Cable Communications, LLC"),

    ("Your home insurance renewal notice",
     "Dear {name},\n\nYour State Farm Homeowners policy is up for renewal "
     "on August 15, 2026.\n\nAnnual premium: $1,247.00\nCoverage period: "
     "Aug 15, 2026 - Aug 15, 2027\nPolicy #: 78-A2-9485\n\nNo action is "
     "needed if you wish to renew. Your premium will be automatically "
     "charged to the payment method on file.\n\nTo make changes, contact "
     "your agent or visit statefarm.com/myaccount.\n\nState Farm Insurance"),

    ("Your Geico auto insurance card",
     "Hi {name},\n\nYour digital insurance card is attached for the policy "
     "period June 20, 2026 - December 20, 2026.\n\nPolicy #: 4291-8765-3120\n"
     "Vehicle: 2022 Toyota Camry\nCoverage: Comprehensive + Collision\n\n"
     "Add your card to Apple Wallet or print a copy.\n\n"
     "Geico, One Geico Plaza, Washington, DC"),

    ("Tax document available: 1099-INT for 2025",
     "Hi {name},\n\nYour 2025 IRS Form 1099-INT is now available for "
     "download.\n\nAccount: Savings ending in 8841\nTotal interest paid: "
     "$1,247.83\n\nSecurely download your tax document by signing in to "
     "your account at fidelity.com/tax. This document will also be "
     "available through TurboTax and H&R Block integrations.\n\n"
     "Fidelity Investments"),

    # ── Security / 2FA recovery codes (these LOOK like phishing but aren't) ─
    ("Your Google 2-Step Verification backup codes",
     "Hi {name},\n\nYou requested backup codes for your Google account "
     "({name}@gmail.com). Store these somewhere safe — each can be used "
     "once to sign in if you don't have access to your phone:\n\n"
     "9482 1734\n2913 8847\n6182 3924\n8419 2731\n3752 9183\n6428 1937\n"
     "5193 8472\n8261 4729\n\nThese codes were generated on June 18, 2026. "
     "If you didn't request them, sign in and revoke them immediately at "
     "myaccount.google.com/security.\n\nThe Google Accounts team"),

    ("Your 1Password Emergency Kit",
     "Hi {name},\n\nThanks for setting up 1Password! Attached is your "
     "Emergency Kit which contains:\n• Your Secret Key (used along with "
     "your password to sign in)\n• Your sign-in address: my.1password.com\n"
     "• Your account email\n\nPrint this and store it somewhere safe like "
     "a fireproof safe or with a trusted family member. You will need it "
     "if you ever lose access to your devices.\n\nNever share your Secret "
     "Key with anyone. 1Password support will never ask for it.\n\n"
     "AgileBits, Inc., 380 Adelaide St W, Toronto, Canada"),

    ("Authenticator code: 729 481",
     "Your verification code is 729 481.\n\nThis code expires in 5 minutes. "
     "Do not share it with anyone — we will never ask for your code by "
     "phone or email.\n\nIf you didn't request this code, change your "
     "password immediately."),

    # ── HR / corporate communications (often confused with phishing) ────────
    ("Your 2026 W-2 is available in Workday",
     "Hi {name},\n\nYour 2025 W-2 tax form is now available in Workday.\n\n"
     "To access:\n1. Sign in to Workday using your corporate SSO\n2. Go to "
     "Pay → Tax Documents\n3. Download your W-2 PDF\n\nIf you have "
     "questions about your W-2, contact Payroll at payroll@yourcompany.com "
     "or visit the HR portal.\n\nYour Company Payroll Team"),

    ("Open enrollment begins next Monday",
     "Hi {name},\n\nAnnual benefits open enrollment runs from June 24 - "
     "July 5, 2026. This is your chance to:\n• Add or remove dependents\n"
     "• Change your medical / dental / vision plan\n• Enroll in or change "
     "your FSA / HSA contributions\n• Update your life insurance beneficiaries\n\n"
     "Log in to the benefits portal via the company intranet to make your "
     "selections. No action is required if you want to keep your current "
     "elections.\n\nQuestions? Email benefits@yourcompany.com."),

    # ── E-commerce variants (more variety beyond Amazon) ────────────────────
    ("Your Etsy order from Sweet & Co has shipped",
     "Hi {name},\n\nGreat news! Your order from Sweet & Co has shipped.\n\n"
     "Order #1234567890\nTracking #: 1Z999AA10123456784 (UPS)\n"
     "Estimated delivery: June 22-24\n\nItems:\n• Hand-painted ceramic mug "
     "(2) - $48.00\n\nTrack your package or contact the seller through "
     "your Etsy account. Etsy, Inc., 117 Adams Street, Brooklyn, NY"),

    ("Order shipped - your Bookshop.org books are on the way",
     "Hi {name},\n\nYour order has shipped! Tracking info:\n• Carrier: "
     "USPS Media Mail\n• Tracking #: 9405511899560120938745\n• Estimated "
     "delivery: June 24-27\n\nItems shipped:\n• Project Hail Mary by Andy "
     "Weir - $14.99\n• The Three-Body Problem by Liu Cixin - $13.49\n\n"
     "Thank you for supporting independent bookstores!\n\nBookshop.org"),

    # ── Calendar / RSVP (different from invite — common notification format) ─
    ("RSVP confirmed: Birthday party on Saturday",
     "Hi {name},\n\n{name2} has invited you to a birthday party!\n\n"
     "📅 Saturday, July 5, 2026 at 7:00 PM\n📍 142 Pine St, Apt 4B, "
     "San Francisco\n\nYour RSVP: Going ✓\n\nView details or change your "
     "response: partiful.com/e/abc123\n\nPartiful"),

    ("Your Calendly meeting is confirmed",
     "Hi {name},\n\nYour 30-min meeting with {name2} is confirmed.\n\n"
     "When: Wednesday, June 25, 2026, 10:00 AM PST\nLocation: Google Meet "
     "(link in calendar invite)\n\nCancel or reschedule: calendly.com/"
     "rescheduling/abcdef\n\nPowered by Calendly"),

    # ── 2026-Q2 hardening: brand-issued transactional patterns that the
    #    PhishFuzzer corpus impersonates a lot. We need real exemplars in
    #    the legit class to keep the brand-name signal balanced.

    ("Your Amazon.com order has shipped",
     "Hello {name},\n\nYour package is on the way! "
     "Your order of \"Sony WH-1000XM5 Wireless Headphones\" has shipped.\n\n"
     "Tracking number: 1Z999AA10123456784\nCarrier: UPS\n"
     "Shipping address: 142 Pine St, San Francisco, CA 94103\n"
     "Estimated delivery: Tuesday, June 24, 2026\n\n"
     "View order details or track your package in Your Orders. "
     "Returns are easy — see our return policy.\n\n"
     "We hope to see you again soon.\nAmazon.com\n\n"
     "Amazon.com Services LLC, 410 Terry Ave N, Seattle, WA 98109"),

    ("Shipped: Your Amazon.com order #114-2876549-1032884",
     "Hello {name},\n\nYour package with \"Logitech MX Master 3S Mouse\" "
     "and \"Anker USB-C Hub\" has shipped via Amazon Logistics.\n\n"
     "Estimated delivery: Wednesday, June 25\n"
     "Tracking ID: TBA325491278749\nShipping address: {name}, "
     "142 Pine St, San Francisco, CA 94103, US\n\n"
     "Track your package or view all order details in Your Orders. "
     "We hope to see you again soon.\n\nAmazon.com"),

    ("Delivered: your Amazon.com package",
     "Hello {name},\n\nYour package was delivered today at 2:34 PM.\n\n"
     "Items in this shipment:\n• Sony WH-1000XM5 Wireless Headphones — 1\n\n"
     "If you have not received your package, please check with neighbours "
     "first, then visit Your Orders to report a problem. "
     "Amazon Customer Service is available 24/7.\n\nThanks for shopping "
     "with us,\nAmazon.com"),

    ("Stripe payout — {amount} has been sent",
     "Hi {name},\n\nYour payout of {amount} USD was sent to your bank "
     "account ending in •••4421.\n\nPayout reference: po_1NhT2k9KsLm4Ab8c\n"
     "Initiated: June 18, 2026\nArrival: Friday, June 20, 2026 (typically "
     "1-2 business days)\n\nView this payout on your Dashboard: "
     "https://dashboard.stripe.com/payouts/po_1NhT2k9KsLm4Ab8c\n\n"
     "Stripe Inc., 354 Oyster Point Blvd, South San Francisco, CA 94080"),

    ("Your Stripe payout was sent",
     "Hi {name},\n\nA payout of {amount} USD was just sent to your bank "
     "account ending in •••4421. Funds should arrive within 1-2 business "
     "days.\n\nView this payout on the Dashboard.\n\n"
     "Stripe Inc., 354 Oyster Point Blvd, South San Francisco, CA"),

    ("Stripe — daily transaction summary",
     "Hi {name},\n\nHere is your transaction summary for June 18, 2026:\n\n"
     "Successful charges: 47\nFailed charges: 2\nDisputes: 0\nTotal "
     "volume: {amount}\nNet (after fees): {amount}\n\nView details on the "
     "Stripe Dashboard.\n\nStripe Inc."),

    ("Please DocuSign: NDA — Project Cobalt",
     "Hello {name},\n\nJane Doe ({name2}@partnerco.com) has sent you a "
     "document to review and sign:\n\n\"NDA — Project Cobalt\"\n\n"
     "Review Documents\n\nDo not share this email — it contains a secure "
     "link to DocuSign that is unique to you. Please do not forward this "
     "email or share the link.\n\nThis envelope was sent through DocuSign. "
     "If you have questions about the document, contact the sender at "
     "{name2}@partnerco.com.\n\nDocuSign, Inc., 221 Main St, San "
     "Francisco, CA 94105"),

    ("Reminder: Please sign \"Vendor MSA 2026\"",
     "Hi {name},\n\nThis is a reminder that you have a document waiting "
     "for your signature in DocuSign.\n\nDocument: Vendor MSA 2026\n"
     "Sender: Procurement Team <procurement@yourcompany.com>\n"
     "Sent: June 16, 2026\nExpires: July 16, 2026\n\nReview Documents in "
     "DocuSign\n\nIf you have already signed, please ignore this reminder. "
     "Otherwise, click the button above to complete signing.\n\nDocuSign, Inc."),

    ("Completed: \"Mutual NDA\" — all parties have signed",
     "Hi {name},\n\nAll parties have signed \"Mutual NDA.\" The fully "
     "executed document is attached to this email and is also available in "
     "your DocuSign account.\n\nSigned by:\n• Jane Doe (jane@partnerco.com) — "
     "Jun 18, 2026 10:14 AM PDT\n• {name} ({name}@yourcompany.com) — "
     "Jun 18, 2026 11:02 AM PDT\n\nThank you for using DocuSign.\n"
     "DocuSign, Inc., 221 Main St, San Francisco, CA"),

    ("Adrian Chen sent you a document to sign via DocuSign",
     "Adrian Chen ({name2}@ridgelinetech.com) has sent you a document to "
     "review and sign.\n\nDocument: Mutual NDA — Project Cobalt\n"
     "Message from Adrian Chen: \"Hi {name}, looping you in on the Cobalt "
     "NDA before our kickoff. Standard form — let me know if anything "
     "needs adjusting.\"\n\nReview Document\n\n"
     "Do Not Share This Email — This email contains a secure link to "
     "DocuSign. Please do not share this email, link, or access code with "
     "others.\n\nAlternate Signing Method — Visit DocuSign.com, click "
     "Access Documents, and enter the security code: A8K2-4F19-LM07.\n\n"
     "About DocuSign — DocuSign, Inc., 221 Main St, San Francisco, CA"),

    ("Your two-step verification backup codes",
     "Hi {name},\n\nYou recently generated new backup codes for two-step "
     "verification on your Google Account. Backup codes are useful when "
     "your phone is unavailable, e.g. when travelling.\n\n"
     "Store the 10 single-use codes somewhere safe (e.g. your password "
     "manager). Each code can be used once and replaces an authenticator "
     "code at sign-in.\n\nIf you did not request new backup codes, review "
     "your account activity at https://myaccount.google.com/security and "
     "change your password.\n\nThanks,\nThe Google Accounts team"),

    ("Your June 2026 mortgage statement is available",
     "Hi {name},\n\nYour June 2026 mortgage statement for loan ending in "
     "•••3294 is now available.\n\n"
     "Principal & interest: $2,431.18\nEscrow (taxes & insurance): $612.40\n"
     "Current monthly payment: $3,043.58\nPayment due date: July 1, 2026\n"
     "Outstanding principal: $389,142.07\n\n"
     "Sign in to chase.com to view your full statement or set up "
     "AutoPay.\n\nJPMorgan Chase Bank, N.A., Equal Housing Lender"),
]


def _instantiate(template: Tuple[str, str], rng: random.Random) -> str:
    """Fill placeholders in a (subject, body) template and return a combined text."""
    subject, body = template
    brand   = rng.choice(_BRANDS)
    amount  = rng.choice(_AMOUNTS)
    name    = rng.choice(_FIRSTNAMES)
    name2   = rng.choice(_FIRSTNAMES)
    url     = _rand_url(rng)

    text = (subject + "\n\n" + body).format(
        brand=brand, amount=amount, name=name, name2=name2, url=url,
    )

    # Occasionally splice in filler text to diversify wording (phishing & legit alike)
    if rng.random() < 0.35:
        text += "\n\n" + rng.choice(_FILLER_FRAGMENTS)
    return text


def generate_content_corpus(seed: int = 42, n_variants: int = 160) -> Tuple[List[str], List[int]]:
    """
    Return (texts, labels) where label = 1 → phishing, 0 → legitimate.
    Each template is instantiated `n_variants` times with randomised placeholders.
    """
    rng = random.Random(seed)

    texts:  List[str] = []
    labels: List[int] = []

    for tmpl in _PHISHING_TEMPLATES:
        for _ in range(n_variants):
            texts.append(_instantiate(tmpl, rng))
            labels.append(1)

    # Match the legitimate count to the phishing count so the corpus is balanced.
    n_phishing = len(texts)
    per_legit  = max(1, n_phishing // len(_LEGIT_TEMPLATES))
    for tmpl in _LEGIT_TEMPLATES:
        for _ in range(per_legit):
            texts.append(_instantiate(tmpl, rng))
            labels.append(0)

    # Light shuffle for good measure
    combined = list(zip(texts, labels))
    rng.shuffle(combined)
    texts, labels = zip(*combined)

    return list(texts), list(labels)


def _build_vectorizer() -> FeatureUnion:
    """
    Word + char-n-gram FeatureUnion.
    Char n-grams catch leetspeak/homoglyph tricks (P@yP@l, Amaz0n, paypa1).
    """
    word_tfidf = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=3,
        max_df=0.95,
        sublinear_tf=True,
        stop_words="english",
        max_features=40_000,
    )
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=5,
        max_df=0.95,
        sublinear_tf=True,
        lowercase=True,
        max_features=40_000,
    )
    return FeatureUnion([("word", word_tfidf), ("char", char_tfidf)])


_CACHE_VERSION = "v4.3-2026-brand-saturated-logreg-preferred"  # bump to invalidate stale caches


def _cache_path() -> Path:
    return _DEFAULT_DATA_DIR / "content_model_cache.pkl"


def _cache_key(*, use_real, augment_synthetic, n_variants, max_real_rows,
               fast_mode, seed) -> str:
    """A stable key that captures all training-relevant options + dataset fingerprint."""
    sigs = []
    for name, _url, _schema in _DATASETS:
        p = _DEFAULT_DATA_DIR / name
        if p.exists():
            st = p.stat()
            sigs.append(f"{name}:{st.st_size}:{int(st.st_mtime)}")
        else:
            sigs.append(f"{name}:absent")
    ds_sig = "|".join(sigs)
    raw = (f"{_CACHE_VERSION}|{ds_sig}|use_real={use_real}|"
           f"augment={augment_synthetic}|n_variants={n_variants}|"
           f"max_rows={max_real_rows}|fast_mode={fast_mode}|seed={seed}")
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_content_pipeline(
    seed: int          = 42,
    *,
    use_real: bool     = True,
    augment_synthetic: bool = True,
    n_variants: int    = 160,
    max_real_rows: int | None = None,
    auto_download: bool       = True,
    use_cache: bool           = True,
    force_retrain: bool       = False,
    fast_mode: bool           = False,
) -> dict:
    """
    Train the content classifier.

    Args:
      use_real         – attempt to load the real phishing-email CSV (default True)
      augment_synthetic – if True AND the real corpus is loaded, also mix in
                          the template-based synthetic samples (helps cover
                          attacker tactics that are under-represented in the
                          public dataset, e.g. tech-support pop-ups, IRS scam
                          with very specific keywords).
      n_variants       – synthetic samples per template (when used)
      max_real_rows    – optional cap on real-corpus size for faster startup
      auto_download    – if real CSV is missing, fetch it from the HF mirror
      use_cache        – load a previously trained pipeline from disk if its
                         cache-key matches (massive speed-up at startup)
      force_retrain    – ignore any cache and train from scratch
      fast_mode        – evaluate only Logistic Regression with one worker;
                         intended for memory-constrained demo builds
    """
    if use_real and auto_download:
        ensure_real_dataset()

    cache_key  = _cache_key(use_real=use_real, augment_synthetic=augment_synthetic,
                            n_variants=n_variants, max_real_rows=max_real_rows,
                            fast_mode=fast_mode, seed=seed)
    cache_path = _cache_path()

    if use_cache and not force_retrain and cache_path.exists():
        try:
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)
            if cached.get("cache_key") == cache_key:
                print(f"Loaded content-model pipeline from cache ({cache_path.name}).")
                return cached["pipeline"]
            else:
                print("Cache key mismatch — retraining content model.")
        except Exception as exc:
            print(f"Cache read failed ({exc}) — retraining.")

    sources: List[str] = []
    texts:  List[str]  = []
    labels: List[int]  = []

    if use_real:
        real = load_real_corpus(max_rows=max_real_rows)
        if real is not None:
            r_texts, r_labels, src = real
            texts.extend(r_texts)
            labels.extend(r_labels)
            sources.append(src)

    if (not texts) or augment_synthetic:
        s_texts, s_labels = generate_content_corpus(seed=seed, n_variants=n_variants)
        texts.extend(s_texts)
        labels.extend(s_labels)
        sources.append(
            f"Synthetic corpus (n={len(s_texts)}: "
            f"{sum(s_labels)} phishing / {len(s_labels)-sum(s_labels)} legitimate)"
        )

    if not texts:
        raise RuntimeError("No training data could be assembled.")

    # Shuffle so train/test split sees a mix of sources
    rng = random.Random(seed)
    combined = list(zip(texts, labels))
    rng.shuffle(combined)
    texts, labels = zip(*combined)
    texts, labels = list(texts), list(labels)

    X_train_txt, X_test_txt, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=seed, stratify=labels,
    )

    vectorizer = _build_vectorizer()
    X_train = vectorizer.fit_transform(X_train_txt)
    X_test  = vectorizer.transform(X_test_txt)

    # ── Model selection ──────────────────────────────────────────────────────
    # Try three competitive linear models and pick the best by 3-fold CV ROC AUC
    # on the TRAINING fold. LinearSVC scores are calibrated via Platt scaling
    # so they emit probabilities; LogReg / ComplementNB are already probabilistic.
    candidates: list[Tuple[str, object]] = [
        ("LogisticRegression",
         LogisticRegression(C=4.0, max_iter=2000, solver="liblinear",
                            class_weight="balanced")),
    ]
    if not fast_mode:
        candidates.extend([
            ("CalibratedLinearSVC",
             CalibratedClassifierCV(
                 estimator=LinearSVC(C=1.0, class_weight="balanced", max_iter=4000),
                 method="sigmoid", cv=3)),
            ("ComplementNB", ComplementNB(alpha=0.3)),
        ])

    cv_results = []
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=seed)
    print("Model selection — 3-fold CV ROC AUC on the training fold:")
    for name, est in candidates:
        t0 = time.time()
        scores = cross_val_score(
            est, X_train, y_train, cv=cv, scoring="roc_auc",
            n_jobs=1 if fast_mode else -1,
        )
        mean = float(scores.mean())
        std  = float(scores.std())
        cv_results.append({"name": name, "cv_auc_mean": round(mean, 4),
                            "cv_auc_std": round(std, 4),
                            "elapsed_s": round(time.time() - t0, 1)})
        print(f"  {name:<22}  AUC = {mean:.4f} ± {std:.4f}   ({time.time()-t0:.1f}s)")

    # Tie-break: when two candidates are within 0.001 ROC AUC of each other,
    # prefer LogisticRegression because its sigmoid outputs are inherently
    # well-calibrated for boundary samples (whereas Platt-calibrated SVMs can
    # be steep near the decision boundary, producing brittle 50–60% probabilities).
    best_raw = max(cv_results, key=lambda r: r["cv_auc_mean"])
    lr = next((r for r in cv_results if r["name"] == "LogisticRegression"), None)
    if lr is not None and abs(best_raw["cv_auc_mean"] - lr["cv_auc_mean"]) < 0.001:
        best = lr
    else:
        best = best_raw
    best_name = best["name"]
    print(f"Selected best model: {best_name} (CV AUC = {best['cv_auc_mean']:.4f})"
          + ("  [LogReg preferred on tie]" if best is lr and best is not best_raw else ""))
    clf = dict(candidates)[best_name]
    clf.fit(X_train, y_train)

    y_pred  = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "Accuracy":   round(float(accuracy_score(y_test, y_pred)), 4),
        "Precision":  round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "Recall":     round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "F1":         round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "ROC_AUC":    round(float(roc_auc_score(y_test, y_proba)), 4),
        "n_train":    int(len(y_train)),
        "n_test":     int(len(y_test)),
        "data_source": " + ".join(sources),
        "model":      best_name,
        "model_selection": cv_results,
    }

    # Top phishing-indicative terms across the feature space.
    # For models with coefficients (LogReg, LinearSVC) we can introspect.
    # For CalibratedClassifierCV(LinearSVC), each fold has its own SVC; average them.
    feature_names: List[str] = []
    for name, vec in vectorizer.transformer_list:
        if hasattr(vec, "get_feature_names_out"):
            feature_names.extend(
                f"{name}:{t}" for t in vec.get_feature_names_out()
            )
    feature_names_arr = np.array(feature_names)

    coefs = _extract_coefficients(clf)
    if coefs is not None and len(coefs) == len(feature_names_arr):
        top_idx = np.argsort(coefs)[-25:][::-1]
        top_terms = [
            {"term": str(feature_names_arr[i]).split(":", 1)[-1],
             "kind": str(feature_names_arr[i]).split(":", 1)[0],
             "weight": round(float(coefs[i]), 4)}
            for i in top_idx
        ]
    else:
        top_terms = []

    pipeline = {
        "vectorizer": vectorizer,
        "clf":        clf,
        "metrics":    metrics,
        "top_terms":  top_terms,
    }

    # Persist cache for fast subsequent startups
    if use_cache:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "wb") as f:
                pickle.dump({"cache_key": cache_key, "pipeline": pipeline}, f)
            size_mb = cache_path.stat().st_size / 1e6
            print(f"Saved content-model cache → {cache_path.name} ({size_mb:.1f} MB)")
        except Exception as exc:
            print(f"Could not write cache: {exc}")

    return pipeline


def build_content_pipeline_from_env(seed: int = 42) -> dict:
    """Build the content model using deployment-friendly environment settings.

    ``PHISHGUARD_DEPLOYMENT_PROFILE=free-demo`` keeps the full request/response
    behaviour but avoids downloading the large public corpora on a 512 MB
    hobby instance.  The default profile is unchanged and still uses the full
    real-data pipeline.
    """
    profile = os.getenv("PHISHGUARD_DEPLOYMENT_PROFILE", "full").strip().lower()
    free_demo = profile in {"free", "free-demo", "demo"}

    def env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def env_int(name: str, default: int) -> int:
        raw = os.getenv(name)
        if raw is None:
            return default
        try:
            return max(1, int(raw))
        except ValueError:
            return default

    use_real = env_bool("CONTENT_MODEL_USE_REAL", not free_demo)
    max_rows_raw = os.getenv("CONTENT_MODEL_MAX_REAL_ROWS", "").strip()
    try:
        max_real_rows = max(1, int(max_rows_raw)) if max_rows_raw else None
    except ValueError:
        max_real_rows = None

    return build_content_pipeline(
        seed=seed,
        use_real=use_real,
        augment_synthetic=env_bool("CONTENT_MODEL_AUGMENT_SYNTHETIC", True),
        n_variants=env_int("CONTENT_MODEL_N_VARIANTS", 24 if free_demo else 160),
        max_real_rows=max_real_rows,
        auto_download=env_bool("CONTENT_MODEL_AUTO_DOWNLOAD", not free_demo),
        use_cache=True,
        fast_mode=env_bool("CONTENT_MODEL_FAST_MODE", free_demo),
    )


def _extract_coefficients(clf) -> np.ndarray | None:
    """
    Best-effort extraction of a 1-D coefficient vector for explainability.
    Supports LogisticRegression, ComplementNB (uses class log-prior diff),
    and CalibratedClassifierCV(LinearSVC) — averages SVC coefs across folds.
    """
    if hasattr(clf, "coef_"):
        c = np.asarray(clf.coef_)
        return c[0] if c.ndim == 2 else c
    if isinstance(clf, CalibratedClassifierCV):
        coefs = []
        for cc in clf.calibrated_classifiers_:
            est = getattr(cc, "estimator", None) or getattr(cc, "base_estimator", None)
            if est is not None and hasattr(est, "coef_"):
                coefs.append(np.asarray(est.coef_).ravel())
        if coefs:
            return np.mean(coefs, axis=0)
    if isinstance(clf, ComplementNB):
        # ComplementNB exposes feature_log_prob_ shape (n_classes, n_features)
        flp = clf.feature_log_prob_
        if flp.shape[0] == 2:
            # higher log-prob under "phishing" relative to "legit" → more phishing-like
            return flp[1] - flp[0]
    return None


def _flat_feature_names(vectorizer) -> np.ndarray:
    """Return per-feature names from a single TfidfVectorizer or a FeatureUnion."""
    if hasattr(vectorizer, "transformer_list"):  # FeatureUnion
        names: List[str] = []
        for name, vec in vectorizer.transformer_list:
            if hasattr(vec, "get_feature_names_out"):
                names.extend(f"{name}:{t}" for t in vec.get_feature_names_out())
        return np.array(names)
    return np.array(vectorizer.get_feature_names_out())


def predict_content(pipeline: dict, subject: str, body: str) -> dict:
    """Score one (subject, body) pair. Returns probabilities and feature contributions."""
    text = (subject or "") + "\n" + (body or "")
    X = pipeline["vectorizer"].transform([text])
    proba = pipeline["clf"].predict_proba(X)[0]
    phishing_prob   = float(proba[1])
    legitimate_prob = float(proba[0])
    prediction = int(pipeline["clf"].predict(X)[0])  # 1 = phishing, 0 = legitimate

    # Per-token contribution for this email (for explainability)
    feature_names = _flat_feature_names(pipeline["vectorizer"])
    coefs = _extract_coefficients(pipeline["clf"])
    if coefs is None or len(coefs) != len(feature_names):
        return {
            "ml_phishing_probability":   round(phishing_prob * 100, 1),
            "ml_legitimate_probability": round(legitimate_prob * 100, 1),
            "ml_label":  "Likely Phishing" if prediction == 1 else "Likely Legitimate",
            "ml_prediction":       prediction,
            "ml_top_contributors": [],
        }
    x_dense = X.toarray()[0]
    contribs = x_dense * coefs

    # Top phishing-indicative features present in this email.
    # Only show word-level features in the UI (char n-grams are noisy fragments).
    nz_idx = np.nonzero(x_dense)[0]
    pairs = []
    for i in nz_idx:
        if contribs[i] <= 0:
            continue
        name = str(feature_names[i])
        kind, _, term = name.partition(":")
        if kind == "word":
            pairs.append((term, float(contribs[i])))
    pairs.sort(key=lambda p: p[1], reverse=True)

    # De-duplicate (sub-strings like "verify" and "verify account" are kept
    # only if both add meaningful unique signal — i.e. drop pure substrings)
    seen = set()
    top_contribs = []
    for term, c in pairs:
        if any(term in s and term != s for s in seen):
            continue
        seen.add(term)
        top_contribs.append({"term": term, "contribution": round(c, 4)})
        if len(top_contribs) >= 8:
            break

    return {
        "ml_phishing_probability":   round(phishing_prob * 100, 1),
        "ml_legitimate_probability": round(legitimate_prob * 100, 1),
        "ml_label":                  "Likely Phishing" if prediction == 1 else "Likely Legitimate",
        "ml_prediction":             prediction,
        "ml_top_contributors":       top_contribs,
    }
