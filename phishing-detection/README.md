# Phishing Website Detection – ML Pipeline

A reproducible machine-learning benchmark comparing four classifiers on the
**UCI Phishing Websites Dataset** (~11 000 samples, 30 tabular features).

---

## Project Structure

```
phishing-detection/
├── data/
│   ├── phishing_dataset.csv          # UCI URL-feature dataset (auto-downloaded)
│   ├── Phishing_Email.csv            # 18,631 real emails (Kaggle/HF, 2002-2007)
│   ├── CEAS_08.csv                   # 39,127 CEAS 2008 emails (Zenodo)
│   ├── Nazario.csv                   # 1,562 Nazario phishing corpus (Zenodo)
│   ├── phishnchips_*.csv             # optional modern synthetic benchmark data
│   ├── phishfuzzer_*.csv             # optional local PhishFuzzer exports
│   ├── content_model_cache.pkl       # optional trusted offline-training cache
│   └── content_model_artifact.pkl    # versioned web artifact (generated explicitly)
├── notebooks/
│   └── phishing_detection.ipynb      # main notebook (run this)
├── src/
│   ├── preprocess.py                 # loading, cleaning, scaling, splitting
│   ├── train.py                      # model definitions & training loop
│   └── evaluate.py                   # metrics + all four plots
├── requirements.txt
└── README.md
```

---

## Classifiers Compared

| # | Model               | Key Hyperparameters                        |
|---|---------------------|--------------------------------------------|
| 1 | Logistic Regression | `solver='lbfgs'`, `max_iter=1000`          |
| 2 | Random Forest       | `n_estimators=100`, `random_state=42`      |
| 3 | SVM (RBF)           | `kernel='rbf'`, `C=1.0`                    |
| 4 | Decision Tree       | `max_depth=10`, `random_state=42`          |

---

## Metrics Reported

- Accuracy
- Precision (weighted)
- Recall (weighted)
- F1-Score (weighted)
- ROC AUC

---

## Visualisations

1. Grouped bar chart – all metrics across all classifiers  
2. Confusion-matrix heatmaps – one per classifier  
3. ROC curves – all classifiers on a single plot  
4. Feature-importance bar chart – Random Forest top-15 features  

---

## Quick Start

```bash
# 1 – create & activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2 – install dependencies
pip install -r requirements.txt

# 3 – launch the notebook
jupyter notebook notebooks/phishing_detection.ipynb
```

The notebook will **automatically download** the UCI dataset on the first run
and cache it to `data/phishing_dataset.csv`.  If the download fails (no
internet), a synthetic dataset with matching structure is generated instead so
the pipeline still runs end-to-end.

---

## Datasets

### 1. URL-feature dataset (notebook benchmark only)

- **Source:** [UCI ML Repository – Phishing Websites (ID 327)](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **Size:** ~11 055 rows × 30 features + 1 target
- **Label encoding:** `-1` = phishing → remapped to `0`; `1` = legitimate → stays `1`
- **Feature types:** ternary integers `{-1, 0, 1}` encoding URL, domain, and HTML signals

### 2. Email-text datasets (`website/` content classifier)

Three classic public corpora, an optional modern synthetic benchmark, and the
dated Spanish SpaPhish corpus are supported. PhishFuzzer exports are supported
when supplied locally but are not auto-downloaded from an unaudited mirror.

| File | Era | Rows | Phishing/Legit | Source | License |
|------|-----|-----:|----------------|--------|---------|
| `Phishing_Email.csv` | 2002-2007 | 18 631 | 7 309 / 11 322 | [HF: zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) | LGPL-3.0 |
| `CEAS_08.csv` | 2008 | 39 127 | 21 841 / 17 286 | [Zenodo 8339691 (Champa et al. 2024)](https://zenodo.org/records/8339691) | CC-BY-4.0 |
| `Nazario.csv` | 2005-2008 | 1 562 | 1 562 / 0 | [Zenodo 8339691 (Champa et al. 2024)](https://zenodo.org/records/8339691) | CC-BY-4.0 |
| `phishnchips_*.csv` (3 files) | modern | varies | binary | [HF: AreLit/PhishNChips v5.2](https://huggingface.co/datasets/AreLit/PhishNChips) — synthetic email benchmark | See source card |
| `SpaPhish.csv` | 2014-2025 when dated | 1 395 parseable | 731 / 664 | [Mendeley Data v1](https://data.mendeley.com/datasets/hz2d6gz7pc/1) | CC-BY-4.0 |
| `phishfuzzer_*.csv` (3 files) | optional | varies | Phishing/Valid; Spam dropped | Local files only; verify provenance and license before use | Verify source |

Plus ~5 600 template-generated synthetic samples in `content_model.py`
(`n_variants=160` × 35+ templates) covering modern attacker patterns
(tech-support pop-ups, homoglyph obfuscation `P@yP@l`, IRS / lottery
scams) **and** modern brand-issued transactional emails (Amazon shipping
× 3, Stripe payout × 3, DocuSign envelope × 3, Chase mortgage, 2FA
backup codes) that no single public corpus represents well.

The committed web artifact also adds 1,044 unique training-only legitimate hard
negatives from 87 grouped template families after the original train/test split.
These include ordinary workplace updates and personal photo/travel messages;
37 normalized families already found in reserved data are excluded. These are
false-positive controls, not real Gmail/Outlook inbox evidence.

Synthetic data broadens tactic coverage but does not establish real-world
performance. The content pipeline therefore keeps campaign/template families
within a single split, removes normalized duplicates and label conflicts across
all sources, fits TF-IDF inside cross-validation, and selects the candidate
model by PR AUC. SpaPhish rows before 2024 plus undated rows may augment
training; 2024 is threshold validation, and 2025 is a post-selection regression
slice. The latter is a partial rather than strict temporal guarantee because
some training rows lack dates and the slice has been repeatedly inspected.
Reported recall and false-positive rates include Wilson 95% intervals. SpaPhish
is not provider-specific Gmail or Outlook evidence.

---

## Feature Groups (Step 2)

| Group             | Example Features                                              |
|-------------------|---------------------------------------------------------------|
| URL-based         | `having_IP_Address`, `URL_Length`, `having_At_Symbol`, …      |
| Domain-based      | `SSLfinal_State`, `age_of_domain`, `DNSRecord`, `web_traffic` |
| HTML/Content-based| `Iframe`, `RightClick`, `popUpWidnow`, `Favicon`, …           |

---

## Tech Stack

- Python 3.x
- pandas, numpy
- scikit-learn
- matplotlib, seaborn
- Jupyter Notebook
- ucimlrepo (dataset download)
