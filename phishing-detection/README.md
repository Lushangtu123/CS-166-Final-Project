# Phishing Website Detection – ML Pipeline

A reproducible machine-learning benchmark comparing four classifiers on the
**UCI Phishing Websites Dataset** (~11 000 samples, 30 tabular features).

---

## Project Structure

```
phishing-detection/
├── data/
│   └── phishing_dataset.csv          # auto-downloaded on first run
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

## Dataset

- **Source:** [UCI ML Repository – Phishing Websites (ID 327)](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **Size:** ~11 055 rows × 30 features + 1 target
- **Label encoding:** `-1` = phishing → remapped to `0`; `1` = legitimate → stays `1`
- **Feature types:** ternary integers `{-1, 0, 1}` encoding URL, domain, and HTML signals

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
