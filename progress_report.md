# CS 166 Final Project – Progress Report

---

**Project Title:** Phishing Website Detection Using Machine Learning  
**Course:** CS 166 – Information Security  
**GitHub Repository:** https://github.com/Lushangtu123/CS-166-Final-Project  
**Report Date:** April 12, 2026  

---

## 1. Project Overview

Phishing attacks remain one of the most prevalent and damaging forms of cybercrime, tricking users into divulging sensitive credentials by impersonating legitimate websites. This project aims to build a reproducible, end-to-end machine-learning pipeline that automatically classifies websites as **phishing** or **legitimate** based on structural and behavioral features extracted from URLs, domain records, and HTML content.

The project uses the **UCI Phishing Websites Dataset** (ID 327), which contains 11,055 labeled website samples described by 30 tabular features. Each feature is encoded as a ternary integer: −1 (phishing indicator), 0 (suspicious), or 1 (legitimate indicator). The binary target is the `result` column.

**Core objective:** Compare four classical machine-learning classifiers — Logistic Regression, Random Forest, Support Vector Machine (RBF kernel), and Decision Tree — across five standard evaluation metrics (Accuracy, Precision, Recall, F1-Score, ROC AUC), and produce quantitative benchmarks with publication-quality visualizations.

**Tech stack:** Python 3.13, pandas, NumPy, scikit-learn, Matplotlib, Seaborn, Jupyter Notebook, ucimlrepo.

---

## 2. Summary of Activities and Contributions

### 2.1 Accomplished Activities

All core pipeline stages have been implemented, tested, and committed to GitHub.

#### Stage 1 – Dataset Acquisition & Exploratory Data Analysis
- Integrated `ucimlrepo` to programmatically fetch the UCI Phishing Websites Dataset (11,055 rows × 31 columns) with automatic local CSV caching.
- Implemented a three-tier fallback loader: (1) local CSV, (2) live UCI download, (3) synthetic dataset generation — ensuring the pipeline runs in any network environment.
- Conducted EDA: class distribution analysis (44.3 % phishing / 55.7 % legitimate), missing-value audit (zero missing values confirmed), feature-value breakdown per group, and a full 31×31 correlation heatmap.

#### Stage 2 – Feature Engineering & Analysis
- Organized all 30 features into three semantically meaningful groups:
  - **URL-based:** `having_ip_address`, `url_length`, `having_at_symbol`, `double_slash_redirecting`, `prefix_suffix`, `having_sub_domain`, `https_token`, `shortining_service`
  - **Domain-based:** `sslfinal_state`, `domain_registration_length`, `age_of_domain`, `dnsrecord`, `web_traffic`, `page_rank`, `google_index`, `statistical_report`
  - **HTML/Content-based:** `favicon`, `port`, `request_url`, `url_of_anchor`, `links_in_tags`, `sfh`, `submitting_to_email`, `abnormal_url`, `redirect`, `on_mouseover`, `rightclick`, `popupwindow`, `iframe`, `links_pointing_to_page`
- Computed per-group mean absolute Pearson correlation with the target. **Domain-based** features showed the highest predictive signal (mean |r| ≈ 0.37), driven by `sslfinal_state` (|r| = 0.58) and `web_traffic` (|r| = 0.49).

#### Stage 3 – Data Preprocessing
- Dropped rows with missing values (none found; included as a safety step).
- Remapped the target label: −1 → 0 (phishing), 1 → 1 (legitimate).
- Applied stratified 80/20 train-test split (`random_state=42`), yielding 8,844 training and 2,211 test samples.
- Applied `StandardScaler` (fit on training data only, transformed both splits) to normalize features for SVM and Logistic Regression.

#### Stage 4 – Model Training
Four classifiers were trained with the following hyperparameters:

| Classifier          | Key Hyperparameters                               |
|---------------------|---------------------------------------------------|
| Logistic Regression | `solver='lbfgs'`, `max_iter=1000`                 |
| Random Forest       | `n_estimators=100`, `random_state=42`, `n_jobs=-1`|
| SVM (RBF)           | `kernel='rbf'`, `C=1.0`, `probability=True`       |
| Decision Tree       | `max_depth=10`, `random_state=42`                 |

All four models were trained in **2.4 seconds** on an Apple M-series processor.

#### Stage 5 – Evaluation & Visualization
Computed five metrics for each classifier on the held-out test set:

| Classifier          | Accuracy | Precision | Recall | F1-Score | ROC AUC |
|---------------------|----------|-----------|--------|----------|---------|
| **Random Forest**   | **0.9747** | **0.9748** | **0.9747** | **0.9746** | **0.9977** |
| SVM (RBF)           | 0.9516   | 0.9520    | 0.9516 | 0.9515   | 0.9893  |
| Decision Tree       | 0.9480   | 0.9481    | 0.9480 | 0.9480   | 0.9865  |
| Logistic Regression | 0.9285   | 0.9287    | 0.9285 | 0.9284   | 0.9808  |

Produced four publication-quality plots:
1. **Grouped bar chart** – all five metrics across all four classifiers with per-bar value annotations.
2. **Confusion matrix heatmaps** – absolute counts and row-normalised percentages for each classifier.
3. **ROC curves** – all four classifiers overlaid on a single axes with AUC in the legend.
4. **Feature importance chart** – Random Forest Gini importances for the top-15 features.

Top-3 most discriminative features identified by Random Forest:
- `sslfinal_state` (importance = 0.3199) — phishing sites rarely hold valid SSL certificates.
- `url_of_anchor` (importance = 0.2503) — phishing pages use external anchor links heavily.
- `web_traffic` (importance = 0.0708) — legitimate sites appear in traffic rankings.

#### Stage 6 – Software Engineering & Reproducibility
- Modular codebase: `src/preprocess.py`, `src/train.py`, `src/evaluate.py`.
- Jupyter Notebook (`notebooks/phishing_detection.ipynb`) with 35 cells, each preceded by a Markdown explanation header.
- Bonus: radar (spider) chart and per-class `classification_report` for every model.
- Full end-to-end execution verified via `jupyter nbconvert --execute` (completed in < 10 s).
- Project committed and pushed to GitHub: https://github.com/Lushangtu123/CS-166-Final-Project

### 2.2 Planned Activities

The following enhancements are scoped for the final submission:

| Activity | Target |
|----------|--------|
| Hyperparameter tuning via `GridSearchCV` (RF `max_features`, SVM `C`/`gamma`) | Final report |
| Cross-validation (5-fold stratified) for more robust metric estimates | Final report |
| Learning-curve analysis to diagnose bias vs. variance | Final report |
| Extended feature engineering: URL string parsing (e.g., entropy, digit ratio) | Final report |
| Export trained Random Forest model with `joblib` for inference demo | Final report |
| Writeup: comparison with prior literature on phishing detection benchmarks | Final report |

### 2.3 Contribution Breakdown

This project is an **individual submission**. All design, implementation, testing, and documentation were completed by the student.

| Task | Owner |
|------|-------|
| Problem definition & dataset selection | Student |
| `src/preprocess.py` – data loading, cleaning, scaling | Student |
| `src/train.py` – model definitions and training loop | Student |
| `src/evaluate.py` – metrics computation and all visualizations | Student |
| `notebooks/phishing_detection.ipynb` – full notebook with EDA and results | Student |
| `README.md` and `requirements.txt` | Student |
| Git history and GitHub upload | Student |

---

## 3. Issues and Risks

### 3.1 Issues Encountered and Mitigation

| # | Issue | Impact | Mitigation Applied |
|---|-------|--------|--------------------|
| 1 | **Column-name case mismatch.** The `ucimlrepo` library returns all column names in lowercase (e.g., `sslfinal_state`), whereas the original UCI documentation uses mixed case (e.g., `SSLfinal_State`). This caused a `KeyError: 'Result'` at runtime. | Medium – blocked pipeline until resolved. | Added `.lower()` normalization to all column names immediately after loading, both in `load_from_ucimlrepo()` and `load_from_csv()`. All downstream references updated to lowercase. |
| 2 | **macOS system Python pip restriction (PEP 668).** `pip install` failed on the system Python 3.13 due to the externally-managed-environment guard. | Low – one-time setup friction. | Created a project-local virtual environment (`.venv/`) and installed all dependencies there. Added `.venv/` to `.gitignore`. |
| 3 | **Pandas type annotation incompatibility.** The return type hint `-> pd.io.formats.style.Styler` in `evaluate.py` raised `AttributeError` on pandas 3.0.2, as the internal module path changed. | Low – import-time crash, no logic impact. | Removed the verbose type hint; Python duck-typing is sufficient for the Styler return value. |
| 4 | **Missing `id` field warning in notebook cells.** `nbformat` ≥ 5.1 requires each cell to carry a unique `id` field; the original `.ipynb` omitted these, producing `MissingIDFieldWarning` during `nbconvert` execution. | Low – cosmetic warning, no execution failure. | Wrote a normalization script that assigned a random 8-character hex `id` to each cell and bumped `nbformat_minor` to 5. |

### 3.2 Risks and Mitigation Plans

| # | Risk | Likelihood | Severity | Mitigation Plan |
|---|------|------------|----------|-----------------|
| 1 | **Dataset availability.** The UCI ML Repository occasionally experiences downtime, which would prevent fresh dataset downloads. | Low | Medium | The dataset is cached locally as `data/phishing_dataset.csv` after the first run; a synthetic fallback generator is also implemented for fully offline operation. |
| 2 | **Overfitting on tabular ternary features.** Because all features are encoded as {−1, 0, 1}, Decision Tree and Random Forest could memorize training patterns rather than generalizing. | Medium | Medium | Depth limit (`max_depth=10`) is applied to Decision Tree. For the final report, 5-fold cross-validation will be used to detect and quantify overfitting. |
| 3 | **Class imbalance shift.** The current split yields 44.3 % phishing / 55.7 % legitimate — relatively balanced. If a different dataset version introduces more skew, precision-recall metrics could degrade. | Low | Medium | Stratified splitting is already enforced. SMOTE oversampling will be evaluated in the final report if imbalance worsens. |
| 4 | **Feature staleness.** The dataset was collected in 2012. Modern phishing techniques (homograph attacks, HTTPS phishing, fast-flux domains) may not be represented by these 30 features. | High | High | Acknowledged as a project limitation. Planned mitigation: supplement with URL string-entropy features derived from live URL parsing. Results will be contextualized against the dataset's collection date in the final discussion. |

---

## 4. Future Improvements and Extensions

This section outlines concrete directions for improving and extending the project beyond the current scope.

### 4.1 Model & Algorithm Improvements

| Area | Description |
|------|-------------|
| **Hyperparameter optimization** | Replace manual hyperparameter selection with automated search (e.g., `GridSearchCV`, `RandomizedSearchCV`, or Bayesian optimization via `optuna`) to systematically maximize validation performance for all four classifiers. |
| **Ensemble and stacking** | Combine predictions from Logistic Regression, SVM, and Decision Tree into a meta-learner (stacking ensemble) to potentially outperform the standalone Random Forest. |
| **Gradient boosting classifiers** | Benchmark XGBoost, LightGBM, and CatBoost against the current classifiers; these gradient-boosted tree methods frequently achieve state-of-the-art results on tabular data. |
| **Deep learning baselines** | Implement a simple feed-forward neural network (MLP) or a 1-D CNN operating on the raw ternary feature vector to establish a deep-learning comparison point. |
| **Class-imbalance handling** | If the dataset shifts toward greater class imbalance, evaluate SMOTE oversampling, class-weighted loss functions, and threshold-tuning on the precision-recall curve. |

### 4.2 Feature Engineering & Data Quality

| Area | Description |
|------|-------------|
| **Raw URL string features** | Parse the raw URL string to extract entropy (Shannon), digit-to-character ratio, number of special characters, TLD reputation score, and Levenshtein distance to known brand names — all of which are orthogonal to the existing ternary features. |
| **WHOIS and DNS enrichment** | Query live WHOIS records and DNS TTL values at inference time to capture domain registration age and fast-flux indicators that are absent from the 2012 dataset. |
| **HTML and JavaScript analysis** | Extract DOM depth, number of external resources, presence of obfuscated JavaScript (`eval`, `unescape`), and form action URL mismatch — features that directly reflect modern phishing page construction. |
| **Modern dataset integration** | Supplement or replace the UCI 2012 dataset with more recent sources (e.g., PhishTank live feed, OpenPhish, or eBay / PayPal phishing corpora) to capture contemporary attack patterns such as homograph attacks, HTTPS-enabled phishing, and lookalike domains. |
| **Graph-based features** | Model hyperlink structure as a directed graph; centrality measures (PageRank, in-degree) of the target page within its link neighborhood have shown discriminative power in recent literature. |

### 4.3 Robustness and Generalization

| Area | Description |
|------|-------------|
| **Cross-dataset validation** | Train on the UCI dataset and evaluate on an entirely independent phishing corpus (e.g., ISCX-URL-2016) to measure domain-transfer generalization rather than held-out accuracy on the same distribution. |
| **Adversarial robustness testing** | Simulate evasion attacks in which an adversary minimally perturbs feature values (e.g., registers an SSL certificate, slightly increases domain age) to flip the classifier's prediction; measure robustness and retrain with adversarial examples. |
| **Temporal drift analysis** | Split the dataset by collection date (if available) and plot classification performance over time to quantify how rapidly feature distributions shift — directly addressing the "feature staleness" risk identified in Section 3.2. |
| **Calibration assessment** | Use reliability diagrams and Brier scores to assess whether predicted probabilities are well-calibrated, which is critical for downstream risk-scoring applications. |

### 4.4 Explainability and Transparency

| Area | Description |
|------|-------------|
| **SHAP value analysis** | Compute SHAP (SHapley Additive exPlanations) values for every test sample to produce global and per-instance feature attribution explanations, going beyond the Random Forest Gini importance already reported. |
| **LIME explanations** | Apply LIME (Local Interpretable Model-agnostic Explanations) to explain individual classification decisions — especially useful for auditing false negatives (missed phishing sites). |
| **Decision boundary visualization** | Project high-dimensional feature space to 2-D via PCA or t-SNE and overlay decision boundaries from each classifier to provide intuitive insight into model behavior. |

### 4.5 Deployment and Productionization

| Area | Description |
|------|-------------|
| **Model serialization** | Export the best-performing model (Random Forest) and the fitted `StandardScaler` using `joblib` so that inference can be performed on new URLs without retraining. |
| **REST API** | Wrap the inference pipeline in a lightweight FastAPI or Flask service that accepts a raw URL string, extracts features, and returns a phishing probability score and binary verdict. |
| **Browser extension prototype** | Develop a minimal Chrome/Firefox extension that calls the REST API in real time and alerts the user when the active page scores above a configurable phishing-probability threshold. |
| **CI/CD pipeline** | Add GitHub Actions workflows that automatically re-execute the Jupyter Notebook, run unit tests (`pytest`), and upload evaluation artifacts on every push to `main`. |
| **Monitoring and data drift detection** | In a production setting, integrate a drift-detection framework (e.g., Evidently AI) to flag when incoming URL distributions diverge significantly from the training distribution and trigger model retraining. |

### 4.6 Evaluation and Benchmarking

| Area | Description |
|------|-------------|
| **Comparison with prior literature** | Formally tabulate results against published phishing-detection benchmarks (e.g., Mohammad et al. 2012, Sahingoz et al. 2019) to position this project's accuracy and AUC within the research landscape. |
| **Cost-sensitive evaluation** | In a real-world deployment, a false negative (failing to detect a phishing site) is far more costly than a false positive (flagging a legitimate site). Incorporate asymmetric misclassification costs and optimize the decision threshold accordingly. |
| **Statistical significance testing** | Use McNemar's test or a 5×2 cross-validated paired t-test to determine whether performance differences between classifiers are statistically significant, not merely due to random variation in the train/test split. |

---

*End of Progress Report*
