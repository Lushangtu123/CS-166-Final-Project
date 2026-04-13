"""
evaluate.py
Metric computation and visualisation for the phishing detection pipeline.

Plots produced
--------------
1. Grouped bar chart – all metrics across all classifiers
2. Confusion-matrix heatmaps – one per classifier
3. ROC curves            – all classifiers on a single axes
4. Feature-importance bar chart – Random Forest top-N features
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
)

# ── Plotting style ─────────────────────────────────────────────────────────────
sns.set_theme(style="whitegrid", palette="muted", font_scale=1.1)
COLORS = sns.color_palette("Set2", n_colors=8)
CLASSIFIER_COLORS = {}   # populated lazily in _assign_colors()


def _assign_colors(names: list) -> dict:
    palette = sns.color_palette("Set2", n_colors=len(names))
    return {name: palette[i] for i, name in enumerate(names)}


# ── Metric computation ─────────────────────────────────────────────────────────

def compute_metrics(results: dict, y_test: pd.Series) -> pd.DataFrame:
    """
    Compute Accuracy, Precision (weighted), Recall (weighted),
    F1 (weighted), and ROC AUC for every classifier.

    Returns a tidy DataFrame with classifiers as rows.
    """
    records = []
    for name, data in results.items():
        y_pred = data["y_pred"]
        y_prob = data["y_prob"]

        records.append({
            "Classifier":  name,
            "Accuracy":    round(accuracy_score(y_test, y_pred), 4),
            "Precision":   round(precision_score(y_test, y_pred, average="weighted", zero_division=0), 4),
            "Recall":      round(recall_score(y_test, y_pred, average="weighted", zero_division=0), 4),
            "F1":          round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 4),
            "ROC AUC":     round(roc_auc_score(y_test, y_prob), 4),
        })

    df = pd.DataFrame(records).set_index("Classifier")
    return df


def highlight_best(metrics_df: pd.DataFrame):
    """
    Return a pandas Styler that highlights the maximum value in each column
    with a green background so the 'best' classifier stands out.
    """
    return metrics_df.style.highlight_max(
        axis=0,
        props="background-color: #b7e4c7; font-weight: bold;",
    ).format("{:.4f}").set_caption("Model Comparison – best value per metric highlighted in green")


# ── Plot 1 – Grouped bar chart ────────────────────────────────────────────────

def plot_metrics_bar(metrics_df: pd.DataFrame, figsize=(14, 6)) -> plt.Figure:
    """Grouped bar chart comparing all metrics across classifiers."""
    metric_cols = ["Accuracy", "Precision", "Recall", "F1", "ROC AUC"]
    n_metrics = len(metric_cols)
    n_classifiers = len(metrics_df)
    x = np.arange(n_metrics)
    bar_width = 0.18
    colors = _assign_colors(metrics_df.index.tolist())

    fig, ax = plt.subplots(figsize=figsize)
    for i, clf_name in enumerate(metrics_df.index):
        offsets = x + (i - n_classifiers / 2 + 0.5) * bar_width
        values = metrics_df.loc[clf_name, metric_cols].values
        bars = ax.bar(offsets, values, width=bar_width, label=clf_name,
                      color=colors[clf_name], edgecolor="white", linewidth=0.6)
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{val:.3f}",
                ha="center", va="bottom", fontsize=7.5, rotation=45,
            )

    ax.set_xticks(x)
    ax.set_xticklabels(metric_cols, fontsize=12)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Classifier Performance Comparison", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.axhline(y=1.0, color="gray", linestyle="--", linewidth=0.8, alpha=0.5)
    fig.tight_layout()
    return fig


# ── Plot 2 – Confusion-matrix heatmaps ────────────────────────────────────────

def plot_confusion_matrices(results: dict, y_test: pd.Series,
                             class_labels=("Phishing", "Legitimate"),
                             figsize_per_clf=(5, 4)) -> plt.Figure:
    """One heatmap per classifier arranged in a single figure row."""
    n = len(results)
    fig, axes = plt.subplots(1, n, figsize=(figsize_per_clf[0] * n, figsize_per_clf[1]))
    if n == 1:
        axes = [axes]

    colors = _assign_colors(list(results.keys()))
    for ax, (name, data) in zip(axes, results.items()):
        cm = confusion_matrix(y_test, data["y_pred"])
        # Normalise to percentage
        cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True)
        annot = np.array([
            [f"{cm[r,c]}\n({cm_pct[r,c]*100:.1f}%)" for c in range(cm.shape[1])]
            for r in range(cm.shape[0])
        ])
        cmap = sns.light_palette(colors[name], as_cmap=True)
        sns.heatmap(
            cm_pct, annot=annot, fmt="", cmap=cmap,
            xticklabels=class_labels, yticklabels=class_labels,
            linewidths=0.5, ax=ax, cbar=False, vmin=0, vmax=1,
        )
        ax.set_title(name, fontsize=11, fontweight="bold")
        ax.set_xlabel("Predicted", fontsize=10)
        ax.set_ylabel("Actual", fontsize=10)

    fig.suptitle("Confusion Matrices", fontsize=14, fontweight="bold", y=1.02)
    fig.tight_layout()
    return fig


# ── Plot 3 – ROC curves ────────────────────────────────────────────────────────

def plot_roc_curves(results: dict, y_test: pd.Series, figsize=(8, 6)) -> plt.Figure:
    """All classifiers' ROC curves on a single plot."""
    fig, ax = plt.subplots(figsize=figsize)
    colors = _assign_colors(list(results.keys()))

    for name, data in results.items():
        fpr, tpr, _ = roc_curve(y_test, data["y_prob"])
        auc = roc_auc_score(y_test, data["y_prob"])
        ax.plot(fpr, tpr, label=f"{name}  (AUC={auc:.4f})",
                color=colors[name], linewidth=2)

    ax.plot([0, 1], [0, 1], "k--", linewidth=1, alpha=0.5, label="Random Baseline")
    ax.fill_between([0, 1], [0, 1], alpha=0.04, color="gray")
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curves – All Classifiers", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    fig.tight_layout()
    return fig


# ── Plot 4 – Feature importance ────────────────────────────────────────────────

def plot_feature_importance(importance_df: pd.DataFrame, top_n: int = 15,
                             figsize=(10, 6)) -> plt.Figure:
    """Horizontal bar chart of the top-N Random Forest feature importances."""
    df = importance_df.head(top_n).copy()[::-1]   # reverse for top-down display
    fig, ax = plt.subplots(figsize=figsize)
    bars = ax.barh(
        df["Feature"], df["Importance"],
        color=sns.color_palette("viridis", n_colors=top_n),
        edgecolor="white", linewidth=0.5,
    )
    for bar, val in zip(bars, df["Importance"]):
        ax.text(val + 0.001, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", fontsize=8.5)

    ax.set_xlabel("Gini Importance", fontsize=12)
    ax.set_title(f"Random Forest – Top {top_n} Feature Importances",
                 fontsize=14, fontweight="bold")
    ax.set_xlim(0, df["Importance"].max() * 1.15)
    fig.tight_layout()
    return fig


# ── Convenience wrapper ────────────────────────────────────────────────────────

def run_full_evaluation(results: dict, y_test: pd.Series,
                         importance_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute metrics, print the styled table, and display all four plots.
    Returns the raw metrics DataFrame.
    """
    metrics_df = compute_metrics(results, y_test)

    print("\n" + "=" * 60)
    print("  CLASSIFICATION METRICS SUMMARY")
    print("=" * 60)
    print(metrics_df.to_string())
    print()

    best_overall = metrics_df.mean(axis=1).idxmax()
    print(f"Best classifier (avg. across all metrics): {best_overall}")

    return metrics_df
