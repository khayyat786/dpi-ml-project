"""Compare machine learning models on unseen capture sessions.

Evaluation is leave-one-session-out: the model is trained on two sessions of
every class and tested on the third. Test flows are classified from their
behavior only (the website name is never a feature), which simulates a hidden
name.

Usage (from the project folder):
    python -m src.train_model            # uses results/dataset_n10.csv
    python -m src.train_model --n 5
"""
import argparse
import sys
import time
from pathlib import Path
from typing import Dict, List

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             classification_report, confusion_matrix, f1_score)
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

from .features import FEATURE_NAMES

SEED = 42


def make_models() -> Dict[str, object]:
    return {
        "Majority guess": DummyClassifier(strategy="most_frequent"),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=SEED),
        "Logistic Regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=3000, class_weight="balanced")),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=SEED,
            n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(random_state=SEED),
    }


def _fit(name: str, model, X, y) -> None:
    if name == "Gradient Boosting":     # no class_weight option: use weights
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)


def evaluate(df: pd.DataFrame) -> dict:
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    groups = df["session"].to_numpy()
    classes = sorted(set(y))
    logo = LeaveOneGroupOut()
    n_folds = logo.get_n_splits(groups=groups)
    if n_folds < 2:
        raise SystemExit("Need at least 2 capture sessions to evaluate.")

    results = {}
    for name in make_models():
        y_true, y_pred, fold_f1, fit_s = [], [], [], 0.0
        pred_s, n_pred = 0.0, 0
        for tr, te in logo.split(X, y, groups):
            model = make_models()[name]
            t0 = time.perf_counter()
            _fit(name, model, X[tr], y[tr])
            fit_s += time.perf_counter() - t0
            t0 = time.perf_counter()
            p = model.predict(X[te])
            pred_s += time.perf_counter() - t0
            n_pred += len(te)
            y_true += list(y[te])
            y_pred += list(p)
            fold_f1.append(f1_score(y[te], p, average="macro",
                                    labels=classes, zero_division=0))
        results[name] = {
            "accuracy": accuracy_score(y_true, y_pred),
            "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
            "macro_f1": f1_score(y_true, y_pred, average="macro",
                                 labels=classes, zero_division=0),
            "macro_f1_fold_mean": float(np.mean(fold_f1)),
            "macro_f1_fold_std": float(np.std(fold_f1)),
            "train_seconds": fit_s / n_folds,
            "predict_ms_per_flow": 1000 * pred_s / max(n_pred, 1),
            "y_true": y_true, "y_pred": y_pred,
        }
    return {"results": results, "classes": classes, "n_folds": n_folds}


def plot_comparison(table: pd.DataFrame, path: Path, n: int) -> None:
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    x = np.arange(len(table))
    ax.bar(x - 0.2, table["macro_f1_fold_mean"], 0.4,
           yerr=table["macro_f1_fold_std"], capsize=3, label="Macro-F1")
    ax.bar(x + 0.2, table["balanced_accuracy"], 0.4,
           label="Balanced accuracy")
    ax.set_xticks(x)
    ax.set_xticklabels(table.index, rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score on unseen sessions")
    ax.set_title(f"Model comparison (first {n} packets, website name hidden)")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_confusion(cm: np.ndarray, classes: List[str], title: str,
                   path: Path) -> None:
    fig, ax = plt.subplots(figsize=(4.6, 4.0))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)))
    ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=30, ha="right")
    ax.set_yticklabels(classes)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title(title, fontsize=10)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def run(n: int = 10, results_dir: str = "results",
        models_dir: str = "models") -> dict:
    res_dir = Path(results_dir)
    df = pd.read_csv(res_dir / f"dataset_n{n}.csv")
    if df.empty:
        raise SystemExit("The dataset is empty. Run src.build_dataset first.")
    out = evaluate(df)
    results, classes = out["results"], out["classes"]

    table = pd.DataFrame({
        name: {k: v for k, v in r.items() if k not in ("y_true", "y_pred")}
        for name, r in results.items()}).T
    table.index.name = "model"
    table.round(4).to_csv(res_dir / f"model_comparison_n{n}.csv")
    plot_comparison(table, res_dir / f"model_comparison_n{n}.png", n)

    real = [m for m in table.index if m != "Majority guess"]
    best = max(real, key=lambda m: table.loc[m, "macro_f1"])
    r = results[best]
    cm = confusion_matrix(r["y_true"], r["y_pred"], labels=classes)
    plot_confusion(cm, classes, f"{best} (unseen sessions)",
                   res_dir / f"confusion_matrix_n{n}.png")
    pd.DataFrame(cm, index=classes, columns=classes).to_csv(
        res_dir / f"confusion_matrix_n{n}.csv")
    report = classification_report(r["y_true"], r["y_pred"], labels=classes,
                                   zero_division=0)
    (res_dir / f"classification_report_n{n}.txt").write_text(
        f"{best}, first {n} packets\n\n{report}", encoding="utf-8")

    # preliminary comparison with the baseline
    n_test = len(r["y_true"])
    maj = results["Majority guess"]
    comp = pd.DataFrame([
        {"system": "Baseline (website name only)", "flows_classified":
         0, "of": n_test, "accuracy": "n/a", "balanced_accuracy": "n/a",
         "macro_f1": "n/a"},
        {"system": "Majority guess", "flows_classified": n_test, "of": n_test,
         "accuracy": round(maj["accuracy"], 4),
         "balanced_accuracy": round(maj["balanced_accuracy"], 4),
         "macro_f1": round(maj["macro_f1"], 4)},
        {"system": f"ML: {best}", "flows_classified": n_test, "of": n_test,
         "accuracy": round(r["accuracy"], 4),
         "balanced_accuracy": round(r["balanced_accuracy"], 4),
         "macro_f1": round(r["macro_f1"], 4)}])
    comp.to_csv(res_dir / f"preliminary_comparison_n{n}.csv", index=False)

    Path(models_dir).mkdir(parents=True, exist_ok=True)
    X = df[FEATURE_NAMES].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    final = make_models()[best]
    _fit(best, final, X, y)
    joblib.dump({"model": final, "features": FEATURE_NAMES, "classes": classes,
                 "n": n}, Path(models_dir) / f"best_model_n{n}.joblib")

    print(f"\nFlows: {len(df)}   classes: {df['label'].value_counts().to_dict()}")
    print(f"Evaluation: leave-one-session-out, {out['n_folds']} folds, "
          f"first {n} packets, website name not used\n")
    show = table[["accuracy", "balanced_accuracy", "macro_f1",
                  "macro_f1_fold_mean", "macro_f1_fold_std",
                  "train_seconds", "predict_ms_per_flow"]].round(3)
    print(show.to_string())
    print(f"\nBest model: {best}\n")
    print(report)
    print("Preliminary comparison (flows whose name is hidden):")
    print(comp.to_string(index=False))
    print(f"\nSaved tables, figures and the model in {results_dir}/ "
          f"and {models_dir}/")
    return {"table": table, "best": best, "classes": classes, "cm": cm,
            "comparison": comp}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Compare ML models")
    ap.add_argument("--n", type=int, default=10, help="packets per flow")
    ap.add_argument("--results", default="results")
    ap.add_argument("--models", default="models")
    args = ap.parse_args(argv)
    run(args.n, args.results, args.models)
    return 0


if __name__ == "__main__":
    sys.exit(main())
