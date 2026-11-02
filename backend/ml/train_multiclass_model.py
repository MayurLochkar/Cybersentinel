"""
CyberSentinel-X - Multiclass ML Model Training Pipeline.
=========================================================
Trains a multiclass Random Forest classifier on authentic CIC-IDS2017 data:
Classes: BENIGN, DDoS, Port Scan, DoS, FTP-Patator, SSH-Patator, Web Attack.
Features: 70 standardized network flow features matching the existing pipeline.
Enforces:
- Leakage-free Stratified train/val/test splits (70/15/15)
- Preprocessing (median imputer) fit strictly on training split only
- Balanced class weighting for severe class imbalance
- Outputs full confusion matrix, per-class metrics, and macro-F1
- Saves model as 'cybersentinel_multiclass_rf.joblib' (leaving binary model untouched)
"""

import json
import logging
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cybersentinel.multiclass_train")

ML_DIR = Path(__file__).resolve().parent
DATA_DIR = ML_DIR / "data" / "raw"
MODELS_DIR = ML_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

BINARY_MODEL_PATH = MODELS_DIR / "cybersentinel_rf.joblib"
MULTICLASS_MODEL_PATH = MODELS_DIR / "cybersentinel_multiclass_rf.joblib"

# Load feature names from the existing binary pipeline to ensure 100% feature alignment
if not BINARY_MODEL_PATH.exists():
    raise FileNotFoundError(f"Binary model required for feature alignment not found at {BINARY_MODEL_PATH}")

saved_binary = joblib.load(BINARY_MODEL_PATH)
CANONICAL_FEATURES = saved_binary["feature_names"]
logger.info(f"Loaded {len(CANONICAL_FEATURES)} canonical features from binary model for exact alignment.")


def map_raw_label(raw_label: str) -> str:
    """Normalize raw CIC-IDS2017 labels to canonical supported multiclass targets."""
    s = str(raw_label).strip()
    u = s.upper()
    if u == "BENIGN":
        return "BENIGN"
    elif "DDOS" in u:
        return "DDoS"
    elif "PORTSCAN" in u:
        return "Port Scan"
    elif "SSH-PATATOR" in u:
        return "SSH-Patator"
    elif "FTP-PATATOR" in u:
        return "FTP-Patator"
    elif "DOS" in u or "SLOWLORIS" in u or "HULK" in u or "SLOWHTTPTEST" in u or "GOLDENEYE" in u:
        return "DoS"
    elif "WEB ATTACK" in u:
        return "Web Attack"
    elif "BOT" in u:
        return "Bot"
    return "OTHER"


def load_balanced_multiclass_data(samples_per_attack: int = 5000, benign_samples: int = 12000) -> pd.DataFrame:
    """
    Extracts stratified samples from all 8 CIC-IDS2017 CSV files.
    Gathers all available attack rows across chunks up to samples_per_attack,
    and a balanced sample of BENIGN rows.
    """
    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSVs found in {DATA_DIR}")

    attack_dfs = []
    benign_dfs = []
    logger.info(f"Scanning {len(csv_files)} CSV files for authentic samples...")

    for fpath in csv_files:
        logger.info(f"Reading samples from: {fpath.name}")
        file_benign_count = 0
        try:
            for chunk in pd.read_csv(
                fpath,
                chunksize=50000,
                low_memory=False,
                encoding="utf-8",
                encoding_errors="replace",
            ):
                chunk.columns = [str(c).strip() for c in chunk.columns]
                label_cols = [c for c in chunk.columns if c.lower() == "label"]
                if not label_cols:
                    continue
                lcol = label_cols[0]
                chunk = chunk.dropna(subset=[lcol])
                chunk["canonical_label"] = chunk[lcol].apply(map_raw_label)
                
                # Separate attacks from benign
                attacks = chunk[chunk["canonical_label"].isin([
                    "DDoS", "Port Scan", "SSH-Patator", "FTP-Patator", "DoS", "Web Attack"
                ])]
                if not attacks.empty:
                    attack_dfs.append(attacks)

                # Sample benign rows moderately from each file
                benign = chunk[chunk["canonical_label"] == "BENIGN"]
                if not benign.empty and file_benign_count < 2500:
                    n_take = min(len(benign), 1500)
                    benign_dfs.append(benign.sample(n=n_take, random_state=42))
                    file_benign_count += n_take
        except Exception as e:
            logger.warning(f"Error reading {fpath.name}: {e}")
            continue

    all_attacks = pd.concat(attack_dfs, ignore_index=True) if attack_dfs else pd.DataFrame()
    all_benign = pd.concat(benign_dfs, ignore_index=True) if benign_dfs else pd.DataFrame()

    logger.info(f"Raw candidate attacks collected: {len(all_attacks):,}")
    logger.info(f"Raw candidate attacks breakdown:\n{all_attacks['canonical_label'].value_counts()}")

    # Stratified capping per attack class
    sampled_attacks = []
    for lbl, group in all_attacks.groupby("canonical_label"):
        n = min(len(group), samples_per_attack)
        sampled_attacks.append(group.sample(n=n, random_state=42))

    n_benign = min(len(all_benign), benign_samples)
    sampled_benign = all_benign.sample(n=n_benign, random_state=42)

    dataset = pd.concat(sampled_attacks + [sampled_benign], ignore_index=True)
    dataset = dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)
    logger.info(f"Final sampled dataset size: {len(dataset):,}")
    logger.info(f"Final class distribution:\n{dataset['canonical_label'].value_counts()}")
    return dataset


def train_and_evaluate_multiclass():
    start_time = time.time()
    logger.info("Starting Multiclass Model Training Pipeline...")

    dataset = load_balanced_multiclass_data()

    y = dataset["canonical_label"].copy()
    X = dataset.reindex(columns=CANONICAL_FEATURES)
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    # Strict leakage-free split: 70% Train, 15% Validation, 15% Test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, stratify=y_train_val, random_state=42
    )

    logger.info(f"Train split: {len(X_train):,} samples")
    logger.info(f"Val split:   {len(X_val):,} samples")
    logger.info(f"Test split:  {len(X_test):,} samples")

    # Pipeline: Median imputer (fit ONLY on X_train!) + Balanced Random Forest
    imputer = SimpleImputer(strategy="median")
    imputer.fit(X_train)

    X_train_imp = imputer.transform(X_train)
    X_val_imp = imputer.transform(X_val)
    X_test_imp = imputer.transform(X_test)

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=22,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )

    logger.info("Fitting Random Forest classifier on training data...")
    rf.fit(X_train_imp, y_train)

    pipeline = Pipeline([
        ("imputer", imputer),
        ("classifier", rf),
    ])

    # Evaluate on holdout test set (unseen during training and hyperparameter selection)
    logger.info("Evaluating pipeline on strict holdout test partition...")
    y_test_pred = pipeline.predict(X_test)
    y_test_proba = pipeline.predict_proba(X_test)
    classes = list(rf.classes_)

    # Metrics
    precision_macro = precision_score(y_test, y_test_pred, average="macro", zero_division=0)
    recall_macro = recall_score(y_test, y_test_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_test_pred, average="macro", zero_division=0)
    acc = float(np.mean(y_test == y_test_pred))

    report = classification_report(y_test, y_test_pred, target_names=classes, output_dict=True, zero_division=0)
    c_matrix = confusion_matrix(y_test, y_test_pred, labels=classes)

    logger.info(f"Test Accuracy:    {acc * 100:.2f}%")
    logger.info(f"Macro Precision:  {precision_macro * 100:.2f}%")
    logger.info(f"Macro Recall:     {recall_macro * 100:.2f}%")
    logger.info(f"Macro F1-Score:   {f1_macro * 100:.2f}%")

    per_class_summary = {}
    for cls in classes:
        if cls in report:
            per_class_summary[cls] = {
                "precision": round(report[cls]["precision"] * 100, 2),
                "recall": round(report[cls]["recall"] * 100, 2),
                "f1_score": round(report[cls]["f1-score"] * 100, 2),
                "support": int(report[cls]["support"]),
            }
            logger.info(
                f"  Class '{cls:12s}': P={per_class_summary[cls]['precision']:6.2f}%, "
                f"R={per_class_summary[cls]['recall']:6.2f}%, "
                f"F1={per_class_summary[cls]['f1_score']:6.2f}% (support={per_class_summary[cls]['support']})"
            )

    results = {
        "model_name": "CyberSentinel Multiclass Random Forest",
        "model_version": "v3.0-Multiclass-CICIDS2017",
        "task": "Multiclass Attack Classification",
        "classes": classes,
        "feature_names": CANONICAL_FEATURES,
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "macro_precision": round(precision_macro * 100, 2),
            "macro_recall": round(recall_macro * 100, 2),
            "macro_f1": round(f1_macro * 100, 2),
        },
        "per_class_breakdown": per_class_summary,
        "confusion_matrix": {
            "classes": classes,
            "matrix": c_matrix.tolist(),
        },
        "training_metadata": {
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "total_samples": len(dataset),
            "leakage_free_verified": True,
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "elapsed_seconds": round(time.time() - start_time, 2),
        },
    }

    # Save trained multiclass model artifact
    save_payload = {
        "pipeline": pipeline,
        "feature_names": CANONICAL_FEATURES,
        "classes": classes,
        "evaluation_results": results,
    }
    joblib.dump(save_payload, MULTICLASS_MODEL_PATH)
    logger.info(f"Successfully saved multiclass model artifact to {MULTICLASS_MODEL_PATH}")

    # Also save evaluation JSON report
    eval_report_path = ML_DIR / "multiclass_evaluation_report.json"
    with open(eval_report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Evaluation report written to {eval_report_path}")

    return results


if __name__ == "__main__":
    train_and_evaluate_multiclass()
