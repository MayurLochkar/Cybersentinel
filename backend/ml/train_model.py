
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# --------------------------------------------------
# 1. Paths and training settings
# --------------------------------------------------

ML_DIR = Path(__file__).resolve().parent
DATA_DIR = ML_DIR / "data" / "raw"
MODEL_DIR = ML_DIR / "models"

MODEL_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 50_000
SAMPLES_PER_CHUNK = 2_000
MAX_SAMPLES_PER_FILE = 25_000
RANDOM_STATE = 42


# --------------------------------------------------
# 2. Load a manageable sample from each CSV
# --------------------------------------------------

def load_dataset():
    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in: {DATA_DIR}"
        )

    file_samples = []

    print(f"Found {len(csv_files)} CSV files.")

    for file_path in csv_files:
        print(f"\nReading: {file_path.name}")
        chunk_samples = []

        try:
            for chunk in pd.read_csv(
                file_path,
                chunksize=CHUNK_SIZE,
                low_memory=False,
                encoding="utf-8",
                encoding_errors="replace",
            ):
                # Remove extra spaces from column names.
                chunk.columns = [
                    str(column).strip()
                    for column in chunk.columns
                ]

                # Find the label column without case sensitivity.
                label_columns = [
                    column
                    for column in chunk.columns
                    if column.strip().lower() == "label"
                ]

                if not label_columns:
                    raise ValueError(
                        f"No Label column found in {file_path.name}"
                    )

                label_column = label_columns[0]

                # Remove rows with missing labels.
                chunk = chunk.dropna(subset=[label_column])

                # Convert labels to BENIGN or ATTACK.
                labels = (
                    chunk[label_column]
                    .astype(str)
                    .str.strip()
                    .str.upper()
                )

                chunk["Label"] = np.where(
                    labels == "BENIGN",
                    "BENIGN",
                    "ATTACK",
                )

                # Sample rows to limit memory usage.
                sample_count = min(
                    SAMPLES_PER_CHUNK,
                    len(chunk),
                )

                if sample_count > 0:
                    chunk_samples.append(
                        chunk.sample(
                            n=sample_count,
                            random_state=RANDOM_STATE,
                        )
                    )

        except Exception as error:
            raise RuntimeError(
                f"Could not process {file_path.name}: {error}"
            ) from error

        if not chunk_samples:
            print("No usable rows found in this file.")
            continue

        file_df = pd.concat(
            chunk_samples,
            ignore_index=True,
        )

        # Keep a maximum number of samples per CSV.
        if len(file_df) > MAX_SAMPLES_PER_FILE:
            file_df = file_df.sample(
                n=MAX_SAMPLES_PER_FILE,
                random_state=RANDOM_STATE,
            )

        file_samples.append(file_df)
        print(f"Sampled rows: {len(file_df):,}")

    if not file_samples:
        raise ValueError("No usable data could be loaded.")

    dataset = pd.concat(
        file_samples,
        ignore_index=True,
    )

    # Standardize column names.
    dataset.columns = [
        str(column).strip()
        for column in dataset.columns
    ]

    # If duplicate column names exist, keep the first.
    dataset = dataset.loc[
        :, ~dataset.columns.duplicated()
    ]

    # Ensure labels are consistently formatted.
    dataset["Label"] = (
        dataset["Label"].astype(str).str.strip().str.upper()
    )

    print(f"\nTotal sampled rows: {len(dataset):,}")
    print("\nSampled label distribution:")
    print(dataset["Label"].value_counts())

    return dataset


# --------------------------------------------------
# 3. Prepare numeric features
# --------------------------------------------------

def prepare_features(dataset):
    y = dataset["Label"].map(
        lambda label: "BENIGN"
        if label == "BENIGN"
        else "ATTACK"
    )

    # These identifiers should not be model features.
    columns_to_drop = [
        column
        for column in dataset.columns
        if column.lower() in {
            "label",
            "flow id",
            "src ip",
            "source ip",
            "dst ip",
            "destination ip",
            "timestamp",
        }
    ]

    X = dataset.drop(
        columns=columns_to_drop,
        errors="ignore",
    )

    # CICIDS2017 flow features should be numeric.
    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    # Replace infinite values with missing values.
    X = X.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # Remove columns containing no usable numeric values.
    X = X.dropna(
        axis=1,
        how="all",
    )

    # Remove duplicate feature names.
    X = X.loc[:, ~X.columns.duplicated()]

    # Remove constant columns.
    non_constant_columns = [
        column
        for column in X.columns
        if X[column].nunique(dropna=True) > 1
    ]
    X = X[non_constant_columns]

    if X.empty:
        raise ValueError(
            "No usable numeric features remain after cleaning."
        )

    # Remove rows whose labels or features cannot be used.
    valid_rows = y.notna()

    X = X.loc[valid_rows].reset_index(drop=True)
    y = y.loc[valid_rows].reset_index(drop=True)

    if y.nunique() < 2:
        raise ValueError(
            "The sampled dataset contains only one class. "
            "Both BENIGN and ATTACK samples are needed."
        )

    print(f"\nUsable rows: {len(X):,}")
    print(f"Usable numeric features: {X.shape[1]}")
    print("\nClass distribution:")
    print(y.value_counts())

    return X, y


# --------------------------------------------------
# 4. Train and evaluate Random Forest
# --------------------------------------------------

def train_model():
    dataset = load_dataset()
    X, y = prepare_features(dataset)

    class_counts = y.value_counts()

    stratify_labels = (
        y if class_counts.min() >= 2 else None
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=stratify_labels,
    )

    # Impute missing values and train the classifier.
    pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="median"),
            ),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    print("\nTraining Random Forest...")
    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    print("\n========== MODEL EVALUATION ==========")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["BENIGN", "ATTACK"],
            zero_division=0,
        )
    )

    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=["BENIGN", "ATTACK"],
        )
    )

    # Save model and its expected input features together.
    model_path = MODEL_DIR / "cybersentinel_rf.joblib"

    joblib.dump(
        {
            "pipeline": pipeline,
            "feature_names": list(X.columns),
            "classes": list(pipeline.classes_),
            "task": "binary_network_traffic_classification",
        },
        model_path,
    )

    print(f"\nModel saved successfully: {model_path}")


if __name__ == "__main__":
    train_model()
