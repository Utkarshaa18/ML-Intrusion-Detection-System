import pandas as pd
import numpy as np
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    classification_report
)


# ==========================================
# SETTINGS
# ==========================================

DATA_PATH = (
    "data/processed/network_data.parquet"
)

MODEL_PATH = "models"

os.makedirs(
    MODEL_PATH,
    exist_ok=True
)


# ==========================================
# LOAD DATA
# ==========================================

print("Loading processed dataset...")

df = pd.read_parquet(
    DATA_PATH
)

print(
    "Dataset shape:",
    df.shape
)


# ==========================================
# LABELS
# ==========================================

label_column = "Label"

if label_column not in df.columns:

    raise Exception(
        "Label column not found!"
    )


# ==========================================
# FEATURES
# ==========================================

drop_columns = [
    "Label",
    "Binary_Label"
]

X = df.drop(
    columns=drop_columns,
    errors="ignore"
)

y_binary = df["Binary_Label"]

y_attack = df["Label"]


# Only numerical features
X = X.select_dtypes(
    include=["number"]
)


print(
    "\nNumber of features:",
    X.shape[1]
)


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y_binary,
        test_size=0.2,
        random_state=42,
        stratify=y_binary
    )
)


# ==========================================
# MODEL 1
# NORMAL VS ATTACK
# ==========================================

print("\nTraining Normal vs Attack model...")

binary_model = Pipeline([
    (
        "imputer",
        SimpleImputer(
            strategy="median"
        )
    ),

    (
        "model",
        RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        )
    )
])


binary_model.fit(
    X_train,
    y_train
)


binary_predictions = (
    binary_model.predict(X_test)
)


accuracy = accuracy_score(
    y_test,
    binary_predictions
)


print(
    "\nNormal vs Attack Accuracy:",
    round(accuracy * 100, 2),
    "%"
)


print(
    "\nClassification Report:"
)

print(
    classification_report(
        y_test,
        binary_predictions
    )
)


# ==========================================
# MODEL 2
# ATTACK TYPE
# ==========================================

print(
    "\nTraining Attack Type model..."
)


# Use exactly the same rows as X_train
attack_train_labels = (
    y_attack.loc[X_train.index]
)


attack_model = Pipeline([
    (
        "imputer",
        SimpleImputer(
            strategy="median"
        )
    ),

    (
        "model",
        RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        )
    )
])


attack_model.fit(
    X_train,
    attack_train_labels
)


attack_predictions = (
    attack_model.predict(X_test)
)


print(
    "\nAttack type classification completed."
)


# ==========================================
# MODEL 3
# ANOMALY DETECTION
# ==========================================

print(
    "\nTraining Isolation Forest..."
)


# Only BENIGN traffic
benign_data = X[
    y_binary == 0
]


# Limit for faster training
if len(benign_data) > 20000:

    benign_data = benign_data.sample(
        n=20000,
        random_state=42
    )


anomaly_model = Pipeline([
    (
        "imputer",
        SimpleImputer(
            strategy="median"
        )
    ),

    (
        "model",
        IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
    )
])


anomaly_model.fit(
    benign_data
)


print(
    "Isolation Forest trained."
)


# ==========================================
# SAVE MODELS
# ==========================================

joblib.dump(
    binary_model,
    "models/binary_model.pkl"
)

joblib.dump(
    attack_model,
    "models/attack_model.pkl"
)

joblib.dump(
    anomaly_model,
    "models/anomaly_model.pkl"
)


# Save feature names
joblib.dump(
    list(X.columns),
    "models/features.pkl"
)


# ==========================================
# SAVE TEST DATA
# ==========================================

test_data = X_test.copy()

test_data[
    "Actual_Binary"
] = y_test.values

test_data[
    "Actual_Attack"
] = (
    y_attack.loc[X_test.index]
    .values
)


test_data.to_parquet(
    "data/processed/test_data.parquet",
    index=False
)


print("\n========================================")
print("TRAINING COMPLETED SUCCESSFULLY")
print("========================================")

print("\nModels created:")

print(
    "✓ models/binary_model.pkl"
)

print(
    "✓ models/attack_model.pkl"
)

print(
    "✓ models/anomaly_model.pkl"
)

print(
    "✓ models/features.pkl"
)

print(
    "\nTest data saved."
)