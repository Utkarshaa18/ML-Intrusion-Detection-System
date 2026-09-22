import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


# Features that both our dataset and live monitor can provide
LIVE_FEATURES = [
    "duration",
    "total_packets",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes"
]


def prepare_training_data(df):


    data = pd.DataFrame()

    data["duration"] = df["Flow Duration"] / 1_000_000

    data["forward_packets"] = df["Total Fwd Packets"]

    data["backward_packets"] = df["Total Backward Packets"]

    data["total_packets"] = (
        data["forward_packets"] +
        data["backward_packets"]
    )

    print(df.columns.tolist())
    data["forward_bytes"] = df["Fwd Packets Length Total"]

    data["backward_bytes"] = df["Bwd Packets Length Total"]

    data["total_bytes"] = (
        data["forward_bytes"] +
        data["backward_bytes"]
    )

    data["packets_per_second"] = df["Flow Packets/s"]

    data["bytes_per_second"] = df["Flow Bytes/s"]

    data = data.replace([np.inf, -np.inf], np.nan)

    data = data.fillna(0)

    return data


def train_live_model(df):

    print("Preparing live model training data...")

    # Use only BENIGN traffic
    benign = df[
        df["Label"].astype(str).str.upper() == "BENIGN"
    ].copy()

    print("Benign records:", len(benign))

    data = prepare_training_data(benign)

    scaler = StandardScaler()

    X = scaler.fit_transform(data[LIVE_FEATURES])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(X)

    joblib.dump(model, "models/live_isolation_forest.joblib")

    joblib.dump(scaler, "models/live_scaler.joblib")

    print("Live model saved successfully!")


def predict_live(features):

    model = joblib.load(
        "models/live_isolation_forest.joblib"
    )

    scaler = joblib.load(
        "models/live_scaler.joblib"
    )

    data = pd.DataFrame([features])

    # Make sure all required features exist
    for column in LIVE_FEATURES:
        if column not in data.columns:
            data[column] = 0

    data = data[LIVE_FEATURES]

    X = scaler.transform(data)

    prediction = model.predict(X)[0]

    score = model.decision_function(X)[0]

    if prediction == -1:
        result = "SUSPICIOUS"
    else:
        result = "NORMAL"

    return result, score