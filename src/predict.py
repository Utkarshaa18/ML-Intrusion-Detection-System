import pandas as pd
import joblib

from agent import calculate_risk


# Load models

binary_model = joblib.load(
    "models/binary_model.pkl"
)

attack_model = joblib.load(
    "models/attack_model.pkl"
)

anomaly_model = joblib.load(
    "models/anomaly_model.pkl"
)

features = joblib.load(
    "models/features.pkl"
)


def predict_traffic(row):

    # Convert row into DataFrame

    input_data = pd.DataFrame(
        [row]
    )


    # Keep only trained features
    input_data = input_data.reindex(
        columns=features
    )


    # Normal vs Attack

    binary_prediction = int(
        binary_model.predict(
            input_data
        )[0]
    )


    # Attack type

    attack_prediction = (
        attack_model.predict(
            input_data
        )[0]
    )


    # Anomaly

    anomaly_prediction = int(
        anomaly_model.predict(
            input_data
        )[0]
    )


    # Agent

    result = calculate_risk(
        binary_prediction,
        anomaly_prediction,
        attack_prediction
    )


    result["prediction"] = (
        "SUSPICIOUS"
        if binary_prediction == 1
        else "NORMAL"
    )


    result["attack_type"] = str(
        attack_prediction
    )


    result["anomaly"] = (
        "ANOMALOUS"
        if anomaly_prediction == -1
        else "NORMAL"
    )


    return result