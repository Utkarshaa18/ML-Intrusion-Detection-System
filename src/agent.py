def calculate_risk(
    binary_prediction,
    anomaly_prediction,
    attack_type
):

    risk = 0

    reasons = []

    # --------------------------------------
    # ML CLASSIFIER
    # --------------------------------------

    if binary_prediction == 1:

        risk += 50

        reasons.append(
            "Machine learning classifier "
            "detected suspicious traffic."
        )


    # --------------------------------------
    # ANOMALY DETECTOR
    # --------------------------------------

    if anomaly_prediction == -1:

        risk += 25

        reasons.append(
            "Traffic behavior is anomalous "
            "compared with normal traffic."
        )


    # --------------------------------------
    # ATTACK TYPE
    # --------------------------------------

    attack = str(
        attack_type
    ).lower()


    if "ddos" in attack:

        risk += 25

        reasons.append(
            "DDoS attack pattern detected."
        )


    elif "dos" in attack:

        risk += 20

        reasons.append(
            "Denial-of-Service behavior detected."
        )


    elif "portscan" in attack:

        risk += 15

        reasons.append(
            "Port scanning behavior detected."
        )


    elif "bot" in attack:

        risk += 20

        reasons.append(
            "Possible botnet activity detected."
        )


    elif "brute" in attack:

        risk += 15

        reasons.append(
            "Possible brute-force behavior detected."
        )


    elif "web" in attack:

        risk += 15

        reasons.append(
            "Web attack pattern detected."
        )


    # --------------------------------------
    # LIMIT SCORE
    # --------------------------------------

    risk = min(
        risk,
        100
    )


    # --------------------------------------
    # RISK LEVEL
    # --------------------------------------

    if risk <= 30:

        level = "LOW"


    elif risk <= 60:

        level = "MEDIUM"


    elif risk <= 80:

        level = "HIGH"


    else:

        level = "CRITICAL"


    # --------------------------------------
    # RECOMMENDATION
    # --------------------------------------

    if level == "CRITICAL":

        recommendation = (
            "Immediately investigate the "
            "affected traffic and consider "
            "isolating the suspicious source."
        )


    elif level == "HIGH":

        recommendation = (
            "Investigate the source and "
            "consider blocking or "
            "rate-limiting the traffic."
        )


    elif level == "MEDIUM":

        recommendation = (
            "Monitor the traffic and "
            "inspect related network flows."
        )


    else:

        recommendation = (
            "Traffic appears normal. "
            "Continue monitoring."
        )


    return {

        "risk_score": risk,

        "risk_level": level,

        "reasons": reasons,

        "recommendation": recommendation
    }