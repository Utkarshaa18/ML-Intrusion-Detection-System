def calculate_live_risk(features, prediction):

    risk = 0
    reasons = []

    # AI Anomaly Detection contribution
    if prediction == "SUSPICIOUS":
        risk += 35
        reasons.append("AI anomaly model flagged unusual traffic distribution.")

    total_packets = features.get("total_packets", 0)
    pps = features.get("packets_per_second", 0)
    bps = features.get("bytes_per_second", 0)
    fwd = features.get("forward_packets", 0)
    bwd = features.get("backward_packets", 0)
    unique_dest = features.get("unique_destinations", 0)

    # Volumetric / Flood Indicators
    if pps > 1500:
        risk += 30
        reasons.append(f"Volumetric flood threshold exceeded ({pps:.1f} packets/sec).")
    elif pps > 600:
        risk += 15
        reasons.append(f"Elevated packet transmission rate ({pps:.1f} packets/sec).")

    # Bandwidth Saturation
    if bps > 6_000_000:
        risk += 20
        reasons.append(f"High network throughput volume ({bps / 1_000_000:.2f} MB/s).")
    elif bps > 3_000_000:
        risk += 10
        reasons.append(f"Noticeable high bandwidth activity ({bps / 1_000_000:.2f} MB/s).")

    # Packet Direction Asymmetry (SYN flood / brute force / scanning)
    if total_packets > 30 and bwd == 0:
        risk += 30
        reasons.append("Unidirectional transmission: 100% outbound traffic with zero reply (typical SYN flood / scan).")
    elif total_packets > 80 and (fwd / max(1, total_packets)) > 0.90:
        risk += 20
        reasons.append("Severe packet asymmetry (>90% outbound packets with few server responses).")

    # Destination Fan-out (Reconnaissance / Port Scanning)
    if unique_dest > 200:
        risk += 30
        reasons.append(f"High destination fan-out ({unique_dest} remote hosts contacted, potential port scan/sweep).")
    elif unique_dest > 100:
        risk += 15
        reasons.append(f"Elevated unique destination targets ({unique_dest} endpoints contacted).")

    risk = min(risk, 100)

    if risk <= 25:
        level = "LOW"
    elif risk <= 55:
        level = "MEDIUM"
    elif risk <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    if not reasons:
        reasons.append("Traffic packet rates, bidirectional flows, and connection scopes align with normal baseline.")

    return risk, level, reasons