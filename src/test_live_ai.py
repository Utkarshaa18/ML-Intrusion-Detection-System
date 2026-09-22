from live_monitor import analyze_live_traffic
from live_model import predict_live
from live_agent import calculate_live_risk


print("===================================")
print("     SENTINELAI LIVE AI TEST")
print("===================================")

print("\nStarting live traffic capture...")
print("Browse a few websites during capture.\n")


# Capture network traffic for 5 seconds
features = analyze_live_traffic(5)


print("\nLive traffic captured!")
print("-----------------------------------")


# Display captured features
for key, value in features.items():
    print(f"{key}: {value}")


print("\nRunning AI anomaly detection...")

# Send traffic to Isolation Forest
result, score = predict_live(features)
risk, level, reasons = calculate_live_risk(
    features,
    result
)

print("\n===================================")
print("       SENTINELAI SECURITY")
print("===================================")

print("Prediction:", result)
print("Risk Score:", risk, "/ 100")
print("Risk Level:", level)

print("\nWhy?")

for reason in reasons:
    print("-", reason)


print("\n===================================")
print("        AI DETECTION RESULT")
print("===================================")

print("Prediction:", result)
print("Anomaly Score:", score)