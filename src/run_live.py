from live_monitor import analyze_live_traffic


print("===================================")
print("      SENTINELAI LIVE MONITOR")
print("===================================")

features = analyze_live_traffic(5)

print("\nLIVE TRAFFIC FEATURES")
print("-----------------------------")

for key, value in features.items():
    print(f"{key}: {value}")