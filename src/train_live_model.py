import pandas as pd
import os

from live_model import train_live_model


# Path to benign CIC-IDS2017 traffic
file_path = "data/raw/Benign-Monday-no-metadata.parquet"


print("===================================")
print("   SENTINELAI LIVE MODEL TRAINING")
print("===================================")

print("\nLoading dataset...")

df = pd.read_parquet(file_path)

print("Dataset loaded!")
print("Rows:", len(df))
print("Columns:", len(df.columns))


print("\nTraining Isolation Forest...")

train_live_model(df)

print("\n===================================")
print("   LIVE MODEL TRAINING COMPLETE")
print("===================================")