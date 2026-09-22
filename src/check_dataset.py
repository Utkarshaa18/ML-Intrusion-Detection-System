import pandas as pd
import glob
import os

# Find parquet files
files = glob.glob("data/raw/*.parquet")

print("Parquet files found:", len(files))

for i, file in enumerate(files):
    print(i, ":", os.path.basename(file))


# Load the first file
print("\nLoading first dataset...")

df = pd.read_parquet(files[0])

print("\n==============================")
print("DATASET INFORMATION")
print("==============================")

print("\nFile:")
print(os.path.basename(files[0]))

print("\nShape:")
print(df.shape)

print("\nColumns:")
for i, column in enumerate(df.columns):
    print(i, ":", column)

print("\nFirst 5 rows:")
print(df.head())

print("\nData types:")
print(df.dtypes)

# Look for label column
print("\nPossible label columns:")

for column in df.columns:
    if "label" in column.lower():
        print(column)