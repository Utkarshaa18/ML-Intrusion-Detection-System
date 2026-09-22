import pandas as pd
import numpy as np
import glob
import os

# ==========================================
# SETTINGS
# ==========================================

RAW_PATH = "data/raw"
OUTPUT_PATH = "data/processed"

os.makedirs(OUTPUT_PATH, exist_ok=True)

# Number of rows taken from each file
# Keep this at 10000 for the first run
ROWS_PER_FILE = 10000


# ==========================================
# FIND PARQUET FILES
# ==========================================

files = glob.glob(
    os.path.join(RAW_PATH, "*.parquet")
)

print("========================================")
print("CICIDS2017 PREPROCESSING")
print("========================================")

print("\nParquet files found:", len(files))

for file in files:
    print("-", os.path.basename(file))


if len(files) == 0:
    raise Exception(
        "No Parquet files found inside data/raw/"
    )


# ==========================================
# LOAD DATA
# ==========================================

dataframes = []

for file in files:

    print(
        "\nLoading:",
        os.path.basename(file)
    )

    df = pd.read_parquet(
        file
    )

    # Take a sample if file is large
    if len(df) > ROWS_PER_FILE:
        df = df.sample(
            n=ROWS_PER_FILE,
            random_state=42
        )

    print("Rows loaded:", len(df))

    dataframes.append(df)


# ==========================================
# COMBINE ALL FILES
# ==========================================

print("\nCombining datasets...")

df = pd.concat(
    dataframes,
    ignore_index=True
)

print(
    "Combined dataset shape:",
    df.shape
)


# ==========================================
# CLEAN COLUMN NAMES
# ==========================================

df.columns = (
    df.columns
    .str.strip()
    .str.replace(" ", "_")
    .str.replace("/", "_per_")
)


print("\nColumns:")
print(df.columns.tolist())


# ==========================================
# FIND LABEL COLUMN
# ==========================================

label_column = None

for column in df.columns:

    if column.lower() == "label":
        label_column = column
        break


if label_column is None:

    raise Exception(
        "Label column was not found!"
    )


print(
    "\nLabel column:",
    label_column
)


# ==========================================
# CLEAN LABELS
# ==========================================

df[label_column] = (
    df[label_column]
    .astype(str)
    .str.strip()
)


print("\nOriginal attack labels:")

print(
    df[label_column].value_counts()
)


# ==========================================
# CREATE BINARY LABEL
# ==========================================

df["Binary_Label"] = (
    df[label_column]
    .apply(
        lambda x:
        0 if x.upper() == "BENIGN"
        else 1
    )
)


print("\nBinary label distribution:")

print(
    df["Binary_Label"].value_counts()
)


# ==========================================
# REMOVE IDENTIFICATION COLUMNS
# ==========================================

columns_to_remove = [
    "Flow_ID",
    "Source_IP",
    "Destination_IP",
    "Timestamp"
]

removed = []

for column in columns_to_remove:

    if column in df.columns:

        df.drop(
            column,
            axis=1,
            inplace=True
        )

        removed.append(column)


print(
    "\nRemoved columns:",
    removed
)


# ==========================================
# REPLACE INFINITY
# ==========================================

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)


# ==========================================
# CONVERT FEATURES TO NUMERIC
# ==========================================

for column in df.columns:

    if column != label_column:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )


# ==========================================
# REMOVE MISSING VALUES
# ==========================================

before = len(df)

df.dropna(
    inplace=True
)

after = len(df)

print(
    "\nRows removed because of missing values:",
    before - after
)


# ==========================================
# SAVE PROCESSED DATA
# ==========================================

output_file = os.path.join(
    OUTPUT_PATH,
    "network_data.parquet"
)

df.to_parquet(
    output_file,
    index=False
)


print("\n========================================")
print("PREPROCESSING COMPLETED")
print("========================================")

print(
    "Final dataset shape:",
    df.shape
)

print(
    "Saved to:",
    output_file
)

print("\nFinal labels:")

print(
    df[label_column].value_counts()
)