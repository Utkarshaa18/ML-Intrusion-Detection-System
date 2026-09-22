import kagglehub
import os
import glob
import shutil

print("Downloading CIC-IDS2017 dataset...")

dataset_path = kagglehub.dataset_download(
    "dhoogla/cicids2017"
)

print("\nDataset downloaded to:")
print(dataset_path)


parquet_files = glob.glob(
    os.path.join(dataset_path, "**", "*.parquet"),
    recursive=True
)

print("\nParquet files found:", len(parquet_files))

for file in parquet_files:
    print(os.path.basename(file))


os.makedirs("data/raw", exist_ok=True)


for file in parquet_files:

    destination = os.path.join(
        "data/raw",
        os.path.basename(file)
    )

    shutil.copy2(
        file,
        destination
    )

print("\nDataset copied successfully to data/raw/")