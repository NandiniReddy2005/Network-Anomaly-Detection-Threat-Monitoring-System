import os
import pandas as pd

# Define paths correctly by going up one level from 'app' to 'backend', then into 'data'
base_dir = os.path.dirname(os.path.abspath(__file__))
cicids_path = os.path.join(base_dir, '..', 'data', 'cicids2017', 'Monday-WorkingHours.pcap_ISCX.csv')
unsw_path = os.path.join(base_dir, '..', 'data', 'unsw_nb15', 'UNSW_NB15_training-set.parquet')

print("Loading CIC-IDS-2017 sample...")
df_cicids = pd.read_csv(cicids_path, nrows=100)
print(f"CIC-IDS-2017 loaded successfully! Shape: {df_cicids.shape}")

print("\nLoading UNSW-NB15 sample...")
df_unsw = pd.read_parquet(unsw_path)
print(f"UNSW-NB15 loaded successfully! Shape: {df_unsw.shape}")