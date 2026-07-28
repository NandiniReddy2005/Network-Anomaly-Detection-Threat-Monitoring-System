import os
import pandas as pd

# Define paths
base_dir = os.path.dirname(os.path.abspath(__file__))
cicids_path = os.path.join(base_dir, '..', 'data', 'cicids2017', 'Monday-WorkingHours.pcap_ISCX.csv')
output_dir = os.path.join(base_dir, '..', 'data', 'processed')

os.makedirs(output_dir, exist_ok=True)

print("Processing CIC-IDS-2017 sample...")
df_cicids = pd.read_csv(cicids_path, nrows=1000)

# Clean column names (strip trailing/leading spaces often found in CIC-IDS)
df_cicids.columns = df_cicids.columns.str.strip()

# Keep a standardized subset for quick backend testing
processed_path = os.path.join(output_dir, 'sample_network_logs.parquet')
df_cicids.to_parquet(processed_path, index=False)

print(f"Step 6 Fully Complete! Processed data saved to: {processed_path}")