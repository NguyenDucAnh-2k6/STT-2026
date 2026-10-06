import pandas as pd

# Read the Parquet file and save it directly as a CSV
pd.read_parquet(r'data_lake\raw\date=2026-10-05\session_sess_20261005_171144_19476.parquet').to_csv(r'output.csv', index=False)
