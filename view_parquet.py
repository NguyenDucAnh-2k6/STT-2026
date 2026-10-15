import pandas as pd

# Read the Parquet file and save it directly as a CSV
pd.read_parquet(r'ml_engine\datasets\CTU-13\1-Neris-20110810.binetflow.parquet').to_csv(r'output.csv', index=False)
