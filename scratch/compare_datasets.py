import os
import glob
import pandas as pd
import numpy as np

# 1. Load wireshark.csv
ws_path = r"d:\STT 2026\data_lake\raw\date=2026-10-06\wireshark.csv"
df_ws = pd.read_csv(ws_path)

# 2. Load Edge-IIoTset (Selected ML dataset)
edge_path = r"d:\STT 2026\ml_engine\datasets\Edge-IIoTset dataset\Selected dataset for ML and DL\ML-EdgeIIoT-dataset.csv"
df_edge_sample = pd.read_csv(edge_path, nrows=5)

# 3. Load Lakehouse parquet
pq_path = r"d:\STT 2026\data_lake\raw\date=2026-10-06\session_sess_20261006_194502_14172.parquet"
df_pq = pd.read_parquet(pq_path)

print("=== 1. TỔNG QUAN VỀ SỐ LƯỢNG & KÍCH THƯỚC ===")
print(f"wireshark.csv: {len(df_ws):,} dòng, {len(df_ws.columns)} cột, size = {os.path.getsize(ws_path)/1024:.1f} KB")
print(f"Edge-IIoTset sample: {len(df_edge_sample.columns)} cột, file gốc ~ hàng trăm MB")
print(f"Lakehouse parquet (phiên cùng thời điểm): {len(df_pq):,} dòng, {len(df_pq.columns)} cột, size = {os.path.getsize(pq_path)/1024:.1f} KB")

print("\n=== 2. CỘT CỦA WIRESHARK.CSV ===")
print(list(df_ws.columns))

print("\n=== 3. CỘT CỦA LAKEHOUSE PARQUET ===")
print(list(df_pq.columns))

print("\n=== 4. CÁC CỘT CHÍNH CỦA EDGE-IIOTSET ===")
print("Tổng 63 cột:", list(df_edge_sample.columns)[:15], "... (cắt bớt)")

print("\n=== 5. KIỂM TRA ĐỘ CHỒNG LẤP TÊN CỘT ===")
cols_ws = set(df_ws.columns)
cols_pq = set(df_pq.columns)
cols_edge = set(df_edge_sample.columns)

print("Trùng tên giữa wireshark.csv và Lakehouse:", cols_ws.intersection(cols_pq))
print("Trùng tên giữa wireshark.csv và Edge-IIoTset:", cols_ws.intersection(cols_edge))
print("Trùng tên giữa Lakehouse và Edge-IIoTset:", cols_pq.intersection(cols_edge))

print("\n=== 6. CÁC GIAO THỨC TRONG WIRESHARK.CSV VS EDGE-IIOTSET ===")
print("Protocols trong wireshark.csv:\n", df_ws['Protocol'].value_counts())
print("\nEdge-IIoTset chứa các trường giao thức:", 
      [c.split('.')[0] for c in df_edge_sample.columns if '.' in c][:20])
