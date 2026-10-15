import pandas as pd
import re

ws_path = r"d:\STT 2026\data_lake\raw\date=2026-10-06\wireshark.csv"
df = pd.read_csv(ws_path)

# Extract ports
ports = []
for info in df['Info']:
    m = re.search(r'(\d+)\s*>\s*(\d+)', str(info))
    if m:
        ports.append((int(m.group(1)), int(m.group(2))))
    else:
        ports.append((None, None))

df['src_port'], df['dst_port'] = zip(*ports)

print('Total rows:', len(df))
print('Unique src_port count:', df['src_port'].nunique())
print('Unique dst_port count:', df['dst_port'].nunique())
print('\nTop 15 dst_port:\n', df['dst_port'].value_counts().head(15))
print('\nTop 15 src_port:\n', df['src_port'].value_counts().head(15))

# Check keywords in Info
print('\nKeyword occurrences in Info:')
for kw in ['attack', 'scan', 'flood', 'syn', 'rst', 'http', 'mqtt', '1883', '8000']:
    cnt = df['Info'].str.contains(kw, case=False, na=False).sum()
    print(f'Info matching "{kw}": {cnt}')

# Sample Info for different protocols
print('\nSample Info for MQTT:')
print(df[df['Protocol'] == 'MQTT']['Info'].head(5).tolist())

print('\nSample Info for HTTP:')
print(df[df['Protocol'].str.contains('HTTP')]['Info'].tolist())

print('\nCheck non-loopback IPs:')
non_lb = df[(df['Source'] != '127.0.0.1') & (df['Source'] != '::1')]
print('Non-loopback source count:', len(non_lb))
