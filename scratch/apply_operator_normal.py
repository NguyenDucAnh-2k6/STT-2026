"""One-time operator annotation; defaults to a dry run."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.relabel import relabel_operator_normal

parser = argparse.ArgumentParser()
parser.add_argument("--apply", action="store_true")
args = parser.parse_args()
report = relabel_operator_normal(ROOT/"data_lake", apply=args.apply)
path = ROOT/"scratch"/f"normal_review_{report['annotation_id']}.json"
path.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps({key:value for key,value in report.items() if key != "files"}))
print("report", path)
