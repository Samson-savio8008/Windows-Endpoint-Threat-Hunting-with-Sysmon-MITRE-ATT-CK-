"""
Download the 18 small host-telemetry datasets listed in scenarios.csv from the
OTRF Security-Datasets repository (MIT licence) and unzip them into ./data/.

Total size is only a few MB. Usage:  python download_data.py
"""
import csv
import io
import urllib.request
import zipfile
from pathlib import Path

BASE = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
        "datasets/atomic/windows/")
DATA_DIR = Path("data")


def main():
    DATA_DIR.mkdir(exist_ok=True)
    with open("scenarios.csv", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        target = DATA_DIR / r["scenario"]
        if target.exists() and any(target.glob("*.json")):
            print(f"skip   {r['scenario']} (already downloaded)")
            continue
        url = BASE + r["zip_path"]
        with urllib.request.urlopen(url, timeout=60) as resp:
            payload = resp.read()
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            z.extractall(target)
        print(f"fetched {r['scenario']} ({len(payload) / 1024:.0f} KB zipped)")
    print(f"\nDone. {len(rows)} scenarios in {DATA_DIR}/")


if __name__ == "__main__":
    main()
