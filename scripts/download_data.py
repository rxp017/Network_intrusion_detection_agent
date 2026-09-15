"""Fetch the pinned public mirror; keep provenance and never overwrite silently."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
REVISION = "161024104f19eea98b5c9aba0499a8fcb867ba1d"
BASE = f"https://media.githubusercontent.com/media/jamshaid120/UNSW_NB15-Complete-dataset/{REVISION}"
NAMES = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
EXPECTED = {
    NAMES[0]: "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    NAMES[1]: "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "raw")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in NAMES:
        target = args.output / name
        if not target.exists():
            print(f"Downloading {name}", flush=True)
            with urlopen(f"{BASE}/{name}", timeout=120) as response:
                content = response.read(60_000_000)
            if not content.decode("utf-8-sig").startswith("id,dur,proto,"):
                raise ValueError(f"Unexpected CSV header in {name}")
            if hashlib.sha256(content).hexdigest() != EXPECTED[name]:
                raise ValueError(f"Pinned checksum mismatch in download: {name}")
            target.with_suffix(".tmp").write_bytes(content)
            target.with_suffix(".tmp").replace(target)
        files[name] = {"url": f"{BASE}/{name}", "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
        if files[name]["sha256"] != EXPECTED[name]:
            raise ValueError(f"Existing file differs from pinned dataset: {name}")
    (args.output / "source.json").write_text(
        json.dumps(
            {
                "dataset": "UNSW-NB15",
                "official_reference": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
                "retrieval": "Public third-party mirror; publisher download requires sign-in. Hashes identify mirror bytes, not publisher authentication.",
                "revision": REVISION,
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("Saved dataset and source.json")


if __name__ == "__main__":
    main()
