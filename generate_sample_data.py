"""
generate_sample_data.py -- Generates synthetic UNSW-NB15 training & testing datasets
with exact feature names, dtypes, and attack categories.
"""

import numpy as np
import pandas as pd

np.random.seed(42)

CLASSES = [
    "Normal",
    "Generic",
    "Exploits",
    "Fuzzers",
    "DoS",
    "Reconnaissance",
    "Analysis",
    "Backdoor",
    "Shellcode",
    "Worms",
]

PROTOS = ["tcp", "udp", "unas", "arp", "ospf", "icmp"]
SERVICES = ["-", "dns", "http", "smtp", "ftp-data", "ftp", "ssh", "pop3"]
STATES = ["FIN", "INT", "CON", "REQ", "RST"]


def generate_dataset(n_samples: int, is_test: bool = False) -> pd.DataFrame:
    # Distribution of classes: Normal is majority, Worms is very rare (<50 in test)
    if is_test:
        class_weights = [0.45, 0.18, 0.12, 0.08, 0.06, 0.05, 0.03, 0.015, 0.01, 0.005]
    else:
        class_weights = [0.45, 0.18, 0.12, 0.08, 0.06, 0.05, 0.03, 0.015, 0.01, 0.005]
    class_weights = np.array(class_weights) / sum(class_weights)

    attack_cats = np.random.choice(CLASSES, size=n_samples, p=class_weights)

    # For testing set, ensure Worms has exactly 44 samples to match limitations.json spec
    if is_test:
        worms_idx = np.where(attack_cats == "Worms")[0]
        if len(worms_idx) > 44:
            attack_cats[worms_idx[44:]] = "Normal"
        elif len(worms_idx) < 44:
            non_worms = np.where(attack_cats != "Worms")[0]
            needed = 44 - len(worms_idx)
            to_replace = np.random.choice(non_worms, size=needed, replace=False)
            attack_cats[to_replace] = "Worms"

    labels = np.where(attack_cats == "Normal", 0, 1)

    data = {
        "id": np.arange(1, n_samples + 1),
        "dur": np.random.exponential(scale=0.5, size=n_samples),
        "proto": np.random.choice(PROTOS, size=n_samples, p=[0.55, 0.30, 0.05, 0.04, 0.04, 0.02]),
        "service": np.random.choice(SERVICES, size=n_samples, p=[0.50, 0.20, 0.15, 0.05, 0.03, 0.03, 0.02, 0.02]),
        "state": np.random.choice(STATES, size=n_samples, p=[0.60, 0.25, 0.10, 0.03, 0.02]),
        "spkts": np.random.poisson(lam=18, size=n_samples) + 1,
        "dpkts": np.random.poisson(lam=16, size=n_samples),
        "sbytes": np.random.poisson(lam=4000, size=n_samples) + 100,
        "dbytes": np.random.poisson(lam=6000, size=n_samples),
        "rate": np.random.exponential(scale=50000, size=n_samples),
        "sttl": np.random.choice([31, 62, 254], size=n_samples, p=[0.2, 0.3, 0.5]),
        "dttl": np.random.choice([0, 29, 60, 252], size=n_samples, p=[0.2, 0.3, 0.3, 0.2]),
        "sload": np.random.exponential(scale=1e6, size=n_samples),
        "dload": np.random.exponential(scale=2e6, size=n_samples),
        "sloss": np.random.poisson(lam=2, size=n_samples),
        "dloss": np.random.poisson(lam=3, size=n_samples),
        "sinpkt": np.random.exponential(scale=10.0, size=n_samples),
        "dinpkt": np.random.exponential(scale=8.0, size=n_samples),
        "sjit": np.random.exponential(scale=50.0, size=n_samples),
        "djit": np.random.exponential(scale=40.0, size=n_samples),
        "swin": np.random.choice([0, 255], size=n_samples, p=[0.3, 0.7]),
        "stcpb": np.random.randint(0, 4000000000, size=n_samples, dtype=np.int64),
        "dtcpb": np.random.randint(0, 4000000000, size=n_samples, dtype=np.int64),
        "dwin": np.random.choice([0, 255], size=n_samples, p=[0.3, 0.7]),
        "tcprtt": np.random.exponential(scale=0.05, size=n_samples),
        "synack": np.random.exponential(scale=0.03, size=n_samples),
        "ackdat": np.random.exponential(scale=0.02, size=n_samples),
        "smean": np.random.randint(40, 1500, size=n_samples),
        "dmean": np.random.randint(40, 1500, size=n_samples),
        "trans_depth": np.random.choice([0, 1, 2], size=n_samples, p=[0.8, 0.18, 0.02]),
        "response_body_len": np.random.poisson(lam=500, size=n_samples),
        "ct_srv_src": np.random.randint(1, 40, size=n_samples),
        "ct_state_ttl": np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.1, 0.6, 0.2, 0.1]),
        "ct_dst_ltm": np.random.randint(1, 30, size=n_samples),
        "ct_src_dport_ltm": np.random.randint(1, 25, size=n_samples),
        "ct_dst_sport_ltm": np.random.randint(1, 20, size=n_samples),
        "ct_dst_src_ltm": np.random.randint(1, 35, size=n_samples),
        "is_ftp_login": np.random.choice([0, 1], size=n_samples, p=[0.98, 0.02]),
        "ct_ftp_cmd": np.random.choice([0, 1, 2], size=n_samples, p=[0.98, 0.015, 0.005]),
        "ct_flw_http_mthd": np.random.choice([0, 1, 2], size=n_samples, p=[0.85, 0.13, 0.02]),
        "ct_src_ltm": np.random.randint(1, 30, size=n_samples),
        "ct_srv_dst": np.random.randint(1, 40, size=n_samples),
        "is_sm_ips_ports": np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01]),
        "attack_cat": attack_cats,
        "label": labels,
    }

    return pd.DataFrame(data)


def main():
    print("Generating synthetic UNSW_NB15_training-set.csv (3000 rows)...")
    train_df = generate_dataset(3000, is_test=False)
    train_df.to_csv("UNSW_NB15_training-set.csv", index=False)

    print("Generating synthetic UNSW_NB15_testing-set.csv (1000 rows)...")
    test_df = generate_dataset(1000, is_test=True)
    test_df.to_csv("UNSW_NB15_testing-set.csv", index=False)

    print("Datasets generated successfully!")


if __name__ == "__main__":
    main()
