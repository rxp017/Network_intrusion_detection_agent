# Data provenance and attribution

## Publisher

[UNSW-NB15 dataset — UNSW Canberra](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

The publisher documents 175,341 training records and 82,332 test records, nine attack categories plus Normal, and use of a controlled cyber range. Its download link required Microsoft sign-in during this audit, so this project used a public mirror.

## Retrieval

Mirror: [jamshaid120/UNSW_NB15-Complete-dataset](https://github.com/jamshaid120/UNSW_NB15-Complete-dataset), pinned commit `161024104f19eea98b5c9aba0499a8fcb867ba1d`.

The mirror's filenames are reversed relative to the publisher's split sizes. Training explicitly resolves roles by row counts and records the mapping:

| Mirror filename | Rows | Assigned role | SHA-256 |
|---|---:|---|---|
| UNSW_NB15_testing-set.csv | 175,341 | Training | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| UNSW_NB15_training-set.csv | 82,332 | Test | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |

These hashes identify the bytes retrieved from that pinned mirror. They are not an independent publisher signature. Source URLs, hashes, and effective roles are also stored in `artifacts/metadata.json`.

The downloader verifies known hashes and never silently replaces an existing different dataset. The full files are excluded from Git. The included replay is 40 test examples per class, shuffled with seed 42; its checksum is in `data/replay.json`.

## Rights and citations

Dataset rights remain with Nour Moustafa and Jill Slay. The official page grants academic research use, requires attribution, and directs commercial users to agree terms with the authors. This repository does not relicense the dataset. Consult the publisher page for authoritative terms and links to the required publications.

Publications listed by the publisher:

1. Moustafa, N. and Slay, J. **UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set).** MilCIS, 2015.
2. Moustafa, N. and Slay, J. **The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set.** Information Security Journal: A Global Perspective, 2016.
3. Moustafa, N. et al. **Novel geometric area analysis technique for anomaly detection using trapezoidal area estimation on large-scale networks.** IEEE Transactions on Big Data, 2017.
4. Moustafa, N. et al. **Big data analytics for intrusion detection system: statistical decision-making using finite dirichlet mixture models.** Data Analytics and Decision Support for Cybersecurity, 2017.
5. Sarhan, M., Layeghy, S., Moustafa, N., and Portmann, M. **NetFlow Datasets for Machine Learning-Based Network Intrusion Detection Systems.** BDTA/WiCON proceedings, 2020/2021.

## Superseded synthetic data

The original repository's root CSVs were generated with labels independent of the features. They were unsuitable as intrusion-detection benchmark evidence and have been removed from the active project. Git history preserves the original files. The generator remains explicitly labelled as a synthetic negative control and writes only into ignored `data/synthetic/`.
