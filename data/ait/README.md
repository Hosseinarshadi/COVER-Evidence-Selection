# AIT Alert Data Set (CSV export)

`alerts_csv.zip` is copied unchanged from https://github.com/ait-aecid/alert-data-set (folder `alerts_csv/`).
Columns: time (unix), name, ip, host, short (alert-type code), time_label (attack phase window or false_positive),
event_label (attack step, or `-` if the alert is not part of the attack).

Data: AIT-ADS, CC BY 4.0 (https://zenodo.org/records/8263181). Repository code: GPL-3.0.
Cite: Landauer, M., Skopik, F., Wurzenberger, M. (2024). Introducing a New Alert Data Set for Multi-Step Attack
Analysis. CSET '24. https://doi.org/10.1145/3675741.3675748 — and Landauer et al. (2023), Maintainable Log Datasets for
Evaluation of Intrusion Detection Systems, IEEE TDSC 20(4).

Rebuild the 20 COVER cases (about 8 minutes; not needed, the built files are in scenarios/):
    python tools/build_ait_cases.py --zip data/ait/alerts_csv.zip --out scenarios/ait_master.json
    python tools/split_scenarios.py scenarios/ait_master.json scenarios/ait
