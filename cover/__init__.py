"""COVER v3: Counterfactual and Competing-Hypothesis Evidence Recommender.

A knowledge-based, rule-based evidence recommender. It contains NO utility score, EIG objective or
learned policy. The legacy EIG controller lives in cover/legacy_baseline.py and is used only as the
S1/A3 comparator.

Boundary rule: nothing in this package may import from scoring/ or read a *.key.json file.
tests/test_cover_no_leakage.py enforces this.
"""
