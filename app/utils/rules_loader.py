import json
import os


def load_rules():
    rules_file = os.path.join("data", "rules.json")
    if not os.path.exists(rules_file):
        raise FileNotFoundError(f"Rules file not found at {rules_file}")
    with open(rules_file, "r") as file:
        return json.load(file)["rules"]
