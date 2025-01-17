import json
import logging

import yaml
from dotenv import load_dotenv
from flask import Blueprint, request, jsonify
import os
from app.utils.rules_loader import load_rules
from app.api.custom_logging import log_findings
from app.utils.scan_helpers import parse_file, scan_file


def check_security(file_path, file_type, rules):
    if file_type == "json":
        file_data = load_json(file_path)
    elif file_type == "yaml":
        file_data = load_yaml(file_path)
    elif file_type == "env":
        file_data = load_env(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")

    findings = scan_file(file_data, rules)

    return findings


def load_env(file_path):
    load_dotenv(file_path)
    return dict(os.environ)


def load_json(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def load_rules():
    import os

    rules_file = os.path.join("data", "rules.json")
    if not os.path.exists(rules_file):
        raise FileNotFoundError(f"Rules file not found at {rules_file}")
    with open(rules_file, "r") as file:
        return json.load(file)["rules"]


def load_yaml(file_path):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)

def validate_scan_request(func):
    def wrapper(*args, **kwargs):
        filepath = request.json.get("filepath")
        if not filepath:
            logging.error("Filepath is missing in the request.")
            return jsonify({"error": "Filepath is missing"}), 400
        if not os.path.exists(filepath):
            logging.error(f"File not found: {filepath}")
            return jsonify({"error": "File not found"}), 400
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper

scan_api = Blueprint('scan_api', __name__)

@scan_api.route("/scan", methods=["POST"])
@validate_scan_request
def scan():
    filepath = request.json.get("filepath")

    content, error = parse_file(filepath)
    if error:
        logging.error(f"Error parsing file: {error}")
        return jsonify({"error": error}), 400

    rules = load_rules()
    try:
        findings = scan_file(content, rules)
        log_findings(findings)
    except Exception as e:
        logging.error(f"Error during file scan: {str(e)}")
        return jsonify({"error": "An error occurred during scanning"}), 500

    return jsonify({"issues": findings}), 200


def scan_file_recursive(file_data, rules):
    findings = []

    def recursive_scan(data):
        if isinstance(data, dict):
            for key, value in data.items():
                findings.extend(
                    recursive_scan(value)
                )  # recursive call for nested dicts
        elif isinstance(data, list):
            for item in data:
                findings.extend(
                    recursive_scan(item)
                )  # recursive call for items in lists
        else:
            for rule in rules:
                match_key = rule["match_key"]
                match_value = rule.get("match_value")
                severity = rule["severity"]

                if isinstance(match_value, list):
                    if any(value == data for value in match_value):
                        findings.append((rule["id"], rule["description"], severity))
                elif match_value == data:
                    findings.append((rule["id"], rule["description"], severity))
        return findings

    findings.extend(recursive_scan(file_data))
    print(f"Findings during recursive scan: {findings}")  # Debugging output
    return findings
