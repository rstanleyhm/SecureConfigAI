import json

import yaml


def parse_file(filepath):
    ext = filepath.rsplit(".", 1)[1].lower()
    with open(filepath, "r") as file:
        try:
            if ext == "json":
                return json.load(file), None
            elif ext == "yaml":
                return yaml.safe_load(file), None
            elif ext == "env":
                content = {}
                for line in file:
                    if line.strip() and not line.startswith("#"):
                        key, value = line.strip().split("=", 1)
                        content[key] = value
                return content, None
        except Exception as e:
            return None, f"Error parsing file: {str(e)}"
    return None, "Unsupported file type"


def scan_file(file_data, rules):
    findings = []

    # Normalize file_data keys to lowercase
    normalized_data = {
        key.lower(): str(value).lower() for key, value in file_data.items()
    }

    for rule in rules:
        match_key = rule["match_key"]
        match_value = rule.get("match_value")
        severity = rule["severity"]

        # Handle match_key as a string or list
        if isinstance(match_key, list):
            # Check if any key in the list exists in normalized_data
            keys_to_check = [key.lower() for key in match_key]
            matched_keys = [key for key in keys_to_check if key in normalized_data]
        else:
            matched_keys = (
                [match_key.lower()] if match_key.lower() in normalized_data else []
            )

        for matched_key in matched_keys:
            file_value = normalized_data[matched_key]

            # Handle match_value as string or list
            if isinstance(match_value, list):
                if file_value in [str(value).lower() for value in match_value]:
                    findings.append((rule["id"], rule["description"], severity))
            elif match_value is None or file_value == str(match_value).lower():
                findings.append((rule["id"], rule["description"], severity))

    return findings
