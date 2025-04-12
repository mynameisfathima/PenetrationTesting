import os
import yaml
from typing import List, Dict, Any


def load_templates_from_directory(directory: str) -> List[Dict[str, Any]]:
    """
    Loads all YAML files from the specified directory and its subdirectories
    and returns them as a list of parsed dictionaries.

    If no directory is passed, it defaults to the current directory.
    """
    templates = []
    for root, _, files in os.walk(directory):  # Use os.walk for recursive traversal
        for filename in files:
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(root, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    try:
                        data = yaml.safe_load(f)  # Safe load to avoid deserialization attacks
                        if data:
                            templates.append(data)
                    except yaml.YAMLError as e:
                        print(f"[ERROR] Failed to parse YAML file {filename}: {e}")
    return templates




