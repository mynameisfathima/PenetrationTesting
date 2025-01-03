import argparse
import yaml
import os
from engine.template_parser import load_templates_from_directory
from engine.scanner import Scanner


def main():
    parser = argparse.ArgumentParser(
        description="A tool for scanning a target URL using templates."
    )

    parser.add_argument(
        "target_url",
        help="The target URL to scan.",
    )
    parser.add_argument(
        "-t", "--templates",
        default="templates/http",
        help=(
            "Path to a specific template file or directory containing YAML templates. "
            "Default: templates/http"
        ),
    )

    # Parse the arguments
    args = parser.parse_args()

    target_url = args.target_url
    templates_path = args.templates

    # Check and load YAML templates
    if os.path.isfile(templates_path) and templates_path.endswith(".yaml"):
        print(f"Loading specific template: {templates_path}")
        with open(templates_path, "r") as file:
            try:
                templates = [yaml.safe_load(file)]  # Parse the YAML into a dictionary
            except yaml.YAMLError as e:
                print(f"Error parsing YAML file: {e}")
                exit(1)
    elif os.path.isdir(templates_path):
        print(f"Loading all YAML files from directory: {templates_path}")
        templates = load_templates_from_directory(templates_path)
    else:
        print(f"Invalid path: {templates_path}. Ensure it points to a .yaml file or a directory.")
        exit(1)
    # Create the scanner instance
    scanner = Scanner(templates)

    # Run the scan
    print(f"Scanning target URL: {target_url}")
    results = scanner.scan(target_url)

    for idx, result in enumerate(results):
        print(f"Result #{idx + 1}, result for {result['name']}: {result['matched']}")


if __name__ == "__main__":
    main()

