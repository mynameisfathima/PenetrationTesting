import argparse
import os
import sys
import datetime
from colorama import Fore, Style, init  # Import colorama
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import yaml
import html
from engine.template_parser import load_templates_from_directory
from engine.scanner import Scanner
from banner import show_banner
from jinja import generate_html_report, convert_html_to_pdf,fetch_description_and_recommendation # Import the generate_html_report and pdf function

def main():
    # Initialize colorama
    init(autoreset=True)

    # Show banner at the start
    show_banner()

    parser = argparse.ArgumentParser(
        description="A tool for scanning a target URL using templates."
    )

    parser.add_argument(
        "target_url",
        help="The target URL to scan.",
    )
    parser.add_argument(
        "-t", "--templates",
        default="templates",
        help=(
            "Path to a specific template file or directory containing YAML templates. "
            "Default: templates"
        ),
    )
    parser.add_argument(
        "-tag",
        nargs="+",
        help="Filter templates by tags. Provide one or more tags to filter.",
    )

    # Parse the arguments
    args = parser.parse_args()
    target_url = args.target_url
    templates_path = args.templates
    selected_tags = args.tag
     # Updated templates path logic
    templates_path = args.templates or os.getcwd() 
     
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

    scanner = Scanner(templates)

    # Run the scan
    print(f"Scanning target URL: {target_url}")
    
    results = scanner.scan(target_url)
    if isinstance(results, dict):  # In case only one YAML file is present
        results = [results]

    # Prepare the results for printing and saving
    scan_results = []
    for idx, result in enumerate(results):
        # Colorize "True" or "False"
        if str(result["matched"]) == "True":
            status_color = f"{Fore.GREEN}True{Style.RESET_ALL}"
        else:
            status_color = f"{Fore.RED}False{Style.RESET_ALL}"

        # Print the result with colored "True" or "False"
        print(
            f"[{idx + 1}]{result['name']}: "
            f"[{status_color}]"
            f"[{result['severity'].capitalize()}]"
        )

        # Store the result in the scan_results list
    for idx, result in enumerate(results):
        chatgpt_data = fetch_description_and_recommendation(result['name'], result['severity'])
        scan_results.append({
            "name": html.escape(result['name']),
            "matched": result['matched'],
            "severity": html.escape(result['severity']),
            "url": html.escape(result.get('url', 'N/A')),
            "description": html.escape(chatgpt_data["description"]),
            "recommendation": html.escape(chatgpt_data["recommendation"])
        })

    
    # Structure data for the report
    data = {
        "website": target_url,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": len(scan_results),
        "vulnerabilities": scan_results
    }

    # Generate HTML report with the scan_results
    generate_html_report(data, "scan_report.html")
    convert_html_to_pdf("scan_report.html", "scan_report.pdf")
if __name__ == "__main__":
    main()
