from typing import List, Dict, Any
import datetime

def process_scan_results(results: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
    """
    Process scan results to prepare data for reporting.

    Args:
        results (List[Dict[str, Any]]): List of scan result dictionaries.
        target_url (str): The URL that was scanned.

    Returns:
        Dict[str, Any]: Processed data for the report.
    """
    vulnerabilities = []
    for res in results:
        if res.get("matched"):
            vulnerabilities.append({
                "type": res.get("name", "Unknown"),
                "severity": res.get("severity", "Unknown").capitalize(),
                "url": res.get("url", "Unknown"),
                "description": res.get("description", "No description available."),
                "recommendation": res.get("recommendation", "No recommendation provided.")
            })

    report_data = {
        "website": target_url,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }

    return report_data
