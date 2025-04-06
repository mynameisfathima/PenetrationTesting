import time
from typing import Dict, Any
from jinja2 import Template
import re
from weasyprint import HTML
import google.generativeai as genai

# Set up the API key
genai.configure(api_key="apikey")


def fetch_description_and_recommendation(vuln_name: str, severity: str) -> Dict[str, str]:
    """Fetch vulnerability description and recommendation using Google's Gemini AI."""
    try:
        # Structured prompt for Gemini AI
        prompt = (
        f"Explain the cybersecurity issue called '{vuln_name}' with a severity level of '{severity}'. "
        f"Provide the following in bullet points, without using asterisks or paragraph formatting:\n\n"
        f"1. A detailed description.\n"
        f"2. A recommended solution.\n\n"
        f"Format your response as:\n"
        f"Description:\n- <bullet points here>\n"
        f"Recommendation:\n- <bullet points here>"
    )
        
       

        # Generate response using Google's AI
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)

        # Validate response structure
        if response and response.candidates:
            ai_response = response.candidates[0].content.parts[0].text.strip() if response.candidates[0].content.parts else ""

            if not ai_response:
                raise ValueError("AI response is empty or incomplete.")

            # Extract description and recommendation
            description_match = re.search(r"Description:\s*(.*?)\s*(Recommendation:|$)", ai_response, re.DOTALL)
            recommendation_match = re.search(r"Recommendation:\s*(.*?)$", ai_response, re.DOTALL)

            description = description_match.group(1).strip() if description_match else "No description available."
            recommendation = recommendation_match.group(1).strip() if recommendation_match else "No recommendation available."

            return {"description": description, "recommendation": recommendation}
        
        else:
            raise ValueError("Google AI response is empty or flagged.")

    except Exception as e:
        print(f"Error fetching data from Google AI: {e}")
        return {
            "description": "Error fetching description.",
            "recommendation": "Error fetching recommendation."
        }



# Function to generate HTML report
def generate_html_report(data: Dict[str, Any], template_path: str = "scan_report.html"):
   

    template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Website Scan Report</title>
    </head>
    <body>
        <h1>Website Scan Report</h1>
        <p><strong>Website:</strong> {{ website }}</p>
        <p><strong>Scan Date:</strong> {{ date }}</p>
        <h2>Summary</h2>
        <p>Total vulnerabilities found: {{ total_vulnerabilities }}</p>
        <p>This report presents the results of a comprehensive penetration test conducted on {{website}} internal network and publicly accessible web applications. The objective of this engagement was to assess the security posture of the infrastructure and applications by identifying vulnerabilities, evaluating their potential impact, and providing recommendations for remediation.</p>
        <h2>Scope of testing</h2>
        <p>This penetration test focused on evaluating the security of specific components within the network and web application environment. The defined scope included:

1. Network Penetration Testing
Targeted Services:

DNS (Domain Name System):

DNS zone transfer testing

Cache poisoning checks

DNS enumeration and misconfiguration analysis

SSL/TLS (Secure Sockets Layer / Transport Layer Security):

Certificate validation

SSL/TLS version and cipher suite analysis

Configuration flaws (e.g., support for deprecated protocols, weak ciphers, lack of forward secrecy)

Exclusions: No other network services, hosts, or internal infrastructure were included in the test scope.

2. Web Application Penetration Testing
Full assessment of the specified web application(s) for vulnerabilities based on the OWASP Top 10 and other common security flaws.</p>
        <h2>Vulnerability Details</h2>
        <table border="1">
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Result</th>
                    <th>Severity</th>
                    <th>Affected URL</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.matched }}</td>
                    <td>{{ vuln.severity }}</td>
                    <td>{{ vuln.url }}</td>
                    <td>{{ vuln.description }}</td>
                    <td>{{ vuln.recommendation }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    """)

    html_report = template.render(data)
    with open(template_path, "w") as file:
        file.write(html_report)

# Function to convert HTML report to PDF
def convert_html_to_pdf(html_path: str, pdf_path: str = "scan_report.pdf"):
    try:
        HTML(html_path).write_pdf(pdf_path)
        print(f"PDF report generated: {pdf_path}")
    except Exception as e:
        print(f"Error converting to PDF: {e}")
