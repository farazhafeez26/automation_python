import re
import requests
from bs4 import BeautifulSoup
import email
from email import policy

# VirusTotal API configuration
API_KEY = "your_api_key"
VT_URL = "https://www.virustotal.com/vtapi/v2/url/report"

def check_email_for_phishing(eml_file):
    # Open and parse the .eml file
    with open(eml_file, 'r', encoding="utf-8") as f:
        email_message = email.message_from_file(f, policy=policy.default)
    
    # Extract email body content
    email_text = ""
    for part in email_message.walk():
        if part.get_content_type() == "text/plain":
            email_text += part.get_payload(decode=True).decode(part.get_content_charset(), errors="replace")

    # List of suspicious words/phrases often found in phishing emails
    phishing_keywords = ["konto gesperrt", "dringend", "sofort", "verifizieren", "passwort zurücksetzen"]

    # Check for phishing keywords in the email
    for keyword in phishing_keywords:
        if keyword.lower() in email_text.lower():
            print(f"Phishing Warning: Suspicious keyword detected - {keyword}")

    # Find and check URLs in the email body
    urls = re.findall(r'(https?://\S+)', email_text)
    for url in urls:
        try:
            print(f"Checking URL: {url}")
            params = {"apikey": API_KEY, "resource": url}
            response = requests.get(VT_URL, params=params)
            result = response.json()

            if result['response_code'] == 1:
                if result['positives'] > 0:
                    print(f"Warning: URL {url} flagged by VirusTotal with {result['positives']} positives out of {result['total']} scans.")
                else:
                    print(f"URL {url} appears to be clean.")
            else:
                print(f"URL {url} has not been previously scanned by VirusTotal.")
        
        except Exception as e:
            print(f"Error while checking URL {url}: {e}")

# Example usage
eml_file = "example_email.eml"
check_email_for_phishing(eml_file)
