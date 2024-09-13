'''Investigating Convincing Phishing Emails

Objective: Determine why customers of secure-startup.com are receiving convincing phishing emails and automate the investigation using a Python script.

Possible Reasons:

Email Spoofing: Attackers are spoofing the company's email domain.
Data Breach: Customer data, including email addresses, may have been compromised.
Compromised Systems: The company's email server or customer database might be compromised.
Domain Hijacking: DNS records could have been altered.
Approach:

Analyze Phishing Emails:

Collect samples of the phishing emails.
Examine email headers for sender information.
Check for similarities with legitimate company emails.


Automate Investigation with Python Script:'''

import re
import requests
from bs4 import BeautifulSoup

def check_email_for_phishing(email_text):
    # Liste von verdächtigen Wörtern/Phishing-Indikatoren
    phishing_keywords = ["konto gesperrt", "dringend", "sofort", "verifizieren", "passwort zurücksetzen"]

    # Checke auf Phishing-Keywords
    for keyword in phishing_keywords:
        if keyword.lower() in email_text.lower():
            print(f"Phishing-Warnung: Verdächtiges Wort gefunden - {keyword}")
    
    # Checke URLs in der E-Mail
    urls = re.findall(r'(https?://\S+)', email_text)
    for url in urls:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                title = soup.title.string if soup.title else 'No Title'
                print(f"Überprüfe URL: {url} - Seite Titel: {title}")
        except Exception as e:
            print(f"Fehler beim Überprüfen der URL: {url}, Grund: {e}")

# Beispiel-E-Mail-Text
email_text = """
Sehr geehrter Kunde, Ihr Konto wurde gesperrt. Bitte verifizieren Sie Ihre Identität sofort, um den Zugang wiederherzustellen: https://malicious-url.com
"""

# Funktion aufrufen
check_email_for_phishing(email_text)
