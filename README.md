# 🛡️ ThreatGuard: Scam & URL Threat Detection Web App

ThreatGuard is a Flask-based web application designed to analyze uploaded documents and classify URLs to identify potential scams, phishing, malware, and defacement attempts. It supports PDF and TXT files and provides interactive threat detection in a sleek, modern UI.


## 🚀 Features

- Detects scam/fake content based on suspicious keywords in uploaded files (PDF/TXT)
- Classifies URLs as benign, phishing, malware, or defacement using predefined domain patterns
- Responsive web interface styled with custom CSS
- Spinner loading animation for improved user experience
- Runs locally with `Flask` and can be deployed with `Waitress`



## Logic Overview
Scam File Detection
- Accepts .pdf and .txt files
- Extracts text and scans for keywords like: lottery, winner, urgent, etc.
- Displays classification result: Scam/Fake or Real/Legitimate


## URL Threat Detection
- Validates URL structure (http/https)
- Checks for known phishing or malware domain patterns
- Displays classification result with color-coded threat levels


## ▶️ How to Run

1. **Install Dependencies**

```bash
python app.py
