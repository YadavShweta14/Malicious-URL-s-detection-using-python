from flask import Flask, render_template, request
import PyPDF2
import re
from waitress import serve

app = Flask(__name__)

# Simple scam keyword list
SCAM_KEYWORDS = [
    'lottery', 'winner', 'urgent', 'bank account', 'transfer fee',
    'click here', 'password', 'verify', 'nigeria'
]
PHISHING_DOMAINS = ['paypa1.com', 'secure-login.', 'free-gift.', 'login-info.', 'account-update.']
MALWARE_DOMAINS = ['download-free.', 'cracked-software.', 'hacktool.', 'malicious']

def predict_fake_or_real_email_content(text):
    text_lower = text.lower()
    if any(keyword in text_lower for keyword in SCAM_KEYWORDS):
        return "Scam/Fake: This message contains suspicious phrases commonly used in scams."
    return "Real/Legitimate: No suspicious content detected."

def url_detection(url):
    url_lower = url.lower()
    if any(domain in url_lower for domain in PHISHING_DOMAINS):
        return "phishing"
    elif any(domain in url_lower for domain in MALWARE_DOMAINS):
        return "malware"
    elif 'hacked' in url_lower:
        return "defacement"
    else:
        return "benign"

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/scam/', methods=['POST'])
def detect_scam():
    if 'file' not in request.files:
        return render_template("index.html", message="No file uploaded.")

    file = request.files['file']
    extracted_text = ""

    try:
        if file.filename.endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(file)
            extracted_text = " ".join([
                page.extract_text() for page in pdf_reader.pages if page.extract_text()
            ])
        elif file.filename.endswith('.txt'):
            extracted_text = file.read().decode("utf-8")
        else:
            return render_template("index.html", message="Invalid file type. Please upload a PDF or TXT file.")
    except Exception as e:
        return render_template("index.html", message=f"Error reading file: {str(e)}")

    if not extracted_text.strip():
        return render_template("index.html", message="File is empty or text could not be extracted.")

    message = predict_fake_or_real_email_content(extracted_text)
    return render_template("index.html", message=message)

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(("http://", "https://")):
        return render_template("index.html", message="Invalid URL format.", input_url=url)

    classification = url_detection(url)
    return render_template("index.html", input_url=url, predicted_class=classification)

if __name__ == '__main__':
    app.run(debug=True)

