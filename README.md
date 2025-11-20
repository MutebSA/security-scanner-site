# 🔍 Security Scanner Site

A simple **web-based security scanner** that checks URLs/domains against known malicious lists (hosted on GitHub) and gives a **risk score** with a clear explanation.  
Built as a portfolio / learning project by a cybersecurity enthusiast.

> ⚠️ **Disclaimer**  
> This tool is for **educational and awareness purposes only**.  
> It does **not** replace professional security products or threat intelligence platforms.

---

## 🚀 Overview

Security Scanner Site lets you paste any **URL or domain** and quickly see:

- Whether it appears in **known malicious / suspicious lists**  
- A **risk score** (e.g. Safe / Warning / High Risk)  
- A breakdown of **why** it was flagged (phishing lists, malware lists, etc.)  

This is perfect to showcase:

- Web development skills (Flask + HTML/CSS/JS)
- Basic cybersecurity thinking (blacklists, indicators of compromise)
- Clean UI + clear UX for non-technical users

---

## ✨ Features

- ✅ **URL / Domain Scan**
  - Enter a URL or domain and get an instant report.
- ✅ **Risk Scoring**
  - Simple numeric score + label like:
    - `0–20` → **Likely Safe**
    - `21–60` → **Suspicious**
    - `61+` → **High Risk**
- ✅ **Threat Feeds from GitHub**
  - Uses JSON files hosted on GitHub for:
    - Known malicious URLs
    - Suspicious domains / IPs
    - (Optional) Malware hashes or patterns
- ✅ **Readable Report**
  - Shows **why** something was flagged:
    - Matched phishing list
    - Matched malware list
    - Matched suspicious domain, etc.
- ✅ **Responsive UI**
  - Works on desktop and mobile
- ✅ **Portfolio-Ready**
  - Clean project structure, easy to show to universities or employers

---

## 🛠 Tech Stack

- **Backend:** Python, Flask  
- **Frontend:** HTML, CSS, JavaScript (vanilla)  
- **Data:** JSON threat lists hosted on GitHub (fetched via HTTP)  

---

## 📁 Project Structure (example)

```bash
security-scanner-site/
├── app.py               # Flask application
├── requirements.txt     # Python dependencies
├── templates/
│   ├── base.html
│   ├── index.html       # Main scan page
│   └── result.html      # Scan results page (if separated)
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
└── README.md
⚙️ Getting Started (Local)
1. Clone the repo
bash
git clone https://github.com/MutebSA/security-scanner-site
cd security-scanner-site
2. Create a virtual environment (optional but recommended)
bash
python -m venv venv
source venv/bin/activate   # Linux / macOS
# OR
venv\Scripts\activate      # Windows
3. Install dependencies
bash
pip install -r requirements.txt
4. Run the app
bash
python app.py
Then open your browser and go to:

📌 How It Works
User submits a URL or domain from the main page.

The backend:

Normalizes the input (removes spaces, etc.).

Looks up the value in one or more JSON threat lists hosted on GitHub.

If there are matches, they are:

Collected into a list of reasons.

Used to calculate a risk score.

The result page shows:

✅ Safe / ⚠️ Suspicious / 🚨 High Risk

Risk score

Which list(s) it matched (phishing, malware, etc.)

Helpful message for non-technical users

🌐 Threat Data Sources
The app is designed to work with JSON lists stored on GitHub, for example:

malicious_urls.json

phishing_domains.json

suspicious_ips.json

You can:

Edit the URLs of these lists directly inside app.py

Maintain your own lists in a GitHub repo and point the app to the raw JSON links.

🔧 If you fork this project, be sure to update the GitHub JSON URLs to your own sources.

🔒 Security & Limitations
This is not a real-time enterprise security product.

It does not:

Sand-box or execute files

Perform dynamic or behavioral analysis

Guarantee that a URL is 100% safe

It only checks against the configured lists and simple rules.

Use it as:

A learning tool

A portfolio project

A demo of how security checks can be integrated into a web app



🤝 Contributing
Pull requests are welcome!

If you’d like to:

Add new threat sources

Improve UI/UX

Optimize performance

Feel free to fork the repo and submit a PR.


text
MIT License
👤 Author
Muteb Alharbi
Cybersecurity Enthusiast • Web Developer

You can connect via:

GitHub: https://github.com/MutebSA
