# 🔐 BaitBuster – Phishing Link Awareness Checker

A beginner-friendly cybersecurity project that helps users identify potentially suspicious URLs and develop safer browsing habits.

BaitBuster provides a second opinion before you click.

## 📌 About the Project

Phishing is a type of cyberattack in which attackers use deceptive links or websites to trick people into revealing sensitive information such as passwords, banking details, or personal data.

BaitBuster is a phishing link awareness tool that analyzes submitted URLs using a set of rule-based detection techniques. It identifies suspicious URL patterns, generates findings, and calculates an overall risk score to help users make more informed decisions before visiting a link.

The project combines a Python-based backend with a Chrome browser extension to make URL analysis accessible to users.

## 🎯 Objectives

- Understand the fundamentals of phishing attacks and malicious URLs.
- Build a tool to assess potentially suspicious links.
- Identify common URL patterns associated with phishing.
- Implement rule-based detection and risk scoring.
- Integrate a backend API with a browser extension.
- Promote awareness of phishing warning signs and safer browsing habits.

## ✨ Features

- **URL Analysis:** Extracts information such as hostname, domain, subdomain, scheme, and path.
- **Rule-Based Detection:** Checks for suspicious keywords, IP-based URLs, excessive subdomains, URL shorteners, punycode, and other unusual URL patterns.
- **Risk Scoring:** Assigns points based on the severity of detected indicators.
- **Risk Categorization:** Classifies results into Low, Medium, and High risk categories.
- **REST API:** Uses FastAPI to connect the detection engine with the browser extension.
- **Chrome Extension:** Allows users to analyze the URL of their current browser tab.
- **Input Validation:** Handles invalid URLs and unsupported URL formats.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development and detection logic |
| FastAPI | REST API development |
| JavaScript | Chrome extension functionality |
| HTML & CSS | Extension interface |
| tldextract | Domain and subdomain extraction |
| pytest | Automated testing |
| Git & GitHub | Version control and project hosting |
| GitHub Actions | Continuous integration |

## 🏗️ Project Structure

```text
BaitBuster/
│
├── api/
│   ├── analyzer.py
│   ├── detector.py
│   ├── scorer.py
│   ├── server.py
│   └── main.py
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
│
├── ml/
│   ├── notebooks/
│   └── artifacts/
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_detector.py
│   ├── test_scorer.py
│   └── test_integration.py
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── requirements.txt
└── README.md
```

## ⚠️ Important Disclaimer

BaitBuster is an educational phishing awareness tool based on rule-based URL analysis.

- A suspicious indicator does not necessarily mean a URL is malicious.
- A low-risk result does not guarantee that a URL is safe.
- HTTPS does not guarantee that a website is trustworthy.
- The risk score is a heuristic assessment, not a probability of phishing.

Always verify website addresses and exercise caution before entering sensitive information.

## 🔮 Future Improvements

- Explore machine learning-based phishing URL classification.
- Improve detection accuracy and reduce false positives.
- Expand the set of URL analysis techniques.
- Improve user awareness through more detailed explanations of detected indicators.

## 👩‍💻 Project Status

**Version 1.0 – Rule-Based Detection and Chrome Extension**

BaitBuster is an ongoing learning project focused on cybersecurity awareness, Python backend development, API integration, and browser extension development.

---

Made with ❤️ and Python.