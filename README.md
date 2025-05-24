# 🔐 AppSec Toolkit – Lightweight Application Security Scanner

A fast and developer-friendly toolkit designed to help teams catch common security issues early in the development cycle. Built for startups, students, and security-minded devs who want to ship secure software with confidence.

---

## ✅ Features (MVP)
- 🔍 **Secrets Scanner**: Detect hardcoded API keys, tokens, and secrets in source code
- 🛠️ **Pluggable Checks**: Modular design makes it easy to add new security checks
- ⚡ **CLI-Based**: Quick to run, easy to integrate into any workflow

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/appsec-toolkit.git
cd appsec-toolkit
```

### 2. Set up your environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the scanner

```bash
python scanner.py /path/to/your/codebase
```

---

## 🔎 Example Output

```
🔍 Scanning sample_project/ for secrets...

🚨 Potential secrets found:
  sample_project/example.py:1 → API_KEY = '123456789abc'

✅ Scan complete.
```

---

## 📦 Planned Features

* [ ] HTTP Security Header Checker
* [ ] Debug Mode Detection (e.g., Flask/Django)
* [ ] Dependency Vulnerability Scanner
* [ ] Input Sanitization Checks
* [ ] Export to HTML/Markdown Reports

---

## 📚 Based On

* [OWASP ASVS Level 1](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 🧠 Who Is This For?

* Solo developers or small teams building public-facing apps
* Interns or new AppSec engineers setting up a baseline
* Security students building real-world tooling
* Anyone preparing apps for city/government/community approval

---

## 📄 License

MIT – free to use, modify, and contribute.

---

## 🙌 Contributions

Got a good check to add? Submit a PR or open an issue!
