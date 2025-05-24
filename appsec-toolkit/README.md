# 🔐 AppSec Toolkit – Lightweight Application Security Scanner

A fast and developer-friendly toolkit designed to help teams catch common security issues like hardcoded secrets, insecure HTTP headers, active debug modes, and vulnerable dependencies early in the development cycle. Built for startups, students, and security-minded devs who want to ship secure software with confidence.

---

## ✅ Features
- 🔍 **Secrets Scanner**: Detects hardcoded API keys, tokens, and secrets in your source code.
- 🚦 **Debug Mode Detection**: Scans Python projects (Flask, Django) and `.env` files for enabled debug/development modes.
- 📦 **Dependency Vulnerability Scanner**: Checks your `requirements.txt` for packages with known vulnerabilities using `pip-audit`.
- 🌐 **Header Scanner**: Analyzes live URLs for the presence of important HTTP security headers.
- 🛠️ **Pluggable Checks**: Modular design allows for easy addition of new security checks.
- ⚡ **CLI-Based**: Fast to run and simple to integrate into your CI/CD pipeline or local development workflow.

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/appsec-toolkit.git # Replace with actual repo URL when available
cd appsec-toolkit
```

### 2. Set up your environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the scanner

**Scan for secrets and debug mode settings in a local project:**
```bash
python scanner.py --path /path/to/your/codebase
```

**Check security headers for a live URL:**
```bash
python scanner.py --url https://your-website.com
```

**Run all applicable scans (path-based and URL-based):**
```bash
python scanner.py --path /path/to/your/codebase --url https://your-website.com
```

---

## 🔎 Example Output

**Secrets Scan:**
```
🔍 Scanning sample_project/ for secrets...

🚨 Potential secrets found:
  sample_project/example.py:1 → API_KEY = '123456789abc'

✅ Scan complete.
```

**Header Scan:**
```
🔍 Checking security headers for https://example.com...

✅ Found Headers:
  X-Content-Type-Options: nosniff
⚠️ Missing Headers & Recommendations:
  - Content-Security-Policy: Consider implementing CSP...
  - Strict-Transport-Security: Implement HSTS...
```

**Debug Mode Scan:**
```
🔍 Scanning /path/to/your/codebase for debug mode settings...

🚨 Potential debug/development settings found:
  📄 File: /path/to/your/codebase/app.py
  ➡️ Line 2: DEBUG = True
  💡 Type: Python Debug Setting
```

**Dependency Vulnerability Scan:**
```
🔍 Checking for vulnerable dependencies in /path/to/your/codebase (requires requirements.txt and pip-audit)...

🚨 Vulnerable dependencies found:
  📦 Package: requests@2.19.0
     ID: PYSEC-XXXX-YYYY 
     Description: Some vulnerability description...
     Fix Versions: 2.20.0, 2.21.0
```
---

## 📦 Planned Features

* [ ] Input Sanitization Checks (e.g., basic checks for common web frameworks)
* [ ] Configuration Checker (e.g., for insecure default settings in common tools)
* [ ] Export to HTML/Markdown Reports
* [ ] More comprehensive language support beyond Python for secrets/debug.

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
